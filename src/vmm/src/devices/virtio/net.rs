// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::devices::{
    epoll::{DeviceEventT, EpollHandler},
    util::{
        net::tap::{Tap, TapError},
        sys::net as SysNetUtil,
        sys::virtio::net as SysVirtioNet,
    },
    virtio::{
        queue::{Queue, INTERRUPT_STATUS_USED_RING},
        types,
        virtio_device::{ActivateError, VirtioDevice},
    },
};
use crate::vstate::memory::GuestMemoryMmap;
// use epoll;
use std::io::{Read, Write};
use std::mem;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use utils::{epoll, eventfd::EventFd};
use vm_memory::Bytes;

const MAX_BUFFER_SIZE: usize = 65562;
const QUEUE_SIZE: u16 = 256;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE, QUEUE_SIZE];

// Tap handling
// A frame is available for reading from the tap device to receive in the guest.
const RX_TAP_EVENT: DeviceEventT = 0;
// The guest has made a buffer available to receive a frame into.
const RX_QUEUE_EVENT: DeviceEventT = 1;
// The transmit queue has a frame that is ready to send from the guest.
const TX_QUEUE_EVENT: DeviceEventT = 2;
// Device shutdown has been requested.
const KILL_EVENT: DeviceEventT = 3;

/// Errors associated with actions on net.
#[derive(Debug, thiserror::Error)]
pub enum NetError {
    /// Failed to create eventfd
    #[error("Failed to create eventfd: {0}")]
    CreateEventFd(#[source] std::io::Error),
    /// Failed to clone eventfd
    #[error("Failed to clone eventfd: {0}")]
    CloneEventFd(#[source] std::io::Error),
    /// Failed to open tap device.
    #[error("Failed to configure tap device; {0}")]
    Tap(#[source] TapError),
    /// Error while polling for network I/O event.
    #[error("Error while polling for network I/O event: {0}")]
    PollError(std::io::Error),
}

struct NetEpollHandler {
    mem: GuestMemoryMmap,
    rx_queue: Queue,
    tx_queue: Queue,
    tap: Tap,
    interrupt_status: Arc<AtomicUsize>,
    interrupt_evt: EventFd,
    rx_buf: [u8; MAX_BUFFER_SIZE],
    rx_count: usize,
    deferred_rx: bool,
    rx_queue_evt: EventFd,
    tx_queue_evt: EventFd,
}

impl NetEpollHandler {
    fn signal_used_queue(&self) {
        self.interrupt_status
            .fetch_or(INTERRUPT_STATUS_USED_RING as usize, Ordering::SeqCst);
        self.interrupt_evt.write(1).unwrap();
    }

    // Copies a single frame from 'self.rx_buf' into the guest.
    // Returns true if a buffer was used, and false if the frame must be deferred until a buffer
    // is made available by the driver
    fn rx_single_frame(&mut self) -> bool {
        let mut next_desc = self.rx_queue.iter(&self.mem).next();
        if next_desc.is_none() {
            return false;
        }

        // We just checked that the head descriptor exists
        let head_index = next_desc.as_ref().unwrap().index;
        let mut write_count = 0;

        // Copy from frame into buffer, which may span multiple descriptors
        loop {
            match next_desc {
                Some(desc) => {
                    if !desc.is_write_only() {
                        break;
                    }
                    let limit = std::cmp::min(write_count + desc.len as usize, self.rx_count);
                    let source_slice = &self.rx_buf[write_count..limit];
                    let write_result = self.mem.write(source_slice, desc.addr);

                    match write_result {
                        Ok(sz) => {
                            write_count += sz;
                        }
                        Err(e) => {
                            println!("net: rx: failed to write slice: {:?}", e);
                            break;
                        }
                    };

                    if write_count >= self.rx_count {
                        break;
                    }
                    next_desc = desc.next_descriptor();
                }
                None => {
                    println!(
                        "net: rx: buffer is too small to hold frame of size {}",
                        self.rx_count
                    );
                    break;
                }
            }
        }

        self.rx_queue
            .add_used(&self.mem, head_index, write_count as u32);

        // Interrupt the guest immediately for received frmaes to reduce latency
        self.signal_used_queue();

        write_count >= self.rx_count
    }

    fn read_tap(&mut self) -> std::io::Result<usize> {
        self.tap.read(&mut self.rx_buf)
    }

    fn process_rx(&mut self) {
        // Read as many frames as possible
        loop {
            let res = self.read_tap();
            match res {
                Ok(count) => {
                    self.rx_count = count;
                    if !self.rx_single_frame() {
                        // DEBUG)  Found that when the Hypervisor OS is Ubuntu 22.04,
                        //         this process is performed at boot
                        // println!("differed_rx turn to true");
                        self.deferred_rx = true;
                        break;
                    }
                }
                Err(e) => {
                    // The tap device is nonblocking, so any error aside from EAGAIN is unexpected
                    if e.raw_os_error().unwrap() != libc::EAGAIN {
                        println!("net: rx: failed to read tap: {:?}", e);
                    }
                    break;
                }
            }
        }
    }

    fn process_tx(&mut self) {
        let mut frame = [0u8; MAX_BUFFER_SIZE];
        let mut used_desc_heads = [0u16; QUEUE_SIZE as usize];
        let mut used_count = 0;

        for avail_desc in self.tx_queue.iter(&self.mem) {
            let head_index = avail_desc.index;
            let mut next_desc = Some(avail_desc);
            let mut read_count = 0;

            // Copy buffer from across multiple descriptors
            #[allow(clippy::while_let_loop)]
            loop {
                match next_desc {
                    Some(desc) => {
                        if desc.is_write_only() {
                            break;
                        }
                        let limit = std::cmp::min(read_count + desc.len as usize, frame.len());
                        let read_result = self
                            .mem
                            .read(&mut frame[read_count..limit as usize], desc.addr);
                        match read_result {
                            Ok(sz) => {
                                read_count += sz;
                            }
                            Err(e) => {
                                println!("net: tx: failed to read slice: {:?}", e);
                                break;
                            }
                        }
                        next_desc = desc.next_descriptor();
                    }
                    None => {
                        break;
                    }
                }
            }

            let write_result = self.tap.write(&frame[..read_count]);
            match write_result {
                Ok(_) => {}
                Err(e) => {
                    println!("net: tx: error failed to write to tap: {:?}", e);
                }
            };

            used_desc_heads[used_count] = head_index;
            used_count += 1;
        }

        for &desc_index in &used_desc_heads[..used_count] {
            self.tx_queue.add_used(&self.mem, desc_index, 0);
        }

        self.signal_used_queue();
    }
}

impl EpollHandler for NetEpollHandler {
    fn handle_event(&mut self, device_event: DeviceEventT, _: u32) {
        match device_event {
            RX_TAP_EVENT => {
                // Process a deferred frame first if available. Don't read from tap again
                // until we manage to receive this deferred frame.
                if self.deferred_rx {
                    if self.rx_single_frame() {
                        self.deferred_rx = false;
                    } else {
                        return;
                    }
                }
                self.process_rx();
            }
            RX_QUEUE_EVENT => {
                if let Err(e) = self.rx_queue_evt.read() {
                    println!("net: error reading rx queue EventFd: {:?}", e);
                    //TODO: device should be removed from epoll
                }
                // There should be a buffer avaialble new to receive the frame into
                if self.deferred_rx && self.rx_single_frame() {
                    println!("differed_rx turn to false");
                    self.deferred_rx = false;
                }
            }
            TX_QUEUE_EVENT => {
                if let Err(e) = self.tx_queue_evt.read() {
                    println!("net: error reading txqueue EventFd: {:?}", e);
                    //TODO: device should be removed from epoll
                }
                self.process_tx();
            }
            KILL_EVENT => {
                println!("virtio net device killed");
                //TODO: device should be removed from epoll
            }
            _ => panic!("unknown token for virtio net device"),
        }
    }
}

pub struct EpollConfig {
    rx_tap_token: u64,
    rx_queue_token: u64,
    tx_queue_token: u64,
    kill_token: u64,
    ep: epoll::Epoll,
    sender: mpsc::Sender<Box<dyn EpollHandler>>,
}

impl EpollConfig {
    pub fn new(
        first_token: u64,
        ep: epoll::Epoll,
        sender: mpsc::Sender<Box<dyn EpollHandler>>,
    ) -> Self {
        EpollConfig {
            rx_tap_token: first_token,
            rx_queue_token: first_token + 1,
            tx_queue_token: first_token + 2,
            kill_token: first_token + 3,
            ep,
            sender,
        }
    }
}

pub struct Net {
    workers_kill_evt: Option<EventFd>,
    kill_evt: EventFd,
    tap: Option<Tap>,
    avail_features: u64,
    acked_features: u64,
    epoll_config: EpollConfig,
}

impl Net {
    /// Create a new virtio network device with the given IP address and netmask
    pub fn new(epoll_config: EpollConfig) -> Result<Net, NetError> {
        let kill_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(NetError::CreateEventFd)?;
        let tap = Tap::new().map_err(NetError::Tap)?;
        // tap.set_ip_addr(ip_addr).map_err(NetError::TapSetIp)?;
        // tap.set_netmask(netmask).map_err(NetError::TapSetNetmask)?;

        // Set offload flags to match the virtio features below.
        tap.set_offload(
            SysNetUtil::TUN_F_CSUM
                | SysNetUtil::TUN_F_UFO
                | SysNetUtil::TUN_F_TSO4
                | SysNetUtil::TUN_F_TSO6,
        )
        .map_err(NetError::Tap)?;

        let vnet_hdr_size = mem::size_of::<SysVirtioNet::virtio_net_hdr_v1>() as i32;
        tap.set_vnet_hdr_size(vnet_hdr_size)
            .map_err(NetError::Tap)?;
        tap.enable().map_err(NetError::Tap)?;

        let avail_features = 1 << SysVirtioNet::VIRTIO_NET_F_GUEST_CSUM
            | 1 << SysVirtioNet::VIRTIO_NET_F_CSUM
            | 1 << SysVirtioNet::VIRTIO_NET_F_GUEST_TSO4
            | 1 << SysVirtioNet::VIRTIO_NET_F_GUEST_UFO
            | 1 << SysVirtioNet::VIRTIO_NET_F_HOST_TSO4
            | 1 << SysVirtioNet::VIRTIO_NET_F_HOST_UFO
            | 1 << SysVirtioNet::VIRTIO_F_VERSION_1;
        Ok(Net {
            workers_kill_evt: Some(kill_evt.try_clone().map_err(NetError::CloneEventFd)?),
            kill_evt,
            tap: Some(tap),
            avail_features,
            acked_features: 0u64,
            epoll_config,
        })
    }
}

impl Drop for Net {
    fn drop(&mut self) {
        // Only kill the child if it claimed its eventfd.
        if self.workers_kill_evt.is_none() {
            // Ignore the result because there is nothing we can do about it.
            let _ = self.kill_evt.write(1);
        }
    }
}

impl VirtioDevice for Net {
    fn device_type(&self) -> u32 {
        types::NETWORK_CARD
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn features(&self, page: u32) -> u32 {
        match page {
            0 => self.avail_features as u32,
            1 => (self.avail_features >> 32) as u32,
            _ => {
                println!("net: virtio net got request for features page: {}", page);
                0x32
            }
        }
    }

    fn ack_features(&mut self, page: u32, value: u32) {
        let mut v = match page {
            0 => value as u64,
            1 => (value as u64) << 32,
            _ => {
                println!(
                    "net: virtio net device cannot ack unknown feature page: {}",
                    page,
                );
                0x64
            }
        };

        // Check if the guest is ACK'ing a feature that we didn't claim to have.
        let unrequested_features = v & !self.avail_features;
        if unrequested_features != 0 {
            println!("net: virtio net got unknown feature ack: {:x}", v);
            v &= !unrequested_features;
        }
        self.acked_features |= v;
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt_evt: EventFd,
        status: Arc<AtomicUsize>,
        mut queues: Vec<Queue>,
        mut queue_evts: Vec<EventFd>,
    ) -> Result<(), ActivateError> {
        if queues.len() != 2 || queue_evts.len() != 2 {
            if queues.len() == queue_evts.len() {
                return Err(ActivateError::UnsupportedNumOfVirtioQueue(queues.len()));
            } else {
                return Err(
                    ActivateError::UnexpectedMismatchNumOfVirtioQueuesAndEventFds(
                        queues.len(),
                        queue_evts.len(),
                    ),
                );
            }
        }
        if let Some(tap) = self.tap.take() {
            if let Some(kill_evt) = self.workers_kill_evt.take() {
                let kill_raw_fd = kill_evt.as_raw_fd();

                let handler = NetEpollHandler {
                    mem,
                    rx_queue: queues.remove(0),
                    tx_queue: queues.remove(0),
                    tap,
                    interrupt_status: status,
                    interrupt_evt,
                    rx_buf: [0u8; MAX_BUFFER_SIZE],
                    rx_count: 0,
                    deferred_rx: false,
                    rx_queue_evt: queue_evts.remove(0),
                    tx_queue_evt: queue_evts.remove(0),
                };

                let tap_raw_fd = handler.tap.as_raw_fd();
                let rx_queue_raw_fd = handler.rx_queue_evt.as_raw_fd();
                let tx_queue_raw_fd = handler.tx_queue_evt.as_raw_fd();

                self.epoll_config
                    .ep
                    .ctl(
                        epoll::ControlOperation::Add,
                        tap_raw_fd,
                        epoll::EpollEvent::new(epoll::EventSet::IN, self.epoll_config.rx_tap_token),
                    )
                    .map_err(ActivateError::EpollCtl)?;
                self.epoll_config
                    .ep
                    .ctl(
                        epoll::ControlOperation::Add,
                        rx_queue_raw_fd,
                        epoll::EpollEvent::new(
                            epoll::EventSet::IN,
                            self.epoll_config.rx_queue_token,
                        ),
                    )
                    .map_err(ActivateError::EpollCtl)?;
                self.epoll_config
                    .ep
                    .ctl(
                        epoll::ControlOperation::Add,
                        tx_queue_raw_fd,
                        epoll::EpollEvent::new(
                            epoll::EventSet::IN,
                            self.epoll_config.tx_queue_token,
                        ),
                    )
                    .map_err(ActivateError::EpollCtl)?;
                self.epoll_config
                    .ep
                    .ctl(
                        epoll::ControlOperation::Add,
                        kill_raw_fd,
                        epoll::EpollEvent::new(epoll::EventSet::IN, self.epoll_config.kill_token),
                    )
                    .map_err(ActivateError::EpollCtl)?;
                // channel should be open and working
                self.epoll_config.sender.send(Box::new(handler)).unwrap();

                return Ok(());
            }
        }
        Err(ActivateError::BadActivate)
    }
}
