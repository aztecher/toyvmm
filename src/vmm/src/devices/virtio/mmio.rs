// Copyright 2023 aztecher, or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use byteorder::{ByteOrder, LittleEndian};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use utils::{errno::Result, eventfd::EventFd};
use vm_memory::GuestAddress;

use crate::devices::{
    bus::BusDevice,
    virtio::{queue::Queue, status, virtio_device::VirtioDevice},
};
use crate::vstate::memory::GuestMemoryMmap;

/// Offset from the base MMIO address of a virtio device used by the guest
/// to notify the device of queue events
pub const NOTIFY_REG_OFFSET: u32 = 0x50;

const VENDOR_ID: u32 = 0x0;
const MMIO_MAGIC_VALUE: u32 = 0x74726976;
const MMIO_VERSION: u32 = 0x2;

/// Implements the
/// [MMIO](http://docs.oasis-open.org/virtio/virtio/v1.0/cs04/virtio-v1.0-cs04.html#x1-1090002)
/// transport for virtio devices.
///
/// This requires 3 points of installation to work with a VM:
///
/// 1. Mmio reads and writes must be sent to this device at what is referred to here as MMIO base.
/// 1. `Mmio::queue_evts` must be installed at `virtio::NOITFY_REG_OFFSET` offset from the MMIO
/// base. Each event in the array must be signaled if the index is written at that offset.
/// 1. `Mmio::interrupt_evt` must signal an interrupt that the guest driver is listening to when it
/// is written to.
///
/// Typically one page (4096 bytes) of MMIO address space is sufficient to handle this transport
/// and inner virtio device.
pub struct MmioTransport {
    device: Box<dyn VirtioDevice>,
    device_activated: bool,

    features_select: u32,
    acked_features_select: u32,
    queue_select: u32,
    driver_status: u32,

    interrupt_status: Arc<AtomicUsize>,
    interrupt_evt: Option<EventFd>,
    queue_evts: Vec<EventFd>,
    config_generation: u32,

    queues: Vec<Queue>,
    mem: Option<GuestMemoryMmap>,
}

impl MmioTransport {
    pub fn new(mem: GuestMemoryMmap, device: Box<dyn VirtioDevice>) -> Result<Self> {
        let mut queue_evts = Vec::new();
        for _ in device.queue_max_sizes().iter() {
            queue_evts.push(EventFd::new(libc::EFD_NONBLOCK)?)
        }
        let queues = device
            .queue_max_sizes()
            .iter()
            .map(|&s| Queue::new(s))
            .collect();
        Ok(MmioTransport {
            device,
            device_activated: false,
            features_select: 0,
            acked_features_select: 0,
            queue_select: 0,
            driver_status: 0,
            queue_evts,
            config_generation: 0,
            interrupt_status: Arc::new(AtomicUsize::new(0)),
            interrupt_evt: Some(EventFd::new(libc::EFD_NONBLOCK)?),
            queues,
            mem: Some(mem),
        })
    }

    /// Gets the list of queue events that must be triggered whenever the VM writes to
    /// `virtio::NOITFY_REG_OFFSET` past the MMIO base. Each event must be triggered when the
    /// value being written equals the index of the event in this list.
    pub fn queue_evts(&self) -> &[EventFd] {
        self.queue_evts.as_slice()
    }

    /// Gets the event this device uses to interrupt the VM when the used queue is changed
    pub fn interrupt_evt(&self) -> Option<&EventFd> {
        self.interrupt_evt.as_ref()
    }

    fn is_driver_ready(&self) -> bool {
        let ready_bits =
            status::ACKNOWLEDGE | status::DRIVER | status::DRIVER_OK | status::FEATURES_OK;
        self.driver_status == ready_bits && self.driver_status & status::FAILED == 0
    }

    fn are_queues_valid(&self) -> bool {
        if let Some(mem) = self.mem.as_ref() {
            self.queues.iter().all(|q| q.is_valid(mem))
        } else {
            false
        }
    }

    fn check_device_status(&self, set: u32, clr: u32) -> bool {
        self.driver_status & (set | clr) == set
    }

    fn with_queue<U, F>(&self, d: U, f: F) -> U
    where
        F: FnOnce(&Queue) -> U,
    {
        match self.queues.get(self.queue_select as usize) {
            Some(queue) => f(queue),
            None => d,
        }
    }

    fn with_queue_mut<F: FnOnce(&mut Queue)>(&mut self, f: F) -> bool {
        if let Some(queue) = self.queues.get_mut(self.queue_select as usize) {
            f(queue);
            true
        } else {
            false
        }
    }
}

impl BusDevice for MmioTransport {
    // OASIS: MMIO Device Register Layout
    #[allow(clippy::bool_to_int_with_if)]
    fn read(&mut self, offset: u64, data: &mut [u8]) {
        match offset {
            0x00..=0xff if data.len() == 4 => {
                let v = match offset {
                    0x0 => MMIO_MAGIC_VALUE,
                    0x04 => MMIO_VERSION,
                    0x08 => self.device.device_type(),
                    0x0c => VENDOR_ID,
                    0x10 => {
                        self.device.features(self.features_select)
                            | if self.features_select == 1 { 0x1 } else { 0x0 }
                    }
                    0x34 => self.with_queue(0, |q| q.get_max_size() as u32),
                    0x44 => self.with_queue(0, |q| q.ready as u32),
                    0x60 => self.interrupt_status.load(Ordering::SeqCst) as u32,
                    0x70 => self.driver_status,
                    0xfc => self.config_generation,
                    _ => {
                        println!("unknown virtio mmio register read: 0x{:x}", offset);
                        return;
                    }
                };
                LittleEndian::write_u32(data, v);
            }
            0x100..=0xfff => self.device.read_config(offset - 0x100, data),
            _ => {
                // WARN!
                println!(
                    "invalid virtio mmio read: 0x{:x}:0x{:x}",
                    offset,
                    data.len()
                );
            }
        }
        // let first_16bit = u16::from(data[0]) | (u16::from(data[1]) << 8);
        // let second_16bit = u16::from(data[2]) | (u16::from(data[3]) << 8);
        // println!("mmio read: offset=0x{:x}, data=0x{:016b}{:016b}", offset, second_16bit, first_16bit);
    }

    fn write(&mut self, offset: u64, data: &[u8]) {
        // let first_16bit = u16::from(data[0]) | (u16::from(data[1]) << 8);
        // let second_16bit = u16::from(data[2]) | (u16::from(data[3]) << 8);
        // println!("mmio write: offset=0x{:x}, data=0x{:016b}{:016b}", offset, second_16bit, first_16bit);
        fn hi(v: &mut GuestAddress, x: u32) {
            *v = (*v & 0xffff_ffff) | (u64::from(x) << 32)
        }

        fn lo(v: &mut GuestAddress, x: u32) {
            *v = (*v & !0xffff_ffff) | u64::from(x)
        }

        let mut mut_q = false;
        match offset {
            0x00..=0xff if data.len() == 4 => {
                let v = LittleEndian::read_u32(data);
                match offset {
                    0x14 => self.features_select = v,
                    0x20 => self.device.ack_features(self.acked_features_select, v),
                    0x24 => self.acked_features_select = v,
                    0x30 => self.queue_select = v,
                    0x38 => mut_q = self.with_queue_mut(|q| q.size = v as u16),
                    0x44 => mut_q = self.with_queue_mut(|q| q.ready = v == 1),
                    0x64 => {
                        if self.check_device_status(status::DRIVER_OK, 0) {
                            self.interrupt_status
                                .fetch_and(!(v as usize), Ordering::SeqCst);
                        }
                    }
                    0x70 => self.driver_status = v,
                    0x80 => mut_q = self.with_queue_mut(|q| lo(&mut q.desc_table, v)),
                    0x84 => mut_q = self.with_queue_mut(|q| hi(&mut q.desc_table, v)),
                    0x90 => mut_q = self.with_queue_mut(|q| lo(&mut q.avail_ring, v)),
                    0x94 => mut_q = self.with_queue_mut(|q| hi(&mut q.avail_ring, v)),
                    0xa0 => mut_q = self.with_queue_mut(|q| lo(&mut q.used_ring, v)),
                    0xa4 => mut_q = self.with_queue_mut(|q| hi(&mut q.used_ring, v)),
                    _ => {
                        println!("unknown virtio mmio register write: 0x{:x}", offset);
                        return;
                    }
                }
            }
            0x100..=0xfff => {
                println!("mmio write on 0x100 ~ 0xfff : data = {:?}", data);
                if self.check_device_status(status::DRIVER, status::FAILED) {
                    self.device.write_config(offset - 0x100, data)
                } else {
                    println!("can' write to device config data area because driver is ready");
                }
            }
            _ => {
                println!(
                    "invalid virtio mmio write: 0x{:x}:0x{:x}",
                    offset,
                    data.len()
                );
                return;
            }
        }
        if self.device_activated && mut_q {
            println!("virtio queue was changed after device was activated");
        }

        if !self.device_activated && self.is_driver_ready() && self.are_queues_valid() {
            if let Some(interrupt_evt) = self.interrupt_evt.take() {
                if let Some(mem) = self.mem.take() {
                    self.device
                        .activate(
                            mem,
                            interrupt_evt,
                            self.interrupt_status.clone(),
                            self.queues.clone(),
                            self.queue_evts.split_off(0),
                        )
                        .unwrap();
                    self.device_activated = true;
                }
            }
        }
    }
}
