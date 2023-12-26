// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::devices::util::sys::virtio::net as SysVirtioNet;
use crate::devices::{
    epoll::{DeviceEventT, EpollHandler},
    virtio::{
        queue::{DescriptorChain, Queue, INTERRUPT_STATUS_USED_RING},
        types,
        virtio_device::{ActivateError, VirtioDevice},
    },
};
use crate::vstate::memory::GuestMemoryMmap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    os::linux::fs::MetadataExt,
    os::unix::io::AsRawFd,
};
use utils::{epoll, eventfd::EventFd};
use vm_memory::{Bytes, GuestAddress, GuestMemory, GuestMemoryError};

const SECTOR_SHIFT: u8 = 9; // 512 = 2^9
const SECTOR_SIZE: u64 = 0x01 << SECTOR_SHIFT;

const QUEUE_SIZE: u16 = 256;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE];

const VIRTIO_BLK_T_IN: u32 = 0;
const VIRTIO_BLK_T_OUT: u32 = 1;
const VIRTIO_BLK_T_FLUSH: u32 = 4;
const VIRTIO_BLK_T_GET_ID: u32 = 8;

const VIRTIO_BLK_S_OK: u8 = 0;
const VIRTIO_BLK_S_IOERR: u8 = 1;
const VIRTIO_BLK_S_UNSUPP: u8 = 2;

const QUEUE_AVAIL_EVENT: DeviceEventT = 0;
const KILL_EVENT: DeviceEventT = 1;

/// Errors associated with actions on block.
#[derive(Debug, thiserror::Error)]
pub enum BlockError {
    /// Error while executing block I/O event
    #[error("Error while executing block I/O event: {0}")]
    Execute(BlockExecuteError),
}

/// BlockRequestType represents the request type of virtio-blk.
#[derive(Debug, PartialEq)]
enum BlockRequestType {
    In,
    Out,
    Flush,
    GetDeviceID,
    Unsupported(u32),
}

/// Errors associated with actions on virtio-blk.
#[derive(Debug, thiserror::Error)]
enum BlockRequestParseError {
    /// Guest gave us bad memory address.
    #[error("Guest gave us bad memory address: {0}")]
    BadMemoryAddressError(#[from] GuestMemoryError),
    /// Guest gave us offsets that would have overflowed a usize
    #[error("Guest gave us offsets `{0:X}` that would have overflowed a usize `{1}`")]
    CheckedOffset(u64, usize),
    /// Guest gave us a write only descriptor that protocol says to read from.
    #[error("Guest gave us a write only descriptor that protocol says to read from")]
    UnexpectedWriteOnlyDescriptor,
    /// Guest gave us a read only descriptor that protocol says to write to.
    #[error("Guest gave us a read only descriptor that protocol says to write to")]
    UnexpectedReadOnlyDescriptor,
    /// Guest gave us too few desciptor in a descriptor chain.
    #[error("Guest gave us too few desciptor in a descriptor chain")]
    DescriptorChainTooShort,
    /// Guest gave us a descriptor that was too short to use.
    #[error("Guest gave us a descriptor that was too short to use")]
    DescriptorLengthTooSmall,
    /// Getting a block's metadata failes.
    #[error("Getting a block's metadata failes: {0}")]
    GetFileMetadata(std::io::Error),
}

/// Errors associated with actions on backend (host-side) disk file.
#[derive(Debug, thiserror::Error)]
pub enum BlockExecuteError {
    /// Failed to flush backend (host-side) disk file.
    #[error("Failed to flush backend (host-side) disk file: {0}")]
    Flush(#[source] std::io::Error),
    /// Failed to read from backend (host-side) disk file.
    #[error("Failed to read from backend (host-side) disk file: {0}")]
    Read(#[source] GuestMemoryError),
    /// Failed to seek backend (host-side) disk file.
    #[error("Failed to seek backend (host-side) disk file: {0}")]
    Seek(#[source] std::io::Error),
    /// Failed to write to backend (host-side) disk file.
    #[error("Failed to write to backend (host-side) disk file: {0}")]
    Write(#[source] GuestMemoryError),
    /// Unsupported request is occcured.
    #[error("Unsupported request has occcured. Request type is {0}.")]
    Unsupported(u32),
}

impl BlockExecuteError {
    fn status(&self) -> u8 {
        match self {
            BlockExecuteError::Flush(_) => VIRTIO_BLK_S_IOERR,
            BlockExecuteError::Read(_) => VIRTIO_BLK_S_IOERR,
            BlockExecuteError::Seek(_) => VIRTIO_BLK_S_IOERR,
            BlockExecuteError::Write(_) => VIRTIO_BLK_S_IOERR,
            BlockExecuteError::Unsupported(_) => VIRTIO_BLK_S_UNSUPP,
        }
    }
}

struct Request {
    request_type: BlockRequestType,
    sector: u64,
    data_addr: GuestAddress,
    data_len: u32,
    status_addr: GuestAddress,
}

impl Request {
    fn request_type(
        mem: &GuestMemoryMmap,
        desc_addr: GuestAddress,
    ) -> std::result::Result<BlockRequestType, BlockRequestParseError> {
        let t = mem
            .read_obj(desc_addr)
            .map_err(BlockRequestParseError::BadMemoryAddressError)?;
        match t {
            VIRTIO_BLK_T_IN => Ok(BlockRequestType::In),
            VIRTIO_BLK_T_OUT => Ok(BlockRequestType::Out),
            VIRTIO_BLK_T_FLUSH => Ok(BlockRequestType::Flush),
            VIRTIO_BLK_T_GET_ID => Ok(BlockRequestType::GetDeviceID),
            t => Ok(BlockRequestType::Unsupported(t)),
        }
    }

    fn sector(
        mem: &GuestMemoryMmap,
        desc_addr: GuestAddress,
    ) -> std::result::Result<u64, BlockRequestParseError> {
        const SECTOR_OFFSET: usize = 8;
        let addr = match mem.checked_offset(desc_addr, SECTOR_OFFSET) {
            Some(v) => v,
            None => {
                return Err(BlockRequestParseError::CheckedOffset(
                    desc_addr.0,
                    SECTOR_OFFSET,
                ))
            }
        };

        mem.read_obj(addr)
            .map_err(BlockRequestParseError::BadMemoryAddressError)
    }

    fn build_device_id(disk_image: &File) -> std::result::Result<String, BlockRequestParseError> {
        let blk_metadata = match disk_image.metadata() {
            Err(e) => return Err(BlockRequestParseError::GetFileMetadata(e)),
            Ok(m) => m,
        };
        Ok(format!(
            "{}{}{}",
            blk_metadata.st_dev(),
            blk_metadata.st_rdev(),
            blk_metadata.st_ino(),
        ))
    }

    fn parse(
        avail_desc: &DescriptorChain,
        mem: &GuestMemoryMmap,
    ) -> std::result::Result<Request, BlockRequestParseError> {
        // The head contains the request type which MUST be readable
        if avail_desc.is_write_only() {
            return Err(BlockRequestParseError::UnexpectedWriteOnlyDescriptor);
        }

        let req_type = Self::request_type(mem, avail_desc.addr)?;
        let sector = Self::sector(mem, avail_desc.addr)?;
        let data_desc = avail_desc
            .next_descriptor()
            .ok_or(BlockRequestParseError::DescriptorChainTooShort)?;
        let status_desc = data_desc
            .next_descriptor()
            .ok_or(BlockRequestParseError::DescriptorChainTooShort)?;
        if data_desc.is_write_only() && req_type == BlockRequestType::Out {
            return Err(BlockRequestParseError::UnexpectedWriteOnlyDescriptor);
        }
        if !data_desc.is_write_only() && req_type == BlockRequestType::In {
            return Err(BlockRequestParseError::UnexpectedReadOnlyDescriptor);
        }

        // The status MUST always be writable
        if !status_desc.is_write_only() {
            return Err(BlockRequestParseError::UnexpectedReadOnlyDescriptor);
        }

        if status_desc.len < 1 {
            return Err(BlockRequestParseError::DescriptorLengthTooSmall);
        }

        Ok(Request {
            request_type: req_type,
            sector,
            data_addr: data_desc.addr,
            data_len: data_desc.len,
            status_addr: status_desc.addr,
        })
    }

    fn execute<T: Seek + Read + Write>(
        &self,
        disk: &mut T,
        mem: &GuestMemoryMmap,
        disk_id: &Vec<u8>,
    ) -> std::result::Result<u32, BlockExecuteError> {
        disk.seek(SeekFrom::Start(self.sector << SECTOR_SHIFT))
            .map_err(BlockExecuteError::Seek)?;
        match self.request_type {
            BlockRequestType::In => {
                mem.read_from(self.data_addr, disk, self.data_len as usize)
                    .map_err(BlockExecuteError::Read)?;
                return Ok(self.data_len);
            }
            BlockRequestType::Out => {
                mem.write_to(self.data_addr, disk, self.data_len as usize)
                    .map_err(BlockExecuteError::Write)?;
            }
            BlockRequestType::Flush => disk.flush().map_err(BlockExecuteError::Flush)?,
            BlockRequestType::GetDeviceID => {
                mem.write_slice(disk_id.as_slice(), self.data_addr)
                    .map_err(BlockExecuteError::Write)?;
            }
            BlockRequestType::Unsupported(t) => return Err(BlockExecuteError::Unsupported(t)),
        };
        Ok(0)
    }
}

pub struct BlockEpollHandler {
    queues: Vec<Queue>,
    mem: GuestMemoryMmap,
    disk_image: File,
    interrupt_status: Arc<AtomicUsize>,
    interrupt_evt: EventFd,
    queue_evt: EventFd,
    disk_image_id: Vec<u8>,
}

impl BlockEpollHandler {
    fn process_queue(&mut self, queue_index: usize) -> bool {
        let queue = &mut self.queues[queue_index];
        let mut used_desc_heads = [(0, 0); QUEUE_SIZE as usize];
        let mut used_count = 0;
        for avail_desc in queue.iter(&self.mem) {
            let len;
            match Request::parse(&avail_desc, &self.mem) {
                Ok(request) => {
                    let status =
                        match request.execute(&mut self.disk_image, &self.mem, &self.disk_image_id)
                        {
                            Ok(l) => {
                                len = l;
                                VIRTIO_BLK_S_OK
                            }
                            Err(e) => {
                                println!("failed executing disk request: {:?}", e);
                                len = 1;
                                e.status()
                            }
                        };
                    // Use unwrap() because the request parsing process already checked the status_addr was valid.
                    self.mem.write_obj(status, request.status_addr).unwrap();
                }
                Err(e) => {
                    println!("failed processing available desciptor chain: {:?}", e);
                    len = 0;
                }
            }
            used_desc_heads[used_count] = (avail_desc.index, len);
            used_count += 1;
        }
        for &(desc_index, len) in &used_desc_heads[..used_count] {
            queue.add_used(&self.mem, desc_index, len);
        }
        used_count > 0
    }

    fn signal_used_queue(&self) {
        self.interrupt_status
            .fetch_or(INTERRUPT_STATUS_USED_RING as usize, Ordering::SeqCst);
        self.interrupt_evt.write(1).unwrap();
    }
}

impl EpollHandler for BlockEpollHandler {
    fn handle_event(&mut self, device_event: DeviceEventT, _: u32) {
        match device_event {
            QUEUE_AVAIL_EVENT => {
                if let Err(e) = self.queue_evt.read() {
                    println!("failed reading queeue EventFd: {:?}", e);
                    return;
                }
                if self.process_queue(0) {
                    self.signal_used_queue();
                }
            }
            KILL_EVENT => {
                // TODO: change this when implementing device removal
                println!("block device killed")
            }
            _ => panic!("unknown token for block device"),
        }
    }
}

pub struct EpollConfig {
    queue_avail_token: u64,
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
            queue_avail_token: first_token,
            kill_token: first_token + 1,
            ep,
            sender,
        }
    }
}

/// Virtio device for exposing block level read/write operations on a host file
pub struct Block {
    kill_evt: Option<EventFd>,
    disk_image: Option<File>,
    avail_features: u64,
    acked_features: u64,
    config_space: Vec<u8>,
    epoll_config: EpollConfig,
}

impl Block {
    /// Create a new virtio block device that operates on the given file
    /// The given file must be seekable and sizable
    pub fn new(mut disk_image: File, epoll_config: EpollConfig) -> Result<Block, BlockError> {
        let disk_size: u64 = disk_image
            .seek(SeekFrom::End(0))
            .map_err(|e| BlockError::Execute(BlockExecuteError::Seek(e)))?;
        if disk_size % SECTOR_SIZE != 0 {
            println!(
                "Disk size {} is not a multiple of sector size {}; \
                     the remainder will not be visible to the guest.",
                disk_size, SECTOR_SIZE
            );
        }
        let avail_features = 1 << SysVirtioNet::VIRTIO_F_VERSION_1;
        Ok(Block {
            kill_evt: None,
            disk_image: Some(disk_image),
            avail_features,
            acked_features: 0u64,
            config_space: Self::build_config_space(disk_size),
            epoll_config,
        })
    }

    fn build_config_space(disk_size: u64) -> Vec<u8> {
        // We only support disk size, which uses the first two words of the configuration space.
        // If the image is not a multiple of the sector size, the tail bits are not exposed.
        // The config space is little endian
        let mut config = Vec::with_capacity(8);
        let num_sectors = disk_size >> SECTOR_SHIFT;
        for i in 0..8 {
            config.push((num_sectors >> (8 * i)) as u8);
        }
        config
    }
}

impl Drop for Block {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.kill_evt.take() {
            // Ignore the result because there is nothing we cna do about it
            let _ = kill_evt.write(1);
        }
    }
}

impl VirtioDevice for Block {
    fn device_type(&self) -> u32 {
        types::BLOCK_DEVICE
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn features(&self, page: u32) -> u32 {
        match page {
            0 => self.avail_features as u32,
            1 => (self.avail_features >> 32) as u32,
            _ => {
                println!(
                    "block: virtio-block got request for features page: {}",
                    page,
                );
                0u32
            }
        }
    }

    fn ack_features(&mut self, page: u32, value: u32) {
        let mut v = match page {
            0 => value as u64,
            1 => (value as u64) << 32,
            _ => {
                println!(
                    "block: virtio-block device cannot ack unknown feature page: {}",
                    page
                );
                0u64
            }
        };

        let unrequested_features = v & !self.avail_features;
        if unrequested_features != 0 {
            println!("block: virtio-block got unknown feature ack: {:x}", v);
            v &= !unrequested_features;
        }
        self.acked_features |= v;
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_len = self.config_space.len() as u64;
        if offset >= config_len {
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len
            data.write_all(
                &self.config_space[offset as usize..std::cmp::min(end, config_len) as usize],
            )
            .unwrap();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        let data_len = data.len() as u64;
        let config_len = self.config_space.len() as u64;
        if offset + data_len > config_len {
            println!("block: failed to write config space");
            return;
        }
        let (_, right) = self.config_space.split_at_mut(offset as usize);
        right.copy_from_slice(data);
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt_evt: EventFd,
        status: Arc<AtomicUsize>,
        queues: Vec<Queue>,
        mut queue_evts: Vec<EventFd>,
    ) -> Result<(), ActivateError> {
        if queues.len() != 1 || queue_evts.len() != 1 {
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
        let (self_kill_evt, kill_evt) =
            match EventFd::new(libc::EFD_NONBLOCK).and_then(|e| Ok((e.try_clone()?, e))) {
                Ok(v) => v,
                Err(e) => return Err(ActivateError::EventFd(e)),
            };
        self.kill_evt = Some(self_kill_evt);

        if let Some(disk_image) = self.disk_image.take() {
            let queue_evt = queue_evts.remove(0);
            let queue_evt_raw_fd = queue_evt.as_raw_fd();
            let kill_evt_raw_fd = kill_evt.as_raw_fd();

            // build_device_id
            let disk_image_id = match Request::build_device_id(&disk_image) {
                Err(_) => {
                    println!("could not generate device id");
                    Vec::new()
                }
                Ok(m) => {
                    let virtio_blk_id_bytes = 20;
                    let mut buf = vec![0; virtio_blk_id_bytes];
                    let disk_id = m.as_bytes();
                    let bytes_to_copy = std::cmp::min(disk_id.len(), virtio_blk_id_bytes);
                    buf[0..bytes_to_copy].clone_from_slice(&disk_id[..bytes_to_copy]);
                    buf
                }
            };

            let handler = BlockEpollHandler {
                queues,
                mem,
                disk_image,
                interrupt_status: status,
                interrupt_evt,
                queue_evt,
                disk_image_id,
            };

            // the channel should be open at this point
            self.epoll_config.sender.send(Box::new(handler)).unwrap();

            self.epoll_config
                .ep
                .ctl(
                    epoll::ControlOperation::Add,
                    queue_evt_raw_fd,
                    epoll::EpollEvent::new(
                        epoll::EventSet::IN,
                        self.epoll_config.queue_avail_token,
                    ),
                )
                .map_err(ActivateError::EpollCtl)?;
            self.epoll_config
                .ep
                .ctl(
                    epoll::ControlOperation::Add,
                    kill_evt_raw_fd,
                    epoll::EpollEvent::new(epoll::EventSet::IN, self.epoll_config.kill_token),
                )
                .map_err(ActivateError::EpollCtl)?;
            return Ok(());
        }

        Err(ActivateError::BadActivate)
    }
}
