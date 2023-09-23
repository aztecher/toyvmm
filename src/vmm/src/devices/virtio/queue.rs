// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::vstate::memory::GuestMemoryMmap;
use std::cmp::min;
use std::num::Wrapping;
use std::sync::atomic::{fence, Ordering};
use vm_memory::{Address, Bytes, GuestAddress, GuestMemory};

pub const INTERRUPT_STATUS_USED_RING: u32 = 0x1;

const VIRTQ_DESC_F_NEXT: u16 = 0x1;
const VIRTQ_DESC_F_WRITE: u16 = 0x2;

/// A virtio descriptor chain
pub struct DescriptorChain<'a> {
    mem: &'a GuestMemoryMmap,
    desc_table: GuestAddress,
    queue_size: u16,
    ttl: u16, // used to prevent infinite chain cycle

    /// Index into the descriptor table
    pub index: u16,

    /// following attributes is defined for `virtio descriptor`
    /// Guest physical address of device specific data
    pub addr: GuestAddress,

    /// Length of device specific data
    pub len: u32,

    /// Includes next, write, and indirect bits
    pub flags: u16,

    /// Index into the descriptor table of the next descriptor if flags has
    /// the next bit set
    pub next: u16,
}

impl<'a> DescriptorChain<'a> {
    fn checked_new(
        mem: &GuestMemoryMmap,
        desc_table: GuestAddress,
        queue_size: u16,
        index: u16,
    ) -> Option<DescriptorChain> {
        if index >= queue_size {
            return None;
        }

        // The size of each element of descriptor table is 16 bytes
        // - le64 addr  = 8byte
        // - le32 len   = 4byte
        // - le16 flags = 2byte
        // - le16 next  = 2byte
        // So, the calculation of the offset of the address
        // indicated by desc_index is 'index * 16'
        let desc_head = match mem.checked_offset(desc_table, (index as usize) * 16) {
            Some(a) => a,
            None => return None,
        };
        // These reads can't fail unless Guest memory is hopelessly broken
        let addr = GuestAddress(mem.read_obj(desc_head).unwrap());
        mem.checked_offset(desc_head, 16)?;
        let len = mem.read_obj(desc_head.unchecked_add(8)).unwrap();
        let flags: u16 = mem.read_obj(desc_head.unchecked_add(12)).unwrap();
        let next: u16 = mem.read_obj(desc_head.unchecked_add(14)).unwrap();
        let chain = DescriptorChain {
            mem,
            desc_table,
            queue_size,
            ttl: queue_size,
            index,
            addr,
            len,
            flags,
            next,
        };
        if chain.is_valid() {
            Some(chain)
        } else {
            None
        }
    }

    fn is_valid(&self) -> bool {
        match self.mem.checked_offset(self.addr, self.len as usize) {
            Some(_) => !self.has_next() || self.next < self.queue_size,
            None => false,
        }
    }

    /// Gets if this descriptor chain has another descriptor chain linked after it.
    pub fn has_next(&self) -> bool {
        self.flags & VIRTQ_DESC_F_NEXT != 0 && self.ttl > 1
    }

    /// If the driver designated this as a write only descriptor.
    ///
    /// If this is false, this descriptor is read only
    /// Write only means that the emulated device can write and the driver can read.
    pub fn is_write_only(&self) -> bool {
        self.flags & VIRTQ_DESC_F_WRITE != 0
    }

    /// Gets the next descriptor in this descriptor chain, if there is one.
    ///
    /// Note that this is distinct from the next descriptor chain returned by `AvailIter`, which is
    /// the head of the next _available_ descriptor chain.
    pub fn next_descriptor(&self) -> Option<DescriptorChain<'a>> {
        if self.has_next() {
            DescriptorChain::checked_new(self.mem, self.desc_table, self.queue_size, self.next).map(
                |mut c| {
                    c.ttl = self.ttl - 1;
                    c
                },
            )
        } else {
            None
        }
    }
}

/// Consuming iterator over all available descriptor chain heads in the queue.
pub struct AvailIter<'a, 'b> {
    mem: &'a GuestMemoryMmap,
    desc_table: GuestAddress,
    avail_ring: GuestAddress,
    next_index: Wrapping<u16>,
    last_index: Wrapping<u16>,
    queue_size: u16,
    next_avail: &'b mut Wrapping<u16>,
}

impl<'a, 'b> Iterator for AvailIter<'a, 'b> {
    type Item = DescriptorChain<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_index == self.last_index {
            return None;
        }

        // Access the avail_ring element indicated by self.next_index
        // skip 4byte (=u16 x 2 / 'flags' member and 'idx' member from avail_ring)
        // Because of the Ring, calculate modulo (= self.next_index % self.queue_size)
        // and the result of modulo calculation, convert to 2bytes order
        // (because the unit of avail_ring's element is 2byte)
        let offset = (4 + (self.next_index.0 % self.queue_size) * 2) as usize;
        // Calculate the next desc_index address from avail_ring address.
        let avail_addr = match self.mem.checked_offset(self.avail_ring, offset) {
            Some(a) => a,
            None => return None,
        };
        // Get the next desc_index value from avail_ring.
        let desc_index: u16 = self.mem.read_obj(avail_addr).unwrap();

        self.next_index += Wrapping(1);

        let ret =
            DescriptorChain::checked_new(self.mem, self.desc_table, self.queue_size, desc_index);
        if ret.is_some() {
            *self.next_avail += Wrapping(1);
        }
        ret
    }
}

#[derive(Clone)]
/// A virtio queue's parameters
pub struct Queue {
    /// The maximal size in elements offered by the device
    max_size: u16,

    /// The queue size in elements the driver selected
    pub size: u16,

    /// Indicates if the queue is finished with configuration
    pub ready: bool,

    /// Guest physical address of descriptor table
    pub desc_table: GuestAddress,

    /// Guest physical address of the available ring
    pub avail_ring: GuestAddress,

    /// Guest physical address of the used ring
    pub used_ring: GuestAddress,

    next_avail: Wrapping<u16>,
    next_used: Wrapping<u16>,
}

impl Queue {
    /// Constructs an empty virtio queue with the given `max_size`
    pub fn new(max_size: u16) -> Queue {
        Queue {
            max_size,
            size: 0,
            ready: false,
            desc_table: GuestAddress(0),
            avail_ring: GuestAddress(0),
            used_ring: GuestAddress(0),
            next_avail: Wrapping(0),
            next_used: Wrapping(0),
        }
    }

    pub fn get_max_size(&self) -> u16 {
        self.max_size
    }

    pub fn actual_size(&self) -> u16 {
        min(self.size, self.max_size)
    }

    pub fn is_valid(&self, mem: &GuestMemoryMmap) -> bool {
        let queue_size = self.actual_size() as usize;
        let desc_table = self.desc_table;
        let desc_table_size = 16 * queue_size;
        let avail_ring = self.avail_ring;
        let avail_ring_size = 6 + 2 * queue_size;
        let used_ring = self.used_ring;
        let used_ring_size = 6 + 8 + queue_size;
        if !self.ready {
            println!("attempt to use virtio queue that is not marked ready");
            false
        } else if self.size > self.max_size || self.size == 0 || (self.size & (self.size - 1)) != 0
        {
            // self.size & (self.size - 1) != 0 checks if the self.size is 2^N
            println!("virtio queue with invalid size: {}", self.size);
            false
        } else if desc_table
            .checked_add(desc_table_size as u64)
            .map_or(true, |v| !mem.address_in_range(v))
        {
            println!(
                "virtio queue descriptor table goes out of bounds: start:0x{:08x}, end:0x{:08x}",
                desc_table.0, desc_table_size,
            );
            false
        } else if avail_ring
            .checked_add(avail_ring_size as u64)
            .map_or(true, |v| !mem.address_in_range(v))
        {
            println!(
                "virtio queue available ring goes out of bounds: start:0x{:08x}, end: 0x{:08x}",
                avail_ring.0, avail_ring_size,
            );
            false
        } else if used_ring
            .checked_add(used_ring_size as u64)
            .map_or(true, |v| !mem.address_in_range(v))
        {
            println!(
                "virtio queue used ring goes out of bounds: start:0x{:08x}, end: 0x{:08x}",
                used_ring.0, used_ring_size,
            );
            false
        } else {
            true
        }
    }

    /// A consuming iterator over all available descriptor chain heads offered by the driver
    pub fn iter<'a, 'b>(&'b mut self, mem: &'a GuestMemoryMmap) -> AvailIter<'a, 'b> {
        if !self.is_valid(mem) {
            return AvailIter {
                mem,
                desc_table: GuestAddress(0),
                avail_ring: GuestAddress(0),
                next_index: Wrapping(0),
                last_index: Wrapping(0),
                queue_size: 0,
                next_avail: &mut self.next_avail,
            };
        }
        let queue_size = self.actual_size();
        let avail_ring = self.avail_ring;

        // Access the 'idx' member of available ring
        // skip 2byte (= u16 / 'flags' member) from avail_ring address
        // and get 2byte (= u16 / 'idx' member that represents the newest index of avail_ring) from that address.
        let index_addr = mem.checked_offset(avail_ring, 2).unwrap();
        let last_index: u16 = mem.read_obj(index_addr).unwrap();

        AvailIter {
            mem,
            desc_table: self.desc_table,
            avail_ring: self.avail_ring,
            next_index: self.next_avail,
            last_index: Wrapping(last_index),
            queue_size,
            next_avail: &mut self.next_avail,
        }
    }

    /// Puts an available descriptor head into the used ring for use by the guest
    pub fn add_used(&mut self, mem: &GuestMemoryMmap, desc_index: u16, len: u32) {
        if desc_index >= self.actual_size() {
            // TODO error
            return;
        }
        let used_ring = self.used_ring;
        let next_used = (self.next_used.0 % self.actual_size()) as u64;

        // virtq_used structure has 4 byte entry before `ring` fields, so skip 4 byte.
        // And each ring entry has 8 bytes, so skip 8 * index.
        let used_elem = used_ring.unchecked_add(4 + next_used * 8);
        // write the descriptor index to virtq_used_elem.id
        mem.write_obj(desc_index, used_elem).unwrap();
        // write the data length to the virtq_used_elem.len
        mem.write_obj(len, used_elem.unchecked_add(4)).unwrap();

        // increment the used index that is the last processed in host side.
        self.next_used += Wrapping(1);

        // This fence ensures all descriptor writes are visible before the index update is.
        fence(Ordering::Release);
        mem.write_obj(self.next_used.0, used_ring.unchecked_add(2))
            .unwrap();
    }
}
