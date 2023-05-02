// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use vmm_sys_util::eventfd::EventFd;
use crate::kvm::memory::GuestMemoryMmap;
use crate::devices::{
    epoll::{DeviceEventT, EpollHandler},
    virtio::{
        types,
        virtio_device::{ActivateResult, ActivateError, VirtioDevice},
        queue::Queue,
    },
};

const QUEUE_SIZE: u16 = 256;
const QUEUE_SIZES: &'static [u16] = &[QUEUE_SIZE];

pub struct BlockEpollHandler {
}

impl BlockEpollHandler {
}

impl EpollHandler for BlockEpollHandler {
    fn handle_event(&mut self, device_event: DeviceEventT, _: u32) {
    }
}

pub struct EpollConfig {
}

impl EpollConfig {
}

pub struct Block {
}

impl Block {
}

impl Drop for Block {
    fn drop(&mut self) {
    }
}

impl VirtioDevice for Block {
    fn device_type(&self) -> u32 {
        types::BLOCK_DEVICE
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt_evt: EventFd,
        status: Arc<AtomicUsize>,
        queues: Vec<Queue>,
        mut queue_evts: Vec<EventFd>,
    ) -> ActivateResult {
        // TODO
        Err(ActivateError::BadActivate)
    }

}
