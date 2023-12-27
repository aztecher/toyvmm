// Copyright 2023 aztecher, or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use utils::eventfd::EventFd;

use crate::devices::virtio::queue::Queue;
use crate::vstate::memory::GuestMemoryMmap;

#[derive(Debug, thiserror::Error)]
pub enum ActivateError {
    /// Failed to create eventfd in virtio device activating process.
    #[error("Failed to create eventfd in virtio device activating process: {0}")]
    EventFd(#[source] std::io::Error),
    /// Failed to configure epoll_ctl in virtio device activating process.
    #[error("Failed to configure epoll_ctl in virtio device activating process: {0}")]
    EpollCtl(#[source] std::io::Error),
    /// Unsupported number of virtio queues detected.
    #[error("Unsupported number of virtio queues detected, queue num is {0}")]
    UnsupportedNumOfVirtioQueue(usize),
    /// Unexpected mismatch of the number of virtio queues and eventfd.
    #[error("Unexpected mismatch of the number of virtio queues ({0}) and eventfds ({1}).")]
    UnexpectedMismatchNumOfVirtioQueuesAndEventFds(usize, usize),
    /// Generic error occured in virtio device activating process.
    #[error("Generic error occured in virtio device activating process.")]
    BadActivate,
}

/// Trait for virtio devices to be driven by a virtio transport.
///
/// The lifecycle of a virtio device is to be moved to a virtio transport, which will then query the
/// device. Once the guest driver has configured the device, `VirtioDevice::activate` will be called
/// and all the events, memory, and queues for device operation will be moved into the device.
/// Optionally, a virtio device can implement device reset in which it returns said resources and
/// resets its internal.
pub trait VirtioDevice: Send {
    /// The virtio device type.
    fn device_type(&self) -> u32;

    /// The maximum size of each queue that this device supports.
    fn queue_max_sizes(&self) -> &[u16];

    /// This set of feature bits shifted by `page * 32`.
    fn features(&self, page: u32) -> u32 {
        let _ = page;
        0
    }

    /// Acknowledges that this set of features should be enabled.
    fn ack_features(&mut self, page: u32, value: u32) {
        let _ = page;
        let _ = value;
    }

    /// Reads this device configuration space at `offset`
    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let _ = offset;
        let _ = data;
    }

    /// Writes to this device configuration space at `offset`
    fn write_config(&mut self, offset: u64, data: &[u8]) {
        let _ = offset;
        let _ = data;
    }

    /// Activates this device for real usage.
    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt_evt: EventFd,
        status: Arc<AtomicUsize>,
        queues: Vec<Queue>,
        queue_evts: Vec<EventFd>,
    ) -> Result<(), ActivateError>;

    fn reset(&mut self) -> Option<(EventFd, Vec<EventFd>)> {
        None
    }
}
