// Copyright 2017 Amazon.com, Inc. or its affiliates.  All Rights Reserved.

// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::devices::virtio;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::mpsc::{channel, Receiver, Sender};
use utils::epoll;

/// Errors associated with actions on epoll.
#[derive(Debug, thiserror::Error)]
pub enum EpollContextError {
    /// Epoll file descriptor create error.
    #[error("Epoll file descriptor create error: {0}")]
    Create(std::io::Error),
    #[error("Failed to add a file descriptor to epoll: {0}")]
    Add(std::io::Error),
}

pub type DeviceEventT = u16;

pub trait EpollHandler: Send {
    fn handle_event(&mut self, device_event: DeviceEventT, event_flags: u32);
}

// Changes to private (in firecracker use VmCore)
#[derive(Clone, Copy)]
pub enum EpollDispatch {
    Exit,
    Stdin,
    DeviceHandler(usize, DeviceEventT),
}

pub struct MaybeHandler {
    handler: Option<Box<dyn EpollHandler>>,
    receiver: Receiver<Box<dyn EpollHandler>>,
}

impl MaybeHandler {
    fn new(receiver: Receiver<Box<dyn EpollHandler>>) -> Self {
        MaybeHandler {
            handler: None,
            receiver,
        }
    }
}

//This should handle epoll related business from now on. A glaring shortcoming of the current
//design is the liberal passing around of raw_fds, and duping of file descriptors. This issue
//will be solved when we also implement device removal.
pub struct EpollContext {
    pub ep: epoll::Epoll,
    pub dispatch_table: Vec<EpollDispatch>,
    pub device_handlers: Vec<MaybeHandler>,
}

impl EpollContext {
    pub fn new(exit_evt_raw_fd: RawFd) -> Result<Self, EpollContextError> {
        // let epoll_raw_fd = epoll::create(true).map_err(EpollContextError::Create)?;
        let epoll_fd = epoll::Epoll::new().map_err(EpollContextError::Create)?;
        // some reasonable initial capacity value
        let mut dispatch_table = Vec::with_capacity(20);
        let device_handlers = Vec::with_capacity(6);
        epoll_fd
            .ctl(
                epoll::ControlOperation::Add,
                exit_evt_raw_fd,
                epoll::EpollEvent::new(epoll::EventSet::IN, dispatch_table.len() as u64),
            )
            .map_err(EpollContextError::Add)?;
        dispatch_table.push(EpollDispatch::Exit);

        epoll_fd
            .ctl(
                epoll::ControlOperation::Add,
                libc::STDIN_FILENO,
                epoll::EpollEvent::new(epoll::EventSet::IN, dispatch_table.len() as u64),
            )
            .map_err(EpollContextError::Add)?;

        dispatch_table.push(EpollDispatch::Stdin);

        Ok(EpollContext {
            ep: epoll_fd,
            dispatch_table,
            device_handlers,
        })
    }

    fn allocate_tokens(&mut self, count: usize) -> (u64, Sender<Box<dyn EpollHandler>>) {
        let dispatch_base = self.dispatch_table.len() as u64;
        let device_idx = self.device_handlers.len();
        let (sender, receiver) = channel();

        for x in 0..count - 1 {
            self.dispatch_table
                .push(EpollDispatch::DeviceHandler(device_idx, x as DeviceEventT));
        }
        self.device_handlers.push(MaybeHandler::new(receiver));
        (dispatch_base, sender)
    }

    pub fn allocate_virtio_blk_token(&mut self) -> virtio::block::EpollConfig {
        let (dispatch_base, sender) = self.allocate_tokens(2);
        let ep_clone = unsafe {
            let mut clone = std::mem::zeroed::<epoll::Epoll>();
            std::ptr::copy(&self.ep, &mut clone, 1);
            clone
        };
        virtio::block::EpollConfig::new(dispatch_base, ep_clone, sender)
    }

    pub fn allocate_virtio_net_tokens(&mut self) -> virtio::net::EpollConfig {
        let (dispatch_base, sender) = self.allocate_tokens(4);
        let ep_clone = unsafe {
            let mut clone = std::mem::zeroed::<epoll::Epoll>();
            std::ptr::copy(&self.ep, &mut clone, 1);
            clone
        };
        virtio::net::EpollConfig::new(dispatch_base, ep_clone, sender)
    }

    #[allow(clippy::toplevel_ref_arg)]
    pub fn get_device_handler(&mut self, device_idx: usize) -> &mut dyn EpollHandler {
        let ref mut maybe = self.device_handlers[device_idx];
        match maybe.handler {
            Some(ref mut v) => v.as_mut(),
            None => maybe
                .handler
                .get_or_insert(maybe.receiver.recv().unwrap())
                .as_mut(),
        }
    }
}

impl Drop for EpollContext {
    fn drop(&mut self) {
        let rc = unsafe { libc::close(self.ep.as_raw_fd()) };
        if rc != 0 {
            println!("warn: cannot close epoll");
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ::utils::eventfd::EventFd;
    use std::os::unix::io::AsRawFd;

    fn create_epoll_context() -> EpollContext {
        EpollContext::new(EventFd::new(libc::EFD_NONBLOCK).unwrap().as_raw_fd()).unwrap()
    }

    #[test]
    pub fn test_epoll_context_new() {
        let epoll_ctx = create_epoll_context();
        assert_eq!(epoll_ctx.dispatch_table.len(), 2);
        assert_eq!(epoll_ctx.device_handlers.len(), 0);
        match epoll_ctx.dispatch_table.get(0).unwrap() {
            EpollDispatch::Exit => (),
            _ => unreachable!(),
        }
        match epoll_ctx.dispatch_table.get(1).unwrap() {
            EpollDispatch::Stdin => (),
            _ => unreachable!(),
        }
    }

    #[test]
    pub fn test_allocate_tokens() {
        let mut epoll_ctx = create_epoll_context();
        // Allocate tokens for virtio-blk
        {
            // allocate 1 token for device
            let (dispatch_base, _) = epoll_ctx.allocate_tokens(2);
            assert_eq!(epoll_ctx.dispatch_table.len(), 3);
            assert_eq!(dispatch_base, 2);
            match epoll_ctx
                .dispatch_table
                .get(dispatch_base as usize)
                .unwrap()
            {
                EpollDispatch::DeviceHandler(device_idx, device_token) => {
                    assert_eq!(device_idx, &0);
                    assert_eq!(device_token, &0);
                }
                _ => unreachable!(),
            }
        }
        // Allocate tokens for virtio-net (additionally)
        {
            // allocate 3 token for device
            let (dispatch_base, _) = epoll_ctx.allocate_tokens(4);
            assert_eq!(epoll_ctx.dispatch_table.len(), 6);
            assert_eq!(dispatch_base, 3);
            match epoll_ctx
                .dispatch_table
                .get(dispatch_base as usize)
                .unwrap()
            {
                EpollDispatch::DeviceHandler(device_idx, device_token) => {
                    assert_eq!(device_idx, &1);
                    assert_eq!(device_token, &0);
                }
                _ => unreachable!(),
            }
            match epoll_ctx
                .dispatch_table
                .get(dispatch_base as usize + 1)
                .unwrap()
            {
                EpollDispatch::DeviceHandler(device_idx, device_token) => {
                    assert_eq!(device_idx, &1);
                    assert_eq!(device_token, &1);
                }
                _ => unreachable!(),
            }
            match epoll_ctx
                .dispatch_table
                .get(dispatch_base as usize + 1)
                .unwrap()
            {
                EpollDispatch::DeviceHandler(device_idx, device_token) => {
                    assert_eq!(device_idx, &1);
                    assert_eq!(device_token, &1);
                }
                _ => unreachable!(),
            }
        }
    }
}
