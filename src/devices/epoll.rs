// Copyright 2017 Amazon.com, Inc. or its affiliates.  All Rights Reserved.

// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use epoll;
use std::os::unix::io::RawFd;
use std::sync::mpsc::{channel, Receiver, Sender};
use crate::devices::virtio;

#[derive(Debug)]
pub enum Error {
    EpollFd(std::io::Error),
}

type Result<T> = std::result::Result<T, Error>;

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
    pub epoll_raw_fd: RawFd,
    pub dispatch_table: Vec<EpollDispatch>,
    pub device_handlers: Vec<MaybeHandler>,
}

impl EpollContext {
    pub fn new(exit_evt_raw_fd: RawFd) -> Result<Self> {
        // TODO: Before
        let epoll_raw_fd = epoll::create(true).map_err(Error::EpollFd)?;
        // some reasonable initial capacity value
        let mut dispatch_table = Vec::with_capacity(20);
        let device_handlers = Vec::with_capacity(6);

        epoll::ctl(
            epoll_raw_fd,
            epoll::EPOLL_CTL_ADD,
            exit_evt_raw_fd,
            epoll::Event::new(epoll::EPOLLIN, dispatch_table.len() as u64),
        ).map_err(Error::EpollFd)?;

        dispatch_table.push(EpollDispatch::Exit);

        epoll::ctl(
            epoll_raw_fd,
            epoll::EPOLL_CTL_ADD,
            libc::STDIN_FILENO,
            epoll::Event::new(epoll::EPOLLIN, dispatch_table.len() as u64),
        ).map_err(Error::EpollFd)?;

        dispatch_table.push(EpollDispatch::Stdin);

        // ERROR... following code
        // use vmm_sys_util::epoll;
        // let mut dispatch_table = Vec::with_capacity(20);
        // let device_handlers = Vec::with_capacity(6);
        // let epoll_fd = epoll::Epoll::new().map_err(Error::EpollFd)?;
        // epoll_fd.ctl(
        //     epoll::ControlOperation::Add,
        //     exit_evt_raw_fd,
        //     epoll::EpollEvent::new(
        //         epoll::EventSet::IN,
        //         dispatch_table.len() as u64,
        //     ),
        // ).map_err(Error::EpollFd)?;
        // dispatch_table.push(EpollDispatch::Exit);
        //
        // epoll_fd.ctl(
        //     epoll::ControlOperation::Add,
        //     libc::STDIN_FILENO, // TODO
        //     epoll::EpollEvent::new(
        //         epoll::EventSet::IN,
        //         dispatch_table.len() as u64,
        //     ),
        // ).map_err(Error::EpollFd)?;
        // dispatch_table.push(EpollDispatch::Stdin);
        //
        // let epoll_raw_fd = epoll_fd.as_raw_fd();
        Ok(EpollContext {
            epoll_raw_fd,
            dispatch_table,
            device_handlers,
        })
    }

    fn allocate_tokens(&mut self, count: usize) -> (u64, Sender<Box<dyn EpollHandler>>) {
        let dispatch_base = self.dispatch_table.len() as u64;
        let device_idx = self.device_handlers.len();
        let (sender, receiver) = channel();

        for x in 0..count - 1 {
            self.dispatch_table.push(EpollDispatch::DeviceHandler(device_idx, x as DeviceEventT));
        }
        self.device_handlers.push(MaybeHandler::new(receiver));
        (dispatch_base, sender)
    }

    pub fn allocate_virtio_blk_token(&mut self) -> virtio::block::EpollConfig {
        let (dispatch_base, sender) = self.allocate_tokens(2);
        virtio::block::EpollConfig::new(dispatch_base, self.epoll_raw_fd, sender)
    }

    pub fn allocate_virtio_net_tokens(&mut self) -> virtio::net::EpollConfig {
        let (dispatch_base, sender) = self.allocate_tokens(4);
        virtio::net::EpollConfig::new(dispatch_base, self.epoll_raw_fd, sender)
    }

    pub fn get_device_handler(&mut self, device_idx: usize) -> &mut dyn EpollHandler {
        let ref mut maybe = self.device_handlers[device_idx];
        match maybe.handler {
            Some(ref mut v) => v.as_mut(),
            None => {
                // This should only be called in response to an epoll trigger, and the channel
                // should always contain a message after the events were added to epoll
                // by the activate() call
                maybe
                    .handler
                    .get_or_insert(maybe.receiver.try_recv().unwrap())
                    .as_mut()
            }
        }
    }
}


impl Drop for EpollContext {
    fn drop(&mut self) {
        let rc = unsafe { libc::close(self.epoll_raw_fd) };
        if rc != 0 {
            println!("warn: cannot close epoll");
        }
    }
}
