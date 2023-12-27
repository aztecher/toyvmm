// Copyright 2023 aztecher, or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod serial;

use std::io;
use std::ops::Deref;
use utils::eventfd::EventFd;
use vm_superio::Trigger;

pub struct EventFdTrigger(EventFd);

impl Trigger for EventFdTrigger {
    type E = io::Error;

    fn trigger(&self) -> io::Result<()> {
        self.write(1)
    }
}

impl Deref for EventFdTrigger {
    type Target = EventFd;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl EventFdTrigger {
    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(EventFdTrigger((**self).try_clone()?))
    }

    pub fn new(evt: EventFd) -> Self {
        Self(evt)
    }

    pub fn get_event(&self) -> EventFd {
        self.0.try_clone().unwrap()
    }
}
