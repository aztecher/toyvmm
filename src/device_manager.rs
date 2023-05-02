// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::{Arc, Mutex};
use crate::devices::{
    bus::Bus,
    virtio::{
        virtio_device::VirtioDevice,
        mmio::{MmioTransport, NOTIFY_REG_OFFSET},
    },
};
use kvm_ioctls::IoEventAddress;
use linux_loader::cmdline;
use crate::kvm::memory::GuestMemoryMmap;
use crate::vm_control::VmRequest;

#[derive(Debug)]
pub enum Error {
    /// Could not create the mmio transport to wrap a VirtioDevice.
    CreateMmioTransport(vmm_sys_util::errno::Error),
    /// Failed to clone a queue's ioeventfd.
    CloneIoeventFd(std::io::Error), // TODO std::io::Error to vmm_sys_util::errno::Error
    /// Failed to clone the mmio irqfd.
    CloneIrqFd(std::io::Error), // TODO std::io::Error to vmm_sys_util::errno::Error
    /// Appending to kernel command line failed.
    Cmdline(cmdline::Error),
    /// No more IRQs are available.
    IrqsExausted,
}

type Result<T> = std::result::Result<T, Error>;

const MAX_IRQ: u32 = 15;

pub struct DeviceManager {
    pub bus: Bus,
    pub vm_requests: Vec<VmRequest>,
    guest_mem: GuestMemoryMmap,
    mmio_len: u64,
    mmio_base: u64,
    irq: u32,
}

impl DeviceManager {
    pub fn new(
        guest_mem: GuestMemoryMmap,
        mmio_len: u64,
        mmio_base: u64,
        irq_base: u32,
    ) -> DeviceManager {
        DeviceManager {
            bus: Bus::new(),
            vm_requests: Vec::new(),
            guest_mem,
            mmio_len,
            mmio_base,
            irq: irq_base,
        }
    }

    pub fn register_mmio(
        &mut self,
        device: Box<dyn VirtioDevice>,
        cmdline: &mut cmdline::Cmdline,
    ) -> Result<()> {
        if self.irq > MAX_IRQ {
            return Err(Error::IrqsExausted);
        }
        let mmio_device = MmioTransport::new(self.guest_mem.clone(), device).map_err(Error::CreateMmioTransport)?;
        for (i, queue_evt) in mmio_device.queue_evts().iter().enumerate() {
            let io_addr = IoEventAddress::Mmio(self.mmio_base + NOTIFY_REG_OFFSET as u64);
            self.vm_requests.push(VmRequest::RegisterIoevent(
                    queue_evt.try_clone().map_err(Error::CloneIoeventFd)?,
                    io_addr,
                    i as u32,
            ));
        }
        if let Some(interrupt_evt) = mmio_device.interrupt_evt() {
            self.vm_requests.push(VmRequest::RegisterIrqfd(
                interrupt_evt.try_clone().map_err(Error::CloneIrqFd)?,
                self.irq,
            ));
        }

        // bus insertion (other bus?)
        self.bus.insert(
            Arc::new(Mutex::new(mmio_device)),
            self.mmio_base,
            self.mmio_len,
        ).unwrap();

        cmdline.insert(
            "virtio_mmio.device",
            &format!("4K@0x{:08x}:{}", self.mmio_base, self.irq),
            )
            .map_err(Error::Cmdline)?;
        self.mmio_base += self.mmio_len;
        self.irq += 1;

        Ok(())
    }
}
