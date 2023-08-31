// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::{
    devices::{
        bus::{Bus, BusDevice},
        virtio::{
            mmio::{MmioTransport, NOTIFY_REG_OFFSET},
            virtio_device::VirtioDevice,
        },
    },
    vstate::{
        memory::GuestMemoryMmap,
        vm::Vm,
        vm_control::{VmRequest, VmResponse},
    },
};
use kvm_ioctls::IoEventAddress;
use linux_loader::cmdline;
use std::sync::{Arc, Mutex};

#[derive(Debug, thiserror::Error)]
pub enum MmioDeviceError {
    /// Could not create the mmio transport to wrap a VirtioDevice.
    #[error("Failed to create mmio transport: {0}")]
    CreateMmioTransport(utils::errno::Error),
    /// Failed to clone a queue's ioeventfd.
    #[error("Failed to clone ioeventfd: {0}")]
    CloneIoeventFd(std::io::Error),
    /// Failed to clone the mmio irqfd.
    #[error("Failed to clone irqfd: {0}")]
    CloneIrqFd(std::io::Error),
    /// Register irqfd or ioevnetfd error.
    #[error("Register irqfd or ioeventfd error: {0}")]
    RegisterNotifier(utils::errno::Error),
    /// Appending to kernel command line failed.
    #[error("Failed to append kernel command line args: {0}")]
    Cmdline(cmdline::Error),
    /// No more IRQs are available.
    #[error("No more irqs are available")]
    IrqsExausted,
}

const MAX_IRQ: u32 = 15;

pub struct MmioDeviceManager {
    pub bus: Bus,
    pub vm_requests: Vec<VmRequest>,
    guest_mem: GuestMemoryMmap,
    mmio_len: u64,
    mmio_base: u64,
    irq: u32,
}

impl MmioDeviceManager {
    pub fn new(
        guest_mem: GuestMemoryMmap,
        mmio_len: u64,
        mmio_base: u64,
        irq_base: u32,
    ) -> MmioDeviceManager {
        MmioDeviceManager {
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
    ) -> Result<(), MmioDeviceError> {
        if self.irq > MAX_IRQ {
            return Err(MmioDeviceError::IrqsExausted);
        }
        let mmio_device = MmioTransport::new(self.guest_mem.clone(), device)
            .map_err(MmioDeviceError::CreateMmioTransport)?;
        for (i, queue_evt) in mmio_device.queue_evts().iter().enumerate() {
            let io_addr = IoEventAddress::Mmio(self.mmio_base + NOTIFY_REG_OFFSET as u64);
            self.vm_requests.push(VmRequest::RegisterIoevent(
                queue_evt
                    .try_clone()
                    .map_err(MmioDeviceError::CloneIoeventFd)?,
                io_addr,
                i as u32,
            ));
        }
        if let Some(interrupt_evt) = mmio_device.interrupt_evt() {
            self.vm_requests.push(VmRequest::RegisterIrqfd(
                interrupt_evt
                    .try_clone()
                    .map_err(MmioDeviceError::CloneIrqFd)?,
                self.irq,
            ));
        }

        // bus insertion (other bus?)
        self.bus
            .insert(
                Arc::new(Mutex::new(mmio_device)) as Arc<Mutex<dyn BusDevice>>,
                self.mmio_base,
                self.mmio_len,
            )
            .unwrap();

        cmdline
            .insert(
                "virtio_mmio.device",
                &format!("4K@0x{:08x}:{}", self.mmio_base, self.irq),
            )
            .map_err(MmioDeviceError::Cmdline)?;
        self.mmio_base += self.mmio_len;
        self.irq += 1;

        Ok(())
    }

    pub fn setup_event_notifier(&self, vm: &Vm) -> Result<(), MmioDeviceError> {
        for request in self.vm_requests.iter() {
            match request.execute(vm.fd()) {
                VmResponse::Ok => (),
                VmResponse::Err(e) => return Err(MmioDeviceError::RegisterNotifier(e)),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        builder::{setup_interrupt_controller, tests::cmdline_contains},
        devices::virtio::{
            queue::Queue,
            virtio_device::{ActivateError, VirtioDevice},
        },
        vstate::{memory, vm::Vm},
    };
    use ::utils::eventfd::EventFd;
    use vm_memory::GuestAddress;

    struct DummyDevice {
        dummy: u32,
    }

    impl DummyDevice {
        pub fn new() -> Self {
            DummyDevice { dummy: 0 }
        }
    }

    impl VirtioDevice for DummyDevice {
        fn device_type(&self) -> u32 {
            self.dummy
        }

        fn queue_max_sizes(&self) -> &[u16] {
            &[64]
        }

        fn activate(
            &mut self,
            _mem: GuestMemoryMmap,
            _interrupt_evt: EventFd,
            _status: Arc<std::sync::atomic::AtomicUsize>,
            _queues: Vec<Queue>,
            _queue_evt: Vec<EventFd>,
        ) -> Result<(), ActivateError> {
            Ok(())
        }
    }

    #[test]
    fn test_register_mmio_devices() {
        let gm = memory::create_guest_memory(&[(None, GuestAddress(0), 128 << 20)], false).unwrap();
        let mut vm = Vm::new().unwrap();
        vm.memory_init(&gm, false).unwrap();
        setup_interrupt_controller(&mut vm).unwrap();
        let mut dm = MmioDeviceManager::new(gm, 0x1000, 0, 5);
        let dummy = Box::new(DummyDevice::new());
        let mut cmdline = linux_loader::cmdline::Cmdline::new(4096).unwrap();
        assert!(dm.register_mmio(dummy, &mut cmdline).is_ok());
        assert!(cmdline_contains(
            &cmdline,
            "virtio_mmio.device=4K@0x00000000:5"
        ));
    }
}
