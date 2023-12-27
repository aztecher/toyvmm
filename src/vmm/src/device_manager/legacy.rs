// Copyright 2023 aztecher, or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::devices::{
    bus::{Bus, BusDevice, BusError},
    legacy::{
        serial::{SerialDevice, SerialEventsWrapper},
        EventFdTrigger,
    },
};
use kvm_ioctls::VmFd;
use std::sync::{Arc, Mutex};
use utils::eventfd::EventFd;
use vm_superio::Serial;

#[derive(Debug, thiserror::Error)]
pub enum LegacyDeviceError {
    /// Cannot create EventFd.
    #[error("Failed to create EventFd: {0}")]
    EventFd(#[from] std::io::Error),
    /// Cannot add legacy device to Bus.
    #[error("Failed to add legacy device to Bus: {0}")]
    BusError(#[from] BusError),
}

pub struct PortIoDeviceManager {
    pub io_bus: Bus,
    pub stdio_serial: Arc<Mutex<SerialDevice>>,
    pub com_evt_1_3: EventFdTrigger,
    pub com_evt_2_4: EventFdTrigger,
}

impl PortIoDeviceManager {
    /// x86 global system interrupt for communication events on serial ports 1 and 3.
    const COM_EVT_1_3_GSI: u32 = 4;
    /// x86 global system interrupt for communication events on serial ports 2 and 4.
    const COM_EVT_2_4_GSI: u32 = 3;
    /// Legacy serial port device addresses.
    const SERIAL_PORT_ADDRESSES: [u64; 4] = [0x3f8, 0x2f8, 0x3e8, 0x2e8];
    /// Size of legacy serial ports.
    const SERIAL_PORT_SIZE: u64 = 0x8;

    /// Create a new PortIoDeviceManager handling legacy devices.
    pub fn new(stdio_serial: Arc<Mutex<SerialDevice>>) -> Result<Self, LegacyDeviceError> {
        let io_bus = Bus::new();
        let com_evt_1_3 = stdio_serial
            .lock()
            .expect("Poisoned lock")
            .serial
            .interrupt_evt()
            .try_clone()?;
        let com_evt_2_4 = EventFdTrigger::new(EventFd::new(libc::EFD_NONBLOCK)?);
        Ok(PortIoDeviceManager {
            io_bus,
            stdio_serial,
            com_evt_1_3,
            com_evt_2_4,
        })
    }

    /// Register legacy devices.
    pub fn register_devices(&mut self, vm_fd: &VmFd) -> Result<(), LegacyDeviceError> {
        let serial_2_4 = Arc::new(Mutex::new(SerialDevice {
            serial: Serial::with_events(
                self.com_evt_2_4.try_clone()?,
                SerialEventsWrapper {
                    buffer_read_event_fd: None,
                },
                Box::new(std::io::sink()),
            ),
        }));
        let serial_1_3 = Arc::new(Mutex::new(SerialDevice {
            serial: Serial::with_events(
                self.com_evt_1_3.try_clone()?,
                SerialEventsWrapper {
                    buffer_read_event_fd: None,
                },
                Box::new(std::io::sink()),
            ),
        }));
        self.io_bus.insert(
            self.stdio_serial.clone() as Arc<Mutex<dyn BusDevice>>,
            Self::SERIAL_PORT_ADDRESSES[0],
            Self::SERIAL_PORT_SIZE,
        )?;
        self.io_bus.insert(
            serial_2_4.clone() as Arc<Mutex<dyn BusDevice>>,
            Self::SERIAL_PORT_ADDRESSES[1],
            Self::SERIAL_PORT_SIZE,
        )?;
        self.io_bus.insert(
            serial_1_3.clone() as Arc<Mutex<dyn BusDevice>>,
            Self::SERIAL_PORT_ADDRESSES[2],
            Self::SERIAL_PORT_SIZE,
        )?;
        self.io_bus.insert(
            serial_2_4 as Arc<Mutex<dyn BusDevice>>,
            Self::SERIAL_PORT_ADDRESSES[3],
            Self::SERIAL_PORT_SIZE,
        )?;
        vm_fd
            .register_irqfd(&self.com_evt_1_3, Self::COM_EVT_1_3_GSI)
            .map_err(|e| {
                LegacyDeviceError::EventFd(std::io::Error::from_raw_os_error(e.errno()))
            })?;
        vm_fd
            .register_irqfd(&self.com_evt_2_4, Self::COM_EVT_2_4_GSI)
            .map_err(|e| {
                LegacyDeviceError::EventFd(std::io::Error::from_raw_os_error(e.errno()))
            })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        builder::{setup_interrupt_controller, setup_stdio_serial_device},
        vstate::{memory, vm::Vm},
    };
    use vm_memory::GuestAddress;

    #[test]
    fn test_register_legacy_devices() {
        let gm = memory::create_guest_memory(&[(None, GuestAddress(0), 128 << 20)], false).unwrap();
        let mut vm = Vm::new().unwrap();
        vm.memory_init(&gm, false).unwrap();
        setup_interrupt_controller(&mut vm).unwrap();
        let mut dm = PortIoDeviceManager::new(setup_stdio_serial_device()).unwrap();
        assert!(dm.register_devices(vm.fd()).is_ok());
    }
}
