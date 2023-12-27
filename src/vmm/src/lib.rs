// Copyright 2023 aztecher, or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

pub mod arch;
pub mod arch_gen;
pub mod builder;
pub mod cpu;
pub mod device_manager;
pub mod devices;
pub mod resources;
pub mod utils;
pub mod vmm_config;
pub mod vstate;

/// これがないとなんかtuntapのioctl_iow_nrが効かなかった
#[macro_use]
extern crate vmm_sys_util;

/// これがないとbuilder.rsのdefer!が効かない
#[macro_use]
extern crate scopeguard;

use crate::vstate::{memory::GuestMemoryMmap, vm::Vm};

/// Errors associated with the VMM internal logic.
#[derive(Debug, thiserror::Error)]
pub enum VmmError {
    /// Vm error.
    #[error("Vm error: {0}")]
    Vm(vstate::vm::VmError),
    /// Event file descriptor error
    #[error("Event file descriptor error: {0}")]
    EventFd(std::io::Error),
    /// Vcpu configuration error.
    #[error("Error configuring the vcpu for boot: {0}")]
    VcpuConfigure(vstate::vcpu::VcpuError),
    /// Vcpu create error.
    #[error("Error creating the vcpu: {0}")]
    VcpuCreate(vstate::vcpu::VcpuError),
    /// Cannot add devices to the legacy I/O Bus.
    #[error("Cannot add devices to the legacy I/O bus. {0}")]
    LegacyIoBus(device_manager::legacy::LegacyDeviceError),
    /// Cannot add a device to the Mmio Bus.
    #[error("Cannot add a device to the mmio bus: {0}")]
    MmioBus(device_manager::mmio::MmioDeviceError),
    /// Failed to register notifier.
    #[error("Failed to register notifier: {0}")]
    MmioNotifier(device_manager::mmio::MmioDeviceError),
}

pub struct Vmm {
    vm: Vm,
    guest_memory: GuestMemoryMmap,
    mmio_device_manager: device_manager::mmio::MmioDeviceManager,
    pio_device_manager: device_manager::legacy::PortIoDeviceManager,
}
