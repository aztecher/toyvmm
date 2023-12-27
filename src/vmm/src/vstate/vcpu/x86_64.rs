// Copyright 2023 aztecher, or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use crate::{
    arch, cpu,
    vstate::{memory::GuestMemoryMmap, vm::Vm},
};
use kvm_ioctls::VcpuFd;
use vm_memory::{Address, GuestAddress};

#[derive(Debug, thiserror::Error)]
pub enum KvmVcpuError {
    /// Cannot open the vcpu file descriptor.
    #[error("Cannot open the vcpu file descriptor")]
    VcpuFd(kvm_ioctls::Error),
    /// Failed to get KVM cpu cpuid
    #[error("Failed to get KVM vcpu cpuid: {0}")]
    VcpuGetCpuid(kvm_ioctls::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum KvmVcpuConfigureError {
    /// Vcpu registers configuration error.
    #[error("Vcpu registers configuration error: {0}")]
    RegsConfiguration(arch::x86_64::RegError),
    /// Vcpu fpu register configuratione error.
    #[error("Vcpu fpu register configuration error: {0}")]
    FpuConfiguration(arch::x86_64::RegError),
    /// Vcpu interrupt configuration error.
    #[error("Vcpu interrupt configuration error: {0}")]
    InterruptConfiguration(arch::x86_64::InterruptError),
    /// Vcpu msr configuration error.
    #[error("Vcpu msr configuration error: {0}")]
    MsrsConfiguration(arch::x86_64::MsrError),
    /// Vcpu set error.
    #[error("Vcpu set error: {0}")]
    SetCpuid(#[from] utils::errno::Error),
    /// Failed to convert `Cpuid` to `kvm_bindings::CpuId`
    #[error("Failed to convert `Cpuid` to `kvm_bindings::CpuId`: {0}")]
    ConvertCpuidType(#[from] utils::fam::Error),
    /// Failed to apply modification.
    #[error("Failed to apply modification to CPUID: {0}")]
    NormalizeCpuidError(#[from] cpu::NormalizeCpuidError),
}

/// A wrapper around creating and using a kvm x86_65 vcpu.
#[derive(Debug)]
pub struct KvmVcpu {
    /// Index of vcpu.
    pub index: u8,
    /// KVM vcpu id.
    pub fd: VcpuFd,
}

impl KvmVcpu {
    pub fn new(index: u8, vm: &Vm) -> Result<Self, KvmVcpuError> {
        /* vmfd.create_vcpu() : Create Vcpu fd using KVM
         * file descriptior : vmfd (from /dev/kvm)
         *
         * execute bellow instruction
         * > ioctl(fd, KVM_CREATE_VCPU, index)
         *   - index represents the vcpu id that is created
         *
         * Example:
         *   let kvm = Kvm::new().unwrap()
         *   let vm = kvm.create_vm().unwrap()
         *   // Create one vCPU with the ID=0
         *   let vcpu = vm.create_vcpu(0)
         */
        let kvm_vcpu = vm
            .fd()
            .create_vcpu(index.into())
            .map_err(KvmVcpuError::VcpuFd)?;
        Ok(KvmVcpu {
            index,
            fd: kvm_vcpu,
        })
    }

    pub fn configure(
        &mut self,
        guest_memory: &GuestMemoryMmap,
        kernel_start_addr: GuestAddress,
        cpuid: &mut cpu::Cpuid,
        num_cpus: u8,
    ) -> Result<(), KvmVcpuConfigureError> {
        cpuid.normalize(self.index, num_cpus, u8::from(num_cpus > 1))?;
        let kvm_cpuid = kvm_bindings::CpuId::try_from(cpuid.clone())?;
        self.fd
            .set_cpuid2(&kvm_cpuid)
            .map_err(KvmVcpuConfigureError::SetCpuid)?;
        arch::x86_64::setup_msrs(&self.fd).map_err(KvmVcpuConfigureError::MsrsConfiguration)?;
        arch::x86_64::setup_fpu(&self.fd).map_err(KvmVcpuConfigureError::FpuConfiguration)?;
        arch::x86_64::setup_regs(&self.fd, kernel_start_addr.raw_value())
            .map_err(KvmVcpuConfigureError::RegsConfiguration)?;
        arch::x86_64::setup_sregs(&self.fd, guest_memory)
            .map_err(KvmVcpuConfigureError::RegsConfiguration)?;
        arch::x86_64::set_lint(&self.fd).map_err(KvmVcpuConfigureError::InterruptConfiguration)?;
        Ok(())
    }

    pub fn get_cpuid(&self) -> Result<kvm_bindings::CpuId, KvmVcpuError> {
        let mut cpuid = self
            .fd
            .get_cpuid2(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
            .map_err(KvmVcpuError::VcpuGetCpuid)?;
        cpuid.retain(|entry| {
            !(entry.function == 0 && entry.index == 0 && entry.flags == 0 && entry.eax == 0)
        });
        Ok(cpuid)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::vstate::memory;

    #[test]
    fn test_kvm_vcpu_configure() {
        {
            let mut vm = Vm::new().unwrap();
            let gm =
                memory::create_guest_memory(&[(None, GuestAddress(0), 0x1000)], false).unwrap();
            vm.memory_init(&gm, false).unwrap();
            vm.setup_irqchip().unwrap();
            let mut kvm_vcpu = KvmVcpu::new(0, &vm).unwrap();
            let kvm_cpuid = vm.supported_cpuid().clone();
            let mut cpuid = cpu::Cpuid::try_from(kvm_cpuid).unwrap();
            assert!(kvm_vcpu
                .configure(&gm, GuestAddress(0), &mut cpuid, 1)
                .is_err());
        }

        {
            let mut vm = Vm::new().unwrap();
            let gm =
                memory::create_guest_memory(&[(None, GuestAddress(0), 128 << 20)], false).unwrap();
            vm.memory_init(&gm, false).unwrap();
            vm.setup_irqchip().unwrap();
            let mut kvm_vcpu = KvmVcpu::new(0, &vm).unwrap();
            let kvm_cpuid = vm.supported_cpuid().clone();
            let mut cpuid = cpu::Cpuid::try_from(kvm_cpuid).unwrap();
            assert!(kvm_vcpu
                .configure(&gm, GuestAddress(0), &mut cpuid, 1)
                .is_ok());
        }
    }
}
