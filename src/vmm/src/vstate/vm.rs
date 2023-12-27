// Copyright 2023 aztecher, or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use crate::{arch, vstate::memory::GuestMemoryMmap};
use kvm_bindings::{
    kvm_pit_config, kvm_userspace_memory_region, CpuId, KVM_MAX_CPUID_ENTRIES,
    KVM_MEM_LOG_DIRTY_PAGES, KVM_PIT_SPEAKER_DUMMY,
};
use kvm_ioctls::{Kvm, VmFd};
#[allow(unused_imports)]
use std::{
    os::unix::io::{AsRawFd, FromRawFd, RawFd},
    result,
};
use vm_memory::{Address, GuestMemory, GuestMemoryRegion};

#[derive(Debug, thiserror::Error)]
pub enum VmError {
    /// Cannot initialize the KVM context.
    #[error("{}", ({
        if .0.errno() == libc::EACCES {
            format!(
                "Error creating KVM object [{}]\nMake sure the user \
                launching the toyvmm process is configured on the /dev/kvm file's ACL.",
                .0
            )
        } else {
            format!("Error creating KVM object. [{}]", .0)
        }
    }))]
    Kvm(#[source] kvm_ioctls::Error),
    /// Cannot open the VM file descriptor.
    #[error("Cannot open the VM file descriptor: {0}")]
    VmFd(#[source] kvm_ioctls::Error),
    /// The number of configured slots is bigger than maximum reported by KVM.
    #[error("the number of configured slots is bigger than maximum reported by KVM")]
    NotEnoughMemorySlots,
    /// Cannot configure the VM.
    #[error("Cannot configure the VM: {0}")]
    VmSetup(#[source] kvm_ioctls::Error),
    // // KVM Errors
    // // Failed to open fd from /dev/kvm
    // VmFd(kvm_ioctls::Error),
    // // Failed to get mmap size
    // VcpuMmapSize(kvm_ioctls::Error),
    /// Cannot set memory region.
    #[error("Cannot set memory resion: {0}")]
    SetUserMemoryRegion(kvm_ioctls::Error),
}

pub struct Vm {
    fd: VmFd,
    max_memslots: usize,

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    supported_cpuid: CpuId,
}

impl Vm {
    pub fn new() -> Result<Self, VmError> {
        let kvm = Kvm::new().map_err(VmError::Kvm)?;
        let max_memslots = kvm.get_nr_memslots();
        /* kvm.create_vm() : create VM fd using KVM of type 0
         * file descriptor : kvm_ioctls::Kvm::kvm.as_raw_fd()
         *   - kvm_ioctls::Kvm::kvm has type std::fs::File
         *
         * execute bellow instruction
         * > ioctl(fd, KVM_CREATE_VM, 0)
         *
         * Example:
         *   let kvm = Kvm::new().unwrap();
         *   let vm = kvm.create_vm() (= kvm.create_vm_with_type(0))
         *
         *   - Kvm::new() open the /dev/kvm file descriptor
         *                and wrap it into Kvm struct
         *
         * file descriptor is automatically closed when dropping.
         */
        let vm_fd = kvm.create_vm().map_err(VmError::VmFd)?;

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            let supported_cpuid = kvm
                .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)
                .map_err(VmError::VmFd)?;
            Ok(Vm {
                fd: vm_fd,
                max_memslots,
                supported_cpuid,
            })
        }
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn supported_cpuid(&self) -> &CpuId {
        &self.supported_cpuid
    }

    #[cfg(target_arch = "x86_64")]
    pub fn setup_irqchip(&self) -> Result<(), VmError> {
        self.fd.create_irq_chip().map_err(VmError::VmSetup)?;
        let pit_config = kvm_pit_config {
            flags: KVM_PIT_SPEAKER_DUMMY,
            ..Default::default()
        };
        self.fd.create_pit2(pit_config).map_err(VmError::VmSetup)
    }

    pub fn set_kvm_memory_regions(
        &self,
        guest_mem: &GuestMemoryMmap,
        track_dirty_pages: bool,
    ) -> Result<(), VmError> {
        /* vmfd.set_user_memory_region() : create/modify guest physical memory slot
         * file descriptior : vmfd
         *
         * execute bellow instrurction
         * > ioctl(vmfd, KVM_SET_USER_MEMORY_REGION(), &use_memory_region)
         *   where
         *     (Example)
         *     let use_memory_region = kvm_userspace_memory_region {
         *         slot: 0,
         *         guest_phys_addr: 0x10000 as u64,
         *         memory_size: 0x10000 as u64,
         *         userspace_addr: 0x0 as u64,
         *         flags: 0,
         *     }
         *
         * Example:
         *   let kvm = Kvm::new().unwrap();
         *   let vm = kvm.create_vm()
         *   let mem_region = kvm_userspace_memory_region {
         *     slot: 0,
         *     guest_phys_addr: 0x10000 as u64,
         *     memory_size: 0x10000 as u64,
         *     userspace_addr: 0x0 as u64,
         *     flags: 0,
         *   };
         *   unsafe {
         *     vm.set_user_memory_region(mem_region).unwrap();
         *   };
         */
        let mut flags = 0u32;
        if track_dirty_pages {
            flags |= KVM_MEM_LOG_DIRTY_PAGES;
        }
        guest_mem
            .iter()
            .enumerate()
            .try_for_each(|(index, region)| {
                let memory_region = kvm_userspace_memory_region {
                    slot: index as u32,
                    guest_phys_addr: region.start_addr().raw_value(),
                    memory_size: region.len(),
                    userspace_addr: guest_mem.get_host_address(region.start_addr()).unwrap() as u64,
                    flags,
                };
                unsafe { self.fd.set_user_memory_region(memory_region) }
            })
            .map_err(VmError::SetUserMemoryRegion)?;
        Ok(())
    }

    pub fn memory_init(
        &mut self,
        guest_mem: &GuestMemoryMmap,
        track_dirty_pages: bool,
    ) -> Result<(), VmError> {
        if guest_mem.num_regions() > self.max_memslots {
            return Err(VmError::NotEnoughMemorySlots);
        }
        self.set_kvm_memory_regions(guest_mem, track_dirty_pages)?;
        #[cfg(target_arch = "x86_64")]
        self.fd
            .set_tss_address(arch::x86_64::KVM_TSS_ADDRESS as usize)
            .map_err(VmError::VmSetup)?;
        Ok(())
    }

    pub fn fd(&self) -> &VmFd {
        &self.fd
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::vstate::memory;
    use vm_memory::GuestAddress;

    #[test]
    fn test_memory_init() {
        let mut vm = Vm::new().unwrap();
        let gm = memory::create_guest_memory(&[(None, GuestAddress(0), 0x1000)], false).unwrap();
        assert!(vm.memory_init(&gm, false).is_ok());
    }

    #[test]
    fn test_set_kvm_memory_regions() {
        let vm = Vm::new().unwrap();
        let gm = memory::create_guest_memory(&[(None, GuestAddress(0), 0x1000)], false).unwrap();
        assert!(vm.set_kvm_memory_regions(&gm, false).is_ok());

        let gm = memory::create_guest_memory(&[(None, GuestAddress(0), 0x10)], false).unwrap();
        let res = vm.set_kvm_memory_regions(&gm, false);
        assert_eq!(
            res.unwrap_err().to_string(),
            "Cannot set memory resion: Invalid argument (os error 22)",
        );
    }
}
