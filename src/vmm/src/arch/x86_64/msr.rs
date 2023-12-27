// Copyright 2023 aztecher, or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use super::msr_index as msri;
use kvm_bindings::{kvm_msr_entry, Msrs};
use kvm_ioctls::VcpuFd;
use utils::fam;

#[derive(Debug, thiserror::Error)]
pub enum MsrError {
    /// FAM structure error.
    #[error("FAM structure error: {0}")]
    FamError(#[from] fam::Error),
    /// Model specific registers (MSR) setup error.
    #[error("Model specific register (MSR) setup error: {0}")]
    SetModelSpecificRegisters(#[from] kvm_ioctls::Error),
    /// Model specific registers count error.
    #[error("Model specific register (MSR) count error")]
    SetModelSpecificRegistersCount,
}

// Creates and populates required MSR entries for booting Linux on x86_64
fn create_boot_msr_entries() -> Vec<kvm_msr_entry> {
    let msr_entry_default = |msr| kvm_msr_entry {
        index: msr,
        data: 0x0,
        ..Default::default()
    };
    vec![
        msr_entry_default(msri::MSR_IA32_SYSENTER_CS),
        msr_entry_default(msri::MSR_IA32_SYSENTER_ESP),
        msr_entry_default(msri::MSR_IA32_SYSENTER_EIP),
        // x86_64 specific msrs
        msr_entry_default(msri::MSR_STAR),
        msr_entry_default(msri::MSR_CSTAR),
        msr_entry_default(msri::MSR_KERNEL_GS_BASE),
        msr_entry_default(msri::MSR_SYSCALL_MASK),
        msr_entry_default(msri::MSR_LSTAR),
        // end of x86_64 specific code
        msr_entry_default(msri::MSR_IA32_TSC),
        kvm_msr_entry {
            index: msri::MSR_IA32_MISC_ENABLE,
            data: u64::from(msri::MSR_IA32_MISC_ENABLE_FAST_STRING),
            ..Default::default()
        },
    ]
}

// Configure Model Specific Registers (MSRs)
pub fn setup_msrs(vcpu: &VcpuFd) -> Result<(), MsrError> {
    let entry_vec = create_boot_msr_entries();
    let msrs = Msrs::from_entries(&entry_vec).map_err(MsrError::FamError)?;
    vcpu.set_msrs(&msrs)
        .map_err(MsrError::SetModelSpecificRegisters)
        .and_then(|msrs_written| {
            if msrs_written as u32 != msrs.as_fam_struct_ref().nmsrs {
                Err(MsrError::SetModelSpecificRegistersCount)
            } else {
                Ok(())
            }
        })
}
