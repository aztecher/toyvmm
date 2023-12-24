// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use crate::utils::byte_order;
use kvm_bindings::kvm_lapic_state;
use kvm_ioctls::VcpuFd;

#[derive(Debug, thiserror::Error)]
pub enum InterruptError {
    /// Get lapic error.
    #[error("Get lapic error: {0}")]
    GetLapic(#[source] kvm_ioctls::Error),
    /// Set lapic error.
    #[error("Set lapic error: {0}")]
    SetLapic(#[source] kvm_ioctls::Error),
}

// Defines poached from apicdef.h kernel header
const APIC_LVT0: usize = 0x350;
const APIC_LVT1: usize = 0x360;
const APIC_MODE_NMI: u32 = 0x4;
const APIC_MODE_EXTINT: u32 = 0x7;

fn get_klapic_reg(klapic: &kvm_lapic_state, reg_offset: usize) -> u32 {
    let range = reg_offset..reg_offset + 4; // 0x350..0x354, 4byte = 32bit
    let reg = klapic.regs.get(range).expect("get_klapic_reg range");
    byte_order::read_le_i32(reg) as u32
}

fn set_klapic_reg(klapic: &mut kvm_lapic_state, reg_offset: usize, value: u32) {
    let range = reg_offset..reg_offset + 4;
    let reg = klapic.regs.get_mut(range).expect("set_klapic_reg range");
    byte_order::write_le_i32(reg, value as i32)
}

fn set_apic_delivery_mode(reg: u32, mode: u32) -> u32 {
    // !0x700 = 0b1000_1111_1111
    // (AND)    0bRRRR_RRRR_RRRR (reg)
    // --------------------------
    //          0bR000_RRRR_RRRR
    // (OR)     0b0MMM_0000_0000 (mode)
    // --------------------------
    //        = 0bRMMM_RRRR_RRRR (Write mode bits to 8~11 bit)
    ((reg) & !0x700) | ((mode) << 8)
}

// Configure LAPICs. LAPIC0 set for external interrupts. LAPIC1 is set for NMI
pub fn set_lint(vcpu: &VcpuFd) -> Result<(), InterruptError> {
    let mut klapic = vcpu.get_lapic().map_err(InterruptError::GetLapic)?;
    let lvt_lint0 = get_klapic_reg(&klapic, APIC_LVT0);
    set_klapic_reg(
        &mut klapic,
        APIC_LVT0,
        set_apic_delivery_mode(lvt_lint0, APIC_MODE_EXTINT),
    );
    let lvt_lint1 = get_klapic_reg(&klapic, APIC_LVT1);
    set_klapic_reg(
        &mut klapic,
        APIC_LVT1,
        set_apic_delivery_mode(lvt_lint1, APIC_MODE_NMI),
    );
    vcpu.set_lapic(&klapic).map_err(InterruptError::SetLapic)
}
