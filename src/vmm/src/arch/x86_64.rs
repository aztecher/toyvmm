// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use super::gdt;
use super::msr_index as msri;
use crate::{
    arch::Error as ArchError, builder::InitrdConfig, utils::byte_order,
    vstate::memory::GuestMemoryMmap,
};
use kvm_bindings::{kvm_fpu, kvm_lapic_state, kvm_msr_entry, kvm_regs, kvm_sregs, CpuId, Msrs};
use kvm_ioctls::VcpuFd;
use linux_loader::{
    configurator::{linux::LinuxBootConfigurator, BootConfigurator, BootParams},
    loader::bootparam::boot_params,
};
use std::mem;
use utils::fam;
use vm_memory::{Address, Bytes, GuestAddress, GuestMemory, GuestMemoryError};

pub const CMDLINE_START: u64 = 0x20000;
const HIGH_MEMORY_START: u64 = 0x0010_0000; // 1 MB

// Initial stack for the boot CPUs
const BOOT_STACK_POINTER: u64 = 0x8ff0;
// Address for the TSS setup
pub const KVM_TSS_ADDRESS: u64 = 0xfffb_d000;
// The 'zero page', a.k.a linux kernel bootparam
const ZERO_PAGE_START: u64 = 0x7000;

const BOOT_GDT_OFFSET: u64 = 0x500;
const BOOT_IDT_OFFSET: u64 = 0x520;
const BOOT_GDT_MAX: usize = 4;
const EFER_LMA: u64 = 0x400;
const EFER_LME: u64 = 0x100;
const X86_CR0_PE: u64 = 0x1;
const X86_CR0_PG: u64 = 0x8000_0000;
const X86_CR4_PAE: u64 = 0x20;

// Initial pagetable
const PML4_START: u64 = 0x9000;
const PDPTE_START: u64 = 0xa000;
const PDE_START: u64 = 0xb000;

// Defines poached from apicdef.h kernel header
const APIC_LVT0: usize = 0x350;
const APIC_LVT1: usize = 0x360;
const APIC_MODE_NMI: u32 = 0x4;
const APIC_MODE_EXTINT: u32 = 0x7;

const EBDA_START: u64 = 0x9fc00;
const E820_RAM: u32 = 1;
const FIRST_ADDR_PAST_32BITS: u64 = 1 << 32;
const MEM_32BIT_GAP_SIZE: u64 = 768 << 20;
pub const MMIO_MEM_START: u64 = FIRST_ADDR_PAST_32BITS - MEM_32BIT_GAP_SIZE;

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

#[derive(Debug, thiserror::Error)]
pub enum RegError {
    /// Get special registers error.
    #[error("Get special registers error: {0}")]
    GetSpecialRegisters(#[source] kvm_ioctls::Error),
    /// Set special registers error.
    #[error("Set special registers error: {0}")]
    SetSpecialRegisters(#[source] kvm_ioctls::Error),
    /// Set general purpose registers error.
    #[error("Set general purpose registers error: {0}")]
    SetBaseRegisters(#[source] kvm_ioctls::Error),
    /// Set floating-point unit registers error.
    #[error("Set floating-point unit registers error: {0}")]
    SetFpuRegisters(#[source] kvm_ioctls::Error),
    /// Invalid global descriptor table (GDT) address error
    #[error("Invalid global descriptor table (GDT) address error")]
    InvalidGdtAddress,
    /// Write global descriptor table (GDT) error.
    #[error("Write global descriptor table (GDT) error: {0}")]
    WriteGdt(#[source] GuestMemoryError),
    /// Write interrupt descriptor table (IDT) error.
    #[error("Write interrupt descriptor table (IDT) error: {0}")]
    WriteIdt(#[source] GuestMemoryError),
    /// Write page map level4 (PML4) error.
    #[error("Write page map level4 error: {0}")]
    WritePml4Address(#[source] GuestMemoryError),
    /// Write page directory pointer table entry error.
    #[error("Write page directory pointer table entry error: {0}")]
    WritePdpteAddress(#[source] GuestMemoryError),
    /// Write page directory entry error.
    #[error("Write page directory entry error: {0}")]
    WritePdeAddress(#[source] GuestMemoryError),
}

#[derive(Debug, thiserror::Error)]
pub enum InterruptError {
    /// Get lapic error.
    #[error("Get lapic error: {0}")]
    GetLapic(#[source] kvm_ioctls::Error),
    /// Set lapic error.
    #[error("Set lapic error: {0}")]
    SetLapic(#[source] kvm_ioctls::Error),
}

pub fn get_kernel_start() -> u64 {
    HIGH_MEMORY_START
}

fn filter_cpuid(cpuid: u64, num_cpus: u64, kvm_cpuid: &mut kvm_bindings::CpuId) {
    const VENDOR_EBX_VAL: u32 = 0x56594f54; // TOYVMMTOYVMM
    const VENDOR_ECX_VAL: u32 = 0x4d4d5659;
    const VENDOR_EDX_VAL: u32 = 0x4f544d4d;
    // CPUID bits in ebx, ecx, and edx.
    const EBX_CLFLUSH_CACHELINE: u32 = 8;
    const EBX_CLFLUSH_SIZE_SHIFT: u32 = 8;
    const EBX_CPU_COUNT_SHIFT: u32 = 16;
    const EBX_CPUID_SHIFT: u32 = 24;
    const ECX_EPB_SHIFT: u32 = 3;
    const ECX_HYPERVISOR_SHIFT: u32 = 31;
    const EDX_HTT_SHIFT: u32 = 28;
    let entries = kvm_cpuid.as_mut_slice();
    for entry in entries.iter_mut() {
        match entry.function {
            0 => {
                // Vendor name "CROSVMCROSVM"
                entry.ebx = VENDOR_EBX_VAL;
                entry.ecx = VENDOR_ECX_VAL;
                entry.edx = VENDOR_EDX_VAL;
            }
            1 => {
                // x86 hypervisor feature
                if entry.index == 0 {
                    entry.ecx |= 1 << ECX_HYPERVISOR_SHIFT;
                }
                entry.ebx = (cpuid << EBX_CPUID_SHIFT) as u32
                    | (EBX_CLFLUSH_CACHELINE << EBX_CLFLUSH_SIZE_SHIFT);
                if num_cpus > 1 {
                    entry.ebx |= (num_cpus as u32) << EBX_CPU_COUNT_SHIFT;
                    entry.edx |= 1 << EDX_HTT_SHIFT;
                }
            }
            6 => {
                // clear x86 ebp feature
                entry.ecx &= !(1 << ECX_EPB_SHIFT);
            }
            _ => (),
        }
    }
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

pub fn setup_cpuid(vcpu: &VcpuFd, id: u64, num_cpus: u64, cpuid: &mut CpuId) {
    filter_cpuid(id, num_cpus, cpuid);
    vcpu.set_cpuid2(cpuid).unwrap();
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

// Configure base registers
pub fn setup_regs(vcpu: &VcpuFd, boot_ip: u64) -> Result<(), RegError> {
    let regs: kvm_regs = kvm_regs {
        rflags: 0x0000_0000_0000_0002u64,
        rip: boot_ip,
        rsp: BOOT_STACK_POINTER as u64,
        rbp: BOOT_STACK_POINTER as u64,
        rsi: ZERO_PAGE_START as u64,
        ..Default::default()
    };

    vcpu.set_regs(&regs).map_err(RegError::SetBaseRegisters)
}

// Configure Floating-Point Unit (FPU) registers
pub fn setup_fpu(vcpu: &VcpuFd) -> Result<(), RegError> {
    let fpu: kvm_fpu = kvm_fpu {
        fcw: 0x37f,
        mxcsr: 0x1f80,
        ..Default::default()
    };
    vcpu.set_fpu(&fpu).map_err(RegError::SetFpuRegisters)
}

fn write_gdt_table(table: &[u64], guest_mem: &GuestMemoryMmap) -> Result<(), RegError> {
    let boot_gdt_addr = GuestAddress(BOOT_GDT_OFFSET);
    for (index, entry) in table.iter().enumerate() {
        let addr = guest_mem
            .checked_offset(boot_gdt_addr, index * mem::size_of::<u64>())
            .ok_or(RegError::InvalidGdtAddress)?;
        guest_mem
            .write_obj(*entry, addr)
            .map_err(RegError::WriteGdt)?;
    }
    Ok(())
}

fn write_idt_value(val: u64, guest_mem: &GuestMemoryMmap) -> Result<(), RegError> {
    let boot_idt_addr = GuestAddress(BOOT_IDT_OFFSET);
    guest_mem
        .write_obj(val, boot_idt_addr)
        .map_err(RegError::WriteIdt)
}

fn configure_segments_and_sregs(
    sregs: &mut kvm_sregs,
    mem: &GuestMemoryMmap,
) -> Result<(), RegError> {
    let gdt_table: [u64; BOOT_GDT_MAX as usize] = [
        gdt::gdt_entry(0, 0, 0),            // NULL
        gdt::gdt_entry(0xa09b, 0, 0xfffff), // CODE
        gdt::gdt_entry(0xc093, 0, 0xfffff), // DATA
        gdt::gdt_entry(0x808b, 0, 0xfffff), // TSS
    ];
    // > https://wiki.osdev.org/GDT_Tutorialを見ると値がちょっとおかしいかもしれねぇ
    //
    // > https://wiki.osdev.org/Global_Descriptor_Table
    //
    //              55 52     47     40 39        31               16 15                0
    // CODE: 0b0..._1010_1111_1001_1011_0000_0000_0000_0000_0000_0000_1111_1111_1111_1111
    //              <-f->     <-Access-><---------------------------> <----- limit ----->
    // - Flags  : 1010      => G(limit is in 4KiB), L(Long mode)
    // - Access : 1001_1011 => P(must 1), S(code/data type), E(executable), RW(readable/writable), A(CPU access allowed)
    //   - 0xa09b of A,9,B represents above values
    //
    // DATA: 0b0..._1100_1111_1001_0011_0000_0000_0000_0000_0000_0000_1111_1111_1111_1111
    // - Flags  : 1100      => G(limit is in 4KiB), DB(32-bit protected mode)
    // - Access : 1001_0011 => P(must 1), S(code/data type), RW(readable/writable), A(CPU access allowed)
    //
    // TSS
    // - Flags  : 1000      => G(limit is in 4KiB)
    // - Access : 1000_1011 => P(must 1), E(executable), RW(readable/writable), A(CPU access allowed)
    //    - TSS requires to support Intel VT
    let code_seg = gdt::kvm_segment_from_gdt(gdt_table[1], 1);
    let data_seg = gdt::kvm_segment_from_gdt(gdt_table[2], 2);
    let tss_seg = gdt::kvm_segment_from_gdt(gdt_table[3], 3);

    // Write seguments
    write_gdt_table(&gdt_table[..], mem)?;
    sregs.gdt.base = BOOT_GDT_OFFSET as u64;
    sregs.gdt.limit = mem::size_of_val(&gdt_table) as u16 - 1;

    write_idt_value(0, mem)?;
    sregs.idt.base = BOOT_IDT_OFFSET as u64;
    sregs.idt.limit = mem::size_of::<u64>() as u16 - 1;

    sregs.cs = code_seg;
    sregs.ds = data_seg;
    sregs.es = data_seg;
    sregs.fs = data_seg;
    sregs.gs = data_seg;
    sregs.ss = data_seg;
    sregs.tr = tss_seg;

    // 64-bit protected mode
    sregs.cr0 |= X86_CR0_PE;
    sregs.efer |= EFER_LME | EFER_LMA;
    Ok(())
}

fn setup_page_tables(sregs: &mut kvm_sregs, mem: &GuestMemoryMmap) -> Result<(), RegError> {
    let boot_pml4_addr = GuestAddress(PML4_START);
    let boot_pdpte_addr = GuestAddress(PDPTE_START);
    let boot_pde_addr = GuestAddress(PDE_START);

    // Entry converting VA [0..512GB)
    mem.write_obj(boot_pdpte_addr.raw_value() as u64 | 0x03, boot_pml4_addr)
        .map_err(RegError::WritePml4Address)?;
    // Entry covering VA [0..1GB)
    mem.write_obj(boot_pde_addr.raw_value() as u64 | 0x03, boot_pdpte_addr)
        .map_err(RegError::WritePdpteAddress)?;
    // 512 MB entries together covering VA [0..1GB).
    // Note we are assuming CPU support 2MB pages (/proc/cpuinfo has 'pse').
    for i in 0..512 {
        mem.write_obj((i << 21) + 0x83u64, boot_pde_addr.unchecked_add(i * 8))
            .map_err(RegError::WritePdeAddress)?;
    }
    sregs.cr3 = boot_pml4_addr.raw_value() as u64;
    sregs.cr4 |= X86_CR4_PAE;
    sregs.cr0 |= X86_CR0_PG;
    Ok(())
}

// Configure the segment registers and system page tables
pub fn setup_sregs(vcpu: &VcpuFd, mem: &GuestMemoryMmap) -> Result<(), RegError> {
    let mut sregs: kvm_sregs = vcpu.get_sregs().map_err(RegError::GetSpecialRegisters)?;

    configure_segments_and_sregs(&mut sregs, mem)?;
    setup_page_tables(&mut sregs, mem)?;

    vcpu.set_sregs(&sregs)
        .map_err(RegError::SetSpecialRegisters)
}

fn get_klapic_reg(klapic: &kvm_lapic_state, reg_offset: usize) -> u32 {
    let range = reg_offset..reg_offset + 4;
    let reg = klapic.regs.get(range).expect("get_klapic_reg range");
    byte_order::read_le_i32(reg) as u32
}

fn set_klapic_reg(klapic: &mut kvm_lapic_state, reg_offset: usize, value: u32) {
    let range = reg_offset..reg_offset + 4;
    let reg = klapic.regs.get_mut(range).expect("set_klapic_reg range");
    byte_order::write_le_i32(reg, value as i32)
}

fn set_apic_delivery_mode(reg: u32, mode: u32) -> u32 {
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

pub fn configure_system(
    guest_mem: &GuestMemoryMmap,
    cmdline_addr: GuestAddress,
    cmdline_size: usize,
    initrd: &Option<InitrdConfig>,
    _num_cpus: u8,
) -> Result<(), ArchError> {
    let mut params = boot_params::default();
    // https://www.kernel.org/doc/html/latest/x86/boot.html
    const KERNEL_TYPE_OF_LOADER: u8 = 0xff;
    const KERNEL_BOOT_FLAG_MAGIC_NUMBER: u16 = 0xaa55;
    const KERNEL_HDR_MAGIC_NUMBER: u32 = 0x5372_6448;
    const KERNEL_MIN_ALIGNMENT_BYTES: u32 = 0x0100_0000;

    params.hdr.type_of_loader = KERNEL_TYPE_OF_LOADER;
    params.hdr.boot_flag = KERNEL_BOOT_FLAG_MAGIC_NUMBER;
    params.hdr.header = KERNEL_HDR_MAGIC_NUMBER;
    params.hdr.cmd_line_ptr = cmdline_addr.raw_value() as u32;
    params.hdr.cmdline_size = cmdline_size as u32;
    params.hdr.kernel_alignment = KERNEL_MIN_ALIGNMENT_BYTES;
    if let Some(initrd_config) = initrd {
        params.hdr.ramdisk_image = initrd_config.address.raw_value() as u32;
        params.hdr.ramdisk_size = initrd_config.size as u32;
    }

    add_e820_entry(&mut params, 0, EBDA_START, E820_RAM)?;
    let first_addr_past_32bits = GuestAddress(FIRST_ADDR_PAST_32BITS);
    let end_32bit_gap_start = GuestAddress(MMIO_MEM_START);
    let himem_start = GuestAddress(HIGH_MEMORY_START);
    let last_addr = guest_mem.last_addr();
    if last_addr < end_32bit_gap_start {
        add_e820_entry(
            &mut params,
            himem_start.raw_value() as u64,
            last_addr.unchecked_offset_from(himem_start) as u64 + 1,
            E820_RAM,
        )?;
    } else {
        add_e820_entry(
            &mut params,
            himem_start.raw_value(),
            end_32bit_gap_start.unchecked_offset_from(himem_start),
            E820_RAM,
        )?;
        if last_addr > first_addr_past_32bits {
            add_e820_entry(
                &mut params,
                first_addr_past_32bits.raw_value(),
                last_addr.unchecked_offset_from(first_addr_past_32bits) + 1,
                E820_RAM,
            )?;
        }
    }

    LinuxBootConfigurator::write_bootparams(
        &BootParams::new(&params, GuestAddress(ZERO_PAGE_START)),
        guest_mem,
    )
    .map_err(|_| ArchError::ZeroPageSetup)
}

fn add_e820_entry(
    params: &mut boot_params,
    addr: u64,
    size: u64,
    mem_type: u32,
) -> super::Result<()> {
    if params.e820_entries >= params.e820_table.len() as u8 {
        return Err(ArchError::E820Configuration);
    }
    params.e820_table[params.e820_entries as usize].addr = addr;
    params.e820_table[params.e820_entries as usize].size = size;
    params.e820_table[params.e820_entries as usize].type_ = mem_type;
    params.e820_entries += 1;
    Ok(())
}
