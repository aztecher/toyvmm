// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

pub mod gdt;
pub mod interrupt;
pub mod layout;
pub mod mptable;
pub mod msr;
pub mod msr_index;
pub mod regs;

use crate::{builder::InitrdConfig, vstate::memory};
use linux_loader::{
    configurator::{linux::LinuxBootConfigurator, BootConfigurator, BootParams},
    loader::bootparam::boot_params,
};
use vm_memory::{Address, GuestAddress, GuestMemory, GuestMemoryRegion};

pub use interrupt::{set_lint, InterruptError};
pub use msr::{setup_msrs, MsrError};
pub use regs::{setup_cpuid, setup_fpu, setup_regs, setup_sregs, RegError};

pub const CMDLINE_START: u64 = 0x20000;
const HIGH_MEMORY_START: u64 = 0x0010_0000; // 1 MB

// Address for the TSS setup
pub const KVM_TSS_ADDRESS: u64 = 0xfffb_d000;
// The 'zero page', a.k.a linux kernel bootparam
const ZERO_PAGE_START: u64 = 0x7000;

const EBDA_START: u64 = 0x9fc00;
const E820_RAM: u32 = 1;
const FIRST_ADDR_PAST_32BITS: u64 = 1 << 32;
const MEM_32BIT_GAP_SIZE: u64 = 768 << 20;
pub const MMIO_MEM_START: u64 = FIRST_ADDR_PAST_32BITS - MEM_32BIT_GAP_SIZE;

pub const CMDLINE_MAX_SIZE: usize = 0x10000;

/// Errors associated with the architecture related operations.
#[derive(Debug, thiserror::Error)]
pub enum ArchError {
    /// Initrd address is not found in configured guest memory.
    #[error("Initrd address is not found in configured guest memory.")]
    InitrdAddress,
    /// Zero page setup error.
    #[error("Zero page setup error: {0}")]
    ZeroPageSetup(#[from] linux_loader::configurator::Error),
    /// E820 table setup failure becauuse of the out-of-bounds.
    #[error("E820 table setup failure because of the out-of-bounds.")]
    E820Configuration,
    /// Error writing MP table to memory.
    #[error("MP table setup failure: {0}")]
    MpTableSetup(#[from] mptable::MptableError),
}

pub const PAGE_SIZE: usize = 4096;

pub fn initrd_load_addr(
    guest_mem: &memory::GuestMemoryMmap,
    initrd_size: usize,
) -> Result<u64, ArchError> {
    // Find first region from guest address
    let first_region = guest_mem
        .find_region(GuestAddress::new(0))
        .ok_or(ArchError::InitrdAddress)?;
    // Get first region length
    let lowmem_size = first_region.len() as usize;
    // Check if initrd size is lower than first region
    if lowmem_size < initrd_size {
        return Err(ArchError::InitrdAddress);
    }
    // bit operation to align to pagesize
    // intuitively, we can get bellow converter
    //   - 0 ~ (PAGE_SIZE - 1)                       -> 0
    //   - (PAGE_SIZE - 1) ~ (PAGE_SIZE * 2 - 1)     -> PAGE_SIZE
    //   - (PAGE_SIZE * 2 - 1) ~ (PAGE_SIZE * 3 - 1) -> PAGE_SIZE * 2
    //   ...
    //
    // to get above result, we operate bellow, all you have to do is
    // invert the bits of PAGE_SIZE and mask the target data.
    let align_to_pagesize = |address| address & !(PAGE_SIZE - 1);
    Ok(align_to_pagesize(lowmem_size - initrd_size) as u64)
}

pub fn arch_memory_regions(size: usize) -> Vec<(GuestAddress, usize)> {
    match size.checked_sub(MMIO_MEM_START as usize) {
        None | Some(0) => vec![(GuestAddress(0), size)],
        Some(remaining) => vec![
            (GuestAddress(0), MMIO_MEM_START as usize),
            (GuestAddress(FIRST_ADDR_PAST_32BITS), remaining),
        ],
    }
}

pub fn get_kernel_start() -> u64 {
    HIGH_MEMORY_START
}

pub fn configure_system(
    guest_mem: &memory::GuestMemoryMmap,
    cmdline_addr: GuestAddress,
    cmdline_size: usize,
    initrd: &Option<InitrdConfig>,
    num_cpus: u8,
) -> Result<(), ArchError> {
    // https://www.kernel.org/doc/html/latest/x86/boot.html
    const KERNEL_TYPE_OF_LOADER: u8 = 0xff;
    const KERNEL_BOOT_FLAG_MAGIC_NUMBER: u16 = 0xaa55;
    const KERNEL_HDR_MAGIC_NUMBER: u32 = 0x5372_6448;
    const KERNEL_MIN_ALIGNMENT_BYTES: u32 = 0x0100_0000;

    mptable::setup_mptable(guest_mem, num_cpus)?;

    let mut params = boot_params::default();
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
            himem_start.raw_value(),
            last_addr.unchecked_offset_from(himem_start) + 1,
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
    .map_err(ArchError::ZeroPageSetup)
}

fn add_e820_entry(
    params: &mut boot_params,
    addr: u64,
    size: u64,
    mem_type: u32,
) -> Result<(), ArchError> {
    if params.e820_entries >= params.e820_table.len() as u8 {
        return Err(ArchError::E820Configuration);
    }
    params.e820_table[params.e820_entries as usize].addr = addr;
    params.e820_table[params.e820_entries as usize].size = size;
    params.e820_table[params.e820_entries as usize].type_ = mem_type;
    params.e820_entries += 1;
    Ok(())
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::vstate::memory;
    use linux_loader::loader::bootparam::boot_e820_entry;

    #[test]
    fn test_align_to_pagesize() {
        let pagesize = 4096;
        let align_to_pagesize = |addr| addr & !(pagesize - 1);
        assert_eq!(0, align_to_pagesize(0) as u64);
        assert_eq!(0, align_to_pagesize(pagesize - 1) as u64);
        assert_eq!(pagesize, align_to_pagesize(pagesize) as u64);
        assert_eq!(pagesize, align_to_pagesize(pagesize * 2 - 1) as u64);
        assert_eq!(pagesize * 2, align_to_pagesize(pagesize * 2) as u64);
        assert_eq!(pagesize * 2, align_to_pagesize(pagesize * 3 - 1) as u64);
    }

    #[test]
    fn regions_lt_4gb() {
        let regions = arch_memory_regions(1 << 29);
        assert_eq!(1, regions.len());
        assert_eq!(vm_memory::GuestAddress(0), regions[0].0);
        assert_eq!(1 << 29, regions[0].1);
    }

    #[test]
    fn regions_gt_4gb() {
        let regions = arch_memory_regions((1 << 32) + 0x8000);
        assert_eq!(2, regions.len());
        assert_eq!(vm_memory::GuestAddress(0), regions[0].0);
        assert_eq!(GuestAddress(1 << 32), regions[1].0);
    }

    #[test]
    fn test_system_configuration_should_panic() {
        let gm = memory::create_guest_memory(&[(None, GuestAddress(0), 128 << 20)], false).unwrap();
        let res = configure_system(&gm, GuestAddress(0), 0, &None, 1);
        assert!(res.is_ok());
    }

    #[test]
    fn test_add_e820_entry() {
        let e820_map = [(boot_e820_entry {
            addr: 0x1,
            size: 4,
            type_: 1,
        }); 128];
        let expected_params = boot_params {
            e820_table: e820_map,
            e820_entries: 1,
            ..Default::default()
        };
        let mut params: boot_params = Default::default();
        add_e820_entry(
            &mut params,
            e820_map[0].addr,
            e820_map[1].size,
            e820_map[2].type_,
        )
        .unwrap();
        assert_eq!(
            format!("{:?}", params.e820_table[0]),
            format!("{:?}", expected_params.e820_table[0]),
        );
        assert_eq!(params.e820_entries, expected_params.e820_entries);

        params.e820_entries = params.e820_table.len() as u8 + 1;
        assert!(add_e820_entry(
            &mut params,
            e820_map[0].addr,
            e820_map[0].size,
            e820_map[0].type_,
        )
        .is_err());
    }
}
