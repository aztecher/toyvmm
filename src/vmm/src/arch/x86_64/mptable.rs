// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use crate::arch::x86_64::layout::IRQ_MAX;
use crate::arch_gen::x86::mpspec;
use crate::vstate::memory;
use std::{io, mem};
use vm_memory::{Address, ByteValued, Bytes, GuestAddress, GuestMemory};

// These `mpspec` wrapper types are only data, reading them from data is a safe initialization.
// SAFETY: POD
unsafe impl ByteValued for mpspec::mpc_bus {}
// SAFETY: POD
unsafe impl ByteValued for mpspec::mpc_cpu {}
// SAFETY: POD
unsafe impl ByteValued for mpspec::mpc_intsrc {}
// SAFETY: POD
unsafe impl ByteValued for mpspec::mpc_ioapic {}
// SAFETY: POD
unsafe impl ByteValued for mpspec::mpc_table {}
// SAFETY: POD
unsafe impl ByteValued for mpspec::mpc_lintsrc {}
// SAFETY: POD
unsafe impl ByteValued for mpspec::mpf_intel {}

#[allow(non_camel_case_types)]
pub type c_char = i8;

macro_rules! char_array {
    ($t:ty; $( $c:expr ),*) => ( [ $( $c as $t ),* ] )
}

// With APIC/xAPIC, there are only 255 APIC IDs available.
// And IOAPIC occupies one APIC ID, so only 254 CPUs at maximum may be supported.
// Actually it's a large number for ToyVMM usecases.
const MAX_SUPPORTED_CPUS: u32 = 254;

// MP table
const MPTABLE_START: u64 = 0x9fc00;
const SMP_MAGIC_IDENT: [c_char; 4] = char_array!(c_char; '_', 'M', 'P', '_');
const MPC_SIGNATURE: [c_char; 4] = char_array!(c_char; 'P', 'C', 'M', 'P');
const MPC_SPEC: i8 = 4;
const MPC_OEM: [c_char; 8] = char_array!(c_char; 'T', 'O', 'Y', 'V', 'M', 'M', ' ', ' ');
const MPC_PRODUCT_ID: [c_char; 12] = ['0' as c_char; 12];
const CPU_STEPPING: u32 = 0x600;
const CPU_FEATURE_APIC: u32 = 0x200;
const CPU_FEATURE_FPU: u32 = 0x001;
const BUS_TYPE_ISA: [u8; 6] = char_array!(u8; 'I', 'S', 'A', ' ', ' ', ' ');
const IO_APIC_DEFAULT_PHYS_BASE: u32 = 0xfec0_0000;
const APIC_DEFAULT_PHYS_BASE: u32 = 0xfee0_0000;
const APIC_VERSION: u8 = 0x14;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum MptableError {
    #[error("There was too little guest memory to store the entier MP table.")]
    NotEnoughMemory,
    #[error("Failure while zeroing out the memory for the MP table.")]
    Clear,
    #[error("Number of CPUs exceeds the maximum supported CPUs.")]
    TooManyCpus,
    #[error("Number of IRQs exceeds the maximum supported IRQs.")]
    TooManyIrqs,
    #[error("The MP table has too little address space to be stored.")]
    AddressOverflow,
    #[error("Failure to write the MP floating pointer.")]
    WriteMpfIntel,
    #[error("Failure to write MP CPU entry.")]
    WriteMpcCpu,
    #[error("Failure to write MP ioapic entry.")]
    WriteMpcIoapic,
    #[error("Failure to write MP bus entry.")]
    WriteMpcBus,
    #[error("Failure to write MP interrupt source entry.")]
    WriteMpcIntsrc,
    #[error("Failure to write MP local interrupt source entry.")]
    WriteMpcLintsrc,
    #[error("Failure to write MP table header.")]
    WriteMpcTable,
}

fn compute_checksum<T: ByteValued>(v: &T) -> u8 {
    // Safe because we are only reading the bytes within the size of the `T` reference `v`.
    let v_slice =
        unsafe { std::slice::from_raw_parts(v as *const T as *const u8, mem::size_of::<T>()) };
    let mut checksum: u8 = 0;
    for i in v_slice.iter() {
        checksum = checksum.wrapping_add(*i);
    }
    checksum
}

fn mpf_intel_compute_checksum(v: &mpspec::mpf_intel) -> u8 {
    let checksum = compute_checksum(v).wrapping_sub(v.checksum);
    (!checksum).wrapping_add(1)
}

fn compute_mp_size(num_cpus: u8) -> usize {
    mem::size_of::<mpspec::mpf_intel>()
        + mem::size_of::<mpspec::mpc_table>()
        + mem::size_of::<mpspec::mpc_cpu>() * (num_cpus as usize)
        + mem::size_of::<mpspec::mpc_bus>()
        + mem::size_of::<mpspec::mpc_ioapic>()
        + mem::size_of::<mpspec::mpc_intsrc>() * (IRQ_MAX as usize + 1)
        + mem::size_of::<mpspec::mpc_lintsrc>() * 2
}

/// Perform setup of the MP tablel for the given `num_cpus`
pub fn setup_mptable(mem: &memory::GuestMemoryMmap, num_cpus: u8) -> Result<(), MptableError> {
    if u32::from(num_cpus) > MAX_SUPPORTED_CPUS {
        return Err(MptableError::TooManyCpus);
    }
    let mut base_mp = GuestAddress(MPTABLE_START);
    let mp_size = compute_mp_size(num_cpus);

    let mut checksum: u8 = 0;
    let ioapicid: u8 = num_cpus + 1;
    if let Some(end_mp) = base_mp.checked_add((mp_size - 1) as u64) {
        if !mem.address_in_range(end_mp) {
            return Err(MptableError::NotEnoughMemory);
        }
    } else {
        return Err(MptableError::AddressOverflow);
    }

    mem.read_from(base_mp, &mut io::repeat(0), mp_size)
        .map_err(|_| MptableError::Clear)?;

    // Setup mpf_intel struct and write it to the guest memory.
    {
        let size = mem::size_of::<mpspec::mpf_intel>() as u64;
        let mut mpf_intel = mpspec::mpf_intel {
            signature: SMP_MAGIC_IDENT,
            physptr: (base_mp.raw_value() + size) as u32,
            length: 1,
            specification: 4,
            ..mpspec::mpf_intel::default()
        };
        mpf_intel.checksum = mpf_intel_compute_checksum(&mpf_intel);
        mem.write_obj(mpf_intel, base_mp)
            .map_err(|_| MptableError::WriteMpfIntel)?;
        // Update base_mp to MPTABLE_START + size_of(mpf_intel)
        base_mp = base_mp.unchecked_add(size);
    }

    // We set the location of mpc_table here but we can't fill it out until we have the length
    // of the entire table later.
    let table_base = base_mp;
    // Update base_mp to MPTABLE_START + size_of(mpf_inte) + size_of(mpc_table)
    // Writing the mpc_table struct to the guest memory is done later.
    base_mp = base_mp.unchecked_add(mem::size_of::<mpspec::mpc_table>() as u64);
    {
        let size = mem::size_of::<mpspec::mpc_cpu>() as u64;
        for cpu_id in 0..num_cpus {
            let mpc_cpu = mpspec::mpc_cpu {
                type_: mpspec::MP_PROCESSOR as u8,
                apicid: cpu_id,
                apicver: APIC_VERSION,
                cpuflag: mpspec::CPU_ENABLED as u8
                    | if cpu_id == 0 {
                        mpspec::CPU_BOOTPROCESSOR as u8
                    } else {
                        0
                    },
                cpufeature: CPU_STEPPING,
                featureflag: CPU_FEATURE_APIC | CPU_FEATURE_FPU,
                ..Default::default()
            };
            mem.write_obj(mpc_cpu, base_mp)
                .map_err(|_| MptableError::WriteMpcCpu)?;
            // Update base_mp to
            //   MPTABLE_START + size_of(mpf_inte) + size_of(mpc_table) + size_of(mpc_cpu #i)
            base_mp = base_mp.unchecked_add(size);
            checksum = checksum.wrapping_add(compute_checksum(&mpc_cpu));
        }
    }
    // The base_mp is
    //   MPTABLE_START + size_of(mpf_intel) + size_of(mpc_table) + size_of(mpc_cpu) * num_cpus
    {
        let size = mem::size_of::<mpspec::mpc_bus>() as u64;
        let mpc_bus = mpspec::mpc_bus {
            type_: mpspec::MP_BUS as u8,
            busid: 0,
            bustype: BUS_TYPE_ISA,
        };
        mem.write_obj(mpc_bus, base_mp)
            .map_err(|_| MptableError::WriteMpcBus)?;
        // Update base_map to
        //   MPTABLE_START + size_of(mpf_intel) + size_of(mpc_table)
        //   size_of(mpc_cpu) * num_cpus + size_of(mpc_bus)
        base_mp = base_mp.unchecked_add(size);
        checksum = checksum.wrapping_add(compute_checksum(&mpc_bus));
    }
    {
        let size = mem::size_of::<mpspec::mpc_ioapic>() as u64;
        let mpc_ioapic = mpspec::mpc_ioapic {
            type_: mpspec::MP_IOAPIC as u8,
            apicid: ioapicid,
            apicver: APIC_VERSION,
            flags: mpspec::MPC_APIC_USABLE as u8,
            apicaddr: IO_APIC_DEFAULT_PHYS_BASE,
        };
        mem.write_obj(mpc_ioapic, base_mp)
            .map_err(|_| MptableError::WriteMpcIoapic)?;
        // Update base_map to
        //   MPTABLE_START + size_of(mpf_intel) + size_of(mpc_table)
        //   size_of(mpc_cpu) * num_cpus + size_of(mpc_bus) + size_of(mpc_ioapic)
        base_mp = base_mp.unchecked_add(size);
        checksum = checksum.wrapping_add(compute_checksum(&mpc_ioapic));
    }
    // Per kvm_setup_default_irq_routing() in kernel
    for i in 0..=u8::try_from(IRQ_MAX).map_err(|_| MptableError::TooManyIrqs)? {
        let size = mem::size_of::<mpspec::mpc_intsrc>() as u64;
        let mpc_intsrc = mpspec::mpc_intsrc {
            type_: mpspec::MP_INTSRC as u8,
            irqtype: mpspec::mp_irq_source_types_mp_INT as u8,
            irqflag: mpspec::MP_IRQPOL_DEFAULT as u16,
            srcbus: 0,
            srcbusirq: i,
            dstapic: ioapicid,
            dstirq: i,
        };
        mem.write_obj(mpc_intsrc, base_mp)
            .map_err(|_| MptableError::WriteMpcIntsrc)?;
        // Update base_map to
        //   MPTABLE_START + size_of(mpf_intel) + size_of(mpc_table)
        //   size_of(mpc_cpu) * num_cpus + size_of(mpc_bus) + size_of(mpc_ioapic)
        //   size_of(mpc_intsrc #i)
        base_mp = base_mp.unchecked_add(size);
        checksum = checksum.wrapping_add(compute_checksum(&mpc_intsrc));
    }
    // The base_mp is
    //   MPTABLE_START + size_of(mpf_intel) + size_of(mpc_table)
    //   size_of(mpc_cpu) * num_cpus + size_of(mpc_bus) + size_of(mpc_ioapic)
    //   size_of(mpc_intsrc) * num_cpus
    {
        let size = mem::size_of::<mpspec::mpc_lintsrc>() as u64;
        let mpc_lintsrc = mpspec::mpc_lintsrc {
            type_: mpspec::MP_LINTSRC as u8,
            irqtype: mpspec::mp_irq_source_types_mp_ExtINT as u8,
            irqflag: mpspec::MP_IRQPOL_DEFAULT as u16,
            srcbusid: 0,
            srcbusirq: 0,
            destapic: 0,
            destapiclint: 0,
        };
        mem.write_obj(mpc_lintsrc, base_mp)
            .map_err(|_| MptableError::WriteMpcLintsrc)?;
        // Update base_mp to
        //   MPTABLE_START + size_of(mpf_intel) + size_of(mpc_table)
        //   size_of(mpc_cpu) * num_cpus + size_of(mpc_bus) + size_of(mpc_ioapic)
        //   size_of(mpc_intsrc) * num_cpus + size_of(mpc_lintsrc)
        base_mp = base_mp.unchecked_add(size);
        checksum = checksum.wrapping_add(compute_checksum(&mpc_lintsrc));
    }
    {
        let size = mem::size_of::<mpspec::mpc_lintsrc>() as u64;
        let mpc_lintsrc = mpspec::mpc_lintsrc {
            type_: mpspec::MP_LINTSRC as u8,
            irqtype: mpspec::mp_irq_source_types_mp_NMI as u8,
            irqflag: mpspec::MP_IRQPOL_DEFAULT as u16,
            srcbusid: 0,
            srcbusirq: 0,
            destapic: 0xFF,
            destapiclint: 1,
        };
        mem.write_obj(mpc_lintsrc, base_mp)
            .map_err(|_| MptableError::WriteMpcLintsrc)?;
        base_mp = base_mp.unchecked_add(size);
        checksum = checksum.wrapping_add(compute_checksum(&mpc_lintsrc));
    }
    // The base_mp is
    //   MPTABLE_START + size_of(mpf_intel) + size_of(mpc_table)
    //   size_of(mpc_cpu) * num_cpus + size_of(mpc_bus) + size_of(mpc_ioapic)
    //   size_of(mpc_intsrc) * num_cpus + size_of(mpc_lintsrc) * 2
    //
    // This is the entire size of mp_table.
    // Write the mpc_table to guest memory.
    let table_end = base_mp;
    {
        let mut mpc_table = mpspec::mpc_table {
            signature: MPC_SIGNATURE,
            // it's safe to use unchecked_offset_from because
            // table_end > table_base
            length: table_end.unchecked_offset_from(table_base) as u16,
            spec: MPC_SPEC,
            oem: MPC_OEM,
            productid: MPC_PRODUCT_ID,
            lapic: APIC_DEFAULT_PHYS_BASE,
            ..Default::default()
        };
        checksum = checksum.wrapping_add(compute_checksum(&mpc_table));
        mpc_table.checksum = (!checksum).wrapping_add(1) as i8;
        mem.write_obj(mpc_table, table_base)
            .map_err(|_| MptableError::WriteMpcTable)?;
    }

    Ok(())
}
