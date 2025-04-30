// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright 2023 Rivos, Inc.
//
// SPDX-License-Identifier: Apache-2.0

use std::mem::size_of;

use vm_memory::{Address, Bytes, GuestAddress, GuestMemory};
use zerocopy::little_endian::U32;
use zerocopy::{Immutable, IntoBytes};

use super::{checksum, AcpiError, Result, Sdt, SdtHeader};

const MADT_CPU_ENABLE_FLAG: u32 = 0;

// clippy doesn't understand that we actually "use" the fields of this struct when we serialize
// them as bytes in guest memory, so here we just ignore dead code to avoid having to name
// everything with an underscore prefix
#[allow(dead_code)]
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default, IntoBytes, Immutable)]
pub struct LocalAPIC {
    r#type: u8,
    length: u8,
    processor_uid: u8,
    apic_id: u8,
    flags: U32,
}

impl LocalAPIC {
    pub fn new(cpu_id: u8) -> Self {
        Self {
            r#type: 0,
            length: 8,
            processor_uid: cpu_id,
            apic_id: cpu_id,
            flags: U32::new(1u32 << MADT_CPU_ENABLE_FLAG),
        }
    }
}

// clippy doesn't understand that we actually "use" the fields of this struct when we serialize
// them as bytes in guest memory, so here we just ignore dead code to avoid having to name
// everything with an underscore prefix
#[allow(dead_code)]
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default, IntoBytes, Immutable)]
pub struct IoAPIC {
    r#type: u8,
    length: u8,
    ioapic_id: u8,
    reserved: u8,
    apic_address: U32,
    gsi_base: U32,
}

impl IoAPIC {
    pub fn new(ioapic_id: u8, apic_address: u32) -> Self {
        IoAPIC {
            r#type: 1,
            length: 12,
            ioapic_id,
            reserved: 0,
            apic_address: U32::new(apic_address),
            gsi_base: U32::ZERO,
        }
    }
}

// clippy doesn't understand that we actually "use" the fields of this struct when we serialize
// them as bytes in guest memory, so here we just ignore dead code to avoid having to name
// everything with an underscore prefix
#[allow(dead_code)]
#[repr(C, packed)]
#[derive(Debug, IntoBytes, Immutable)]
struct MadtHeader {
    sdt: SdtHeader,
    base_address: U32,
    flags: U32,
}

/// Multiple APIC Description Table (MADT)
///
/// This table includes information about the interrupt controllers of the device.
/// More information about this table can be found in the ACPI specification:
/// https://uefi.org/specs/ACPI/6.5/05_ACPI_Software_Programming_Model.html#multiple-apic-description-table-madt
#[derive(Debug)]
pub struct Madt {
    header: MadtHeader,
    interrupt_controllers: Vec<u8>,
}

impl Madt {
    pub fn new(
        oem_id: [u8; 6],
        oem_table_id: [u8; 8],
        oem_revision: u32,
        base_address: u32,
        interrupt_controllers: Vec<u8>,
    ) -> Self {
        let length = size_of::<MadtHeader>() + interrupt_controllers.len();
        let sdt_header = SdtHeader::new(
            *b"APIC",
            // It is ok to unwrap the conversion of `length` to u32. `SdtHeader` is 36 bytes long,
            // so `length` here has a value of 44.
            length.try_into().unwrap(),
            6,
            oem_id,
            oem_table_id,
            oem_revision,
        );

        let mut header = MadtHeader {
            sdt: sdt_header,
            base_address: U32::new(base_address),
            flags: U32::ZERO,
        };

        header.sdt.checksum = checksum(&[header.as_bytes(), interrupt_controllers.as_bytes()]);

        Madt {
            header,
            interrupt_controllers,
        }
    }
}

impl Sdt for Madt {
    fn len(&self) -> usize {
        self.header.sdt.length.get().try_into().unwrap()
    }

    fn write_to_guest<M: GuestMemory>(&mut self, mem: &M, address: GuestAddress) -> Result<()> {
        mem.write_slice(self.header.as_bytes(), address)?;
        let address = address
            .checked_add(size_of::<MadtHeader>() as u64)
            .ok_or(AcpiError::InvalidGuestAddress)?;
        mem.write_slice(self.interrupt_controllers.as_bytes(), address)?;

        Ok(())
    }
}

// use super::sdt::Sdt;
// use crate::arch::x86_64::mptable::{APIC_DEFAULT_PHYS_BASE, IO_APIC_DEFAULT_PHYS_BASE};
// use zerocopy::{FromBytes, Immutable, IntoBytes};
//
// const MADT_CPU_ENABLE_FLAG: u32 = 0;
// const MADT_CPU_ONLINE_CAPABLE_FLAG: usize = 1;
//
// #[repr(C, packed)]
// #[derive(Default, IntoBytes, Immutable, FromBytes)]
// pub struct LocalApic {
//     r#type: u8,
//     length: u8,
//     processor_uid: u8,
//     apic_id: u8,
//     flags: u32,
// }
//
// #[repr(C, packed)]
// #[derive(IntoBytes, Immutable, FromBytes)]
// struct LocalX2Apic {
//     pub r#type: u8,
//     pub length: u8,
//     pub _reserved: u16,
//     pub apic_id: u32,
//     pub flags: u32,
//     pub processor_id: u32,
// }
//
// #[repr(C, packed)]
// #[derive(Default, IntoBytes, Immutable, FromBytes)]
// struct IoApic {
//     pub r#type: u8,
//     pub length: u8,
//     pub ioapic_id: u8,
//     _reserved: u8,
//     pub apic_address: u32,
//     pub gsi_base: u32,
// }
//
// pub fn create_table(nr_vcpus: u8) -> Sdt {
//     let mut madt = Sdt::new(*b"APIC", 44, 5, *b"TOYVMM", *b"TVMADT  ", 0);
//
//     madt.write(36, APIC_DEFAULT_PHYS_BASE);
//     for cpu_id in 0..nr_vcpus {
//         let lapic = LocalApic {
//             r#type: 0, // 0 = Processor Local APIC
//             length: 8,
//             processor_uid: cpu_id,
//             apic_id: cpu_id,
//             flags: 1u32 << MADT_CPU_ENABLE_FLAG,
//         };
//         // let lapic = LocalX2Apic {
//         //     r#type: 9, // 9 = Processor Local x2APIC
//         //     length: 16,
//         //     processor_id: cpu_id as u32,
//         //     apic_id: cpu_id as u32,
//         //     flags: if cpu_id == 0 {
//         //         1 << MADT_CPU_ENABLE_FLAG
//         //     } else {
//         //         0
//         //     } | (1 << MADT_CPU_ONLINE_CAPABLE_FLAG),
//         //     _reserved: 0,
//         // };
//         madt.append(lapic);
//     }
//     madt.append(IoApic {
//         r#type: 1, // 1 = I/O APIC
//         length: 12,
//         ioapic_id: 0,
//         apic_address: IO_APIC_DEFAULT_PHYS_BASE,
//         gsi_base: 0, // 0? 5?
//         ..Default::default()
//     });
//     madt.update_checksum();
//
//     madt
// }
