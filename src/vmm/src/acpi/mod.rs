// Copyright 2025 aztecher, or its affiliates. All Rights Reserved.
//
// Portions Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod aml;
pub mod dsdt;
pub mod fadt;
pub mod madt;
pub mod rsdp;
pub mod xsdt;

use vm_memory::{GuestAddress, GuestMemory, GuestMemoryError};
use zerocopy::little_endian::U32;
use zerocopy::{Immutable, IntoBytes};

const TOYVMM_ACPI_CREATOR_ID: [u8; 4] = *b"TVAT";
const TOYVMM_ACPI_CREATOR_REVISION: u32 = 0x20250501;

pub fn checksum(buf: &[&[u8]]) -> u8 {
    (255 - buf
        .iter()
        .flat_map(|b| b.iter())
        .fold(0u8, |acc, x| acc.wrapping_add(*x)))
    .wrapping_add(1)
}

/// ACPI type representing memory addresses
#[repr(C, packed)]
#[derive(IntoBytes, Immutable, Clone, Copy, Debug, Default)]
pub struct GenericAddressStructure {
    pub address_space_id: u8,
    pub register_bit_width: u8,
    pub register_bit_offset: u8,
    pub access_size: u8,
    pub address: u64,
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum AcpiError {
    /// Guest memory error: {0}
    GuestMemory(#[from] GuestMemoryError),
    /// Invalid guest address
    InvalidGuestAddress,
    /// Invalid register size
    InvalidRegisterSize,
}

#[repr(C, packed)]
#[derive(Clone, Debug, Copy, Default, IntoBytes, Immutable)]
pub struct SdtHeader {
    pub signature: [u8; 4],
    pub length: U32,
    pub revision: u8,
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub oem_table_id: [u8; 8],
    pub oem_revision: U32,
    pub creator_id: [u8; 4],
    pub creator_revison: U32,
}

impl SdtHeader {
    pub(crate) fn new(
        signature: [u8; 4],
        length: u32,
        table_revision: u8,
        oem_id: [u8; 6],
        oem_table_id: [u8; 8],
        oem_revision: u32,
    ) -> Self {
        SdtHeader {
            signature,
            length: U32::new(length),
            revision: table_revision,
            checksum: 0,
            oem_id,
            oem_table_id,
            oem_revision: U32::new(oem_revision),
            creator_id: TOYVMM_ACPI_CREATOR_ID,
            creator_revison: U32::new(TOYVMM_ACPI_CREATOR_REVISION),
        }
    }
}

/// A trait for functionality around System Descriptor Tables.
pub trait Sdt {
    /// Get the length of the table
    fn len(&self) -> usize;

    /// Return true if Sdt is empty
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Write the table in guest memory
    fn write_to_guest<M: GuestMemory>(
        &mut self,
        mem: &M,
        address: GuestAddress,
    ) -> Result<(), AcpiError>;
}
