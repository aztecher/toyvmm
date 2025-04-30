// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::mem::size_of;

use zerocopy::IntoBytes;

use crate::acpi;
use crate::acpi::{
    aml,
    dsdt::Dsdt,
    fadt::{
        Fadt, FADT_F_HW_REDUCED_ACPI, FADT_F_PWR_BUTTON, FADT_F_SLP_BUTTON,
        IAPC_BOOT_ARG_FLAGS_MSI_NOT_PRESENT, IAPC_BOOT_ARG_FLAGS_PCI_ASPM,
        IAPC_BOOT_ARG_FLAGS_VGA_NOT_PRESENT,
    },
    madt::{IoAPIC, LocalAPIC, Madt},
    rsdp::Rsdp,
    xsdt::Xsdt,
    Sdt,
};

use crate::arch::x86_64::mptable::{APIC_DEFAULT_PHYS_BASE, IO_APIC_DEFAULT_PHYS_BASE};
use crate::arch::x86_64::RSDP_POINTER;
use crate::device_manager::{
    legacy::PortIoDeviceManager,
    mmio::{add_virtio_aml, MmioDeviceManager},
};
use crate::vstate::memory::GuestMemoryMmap;
use vm_memory::{Address, GuestAddress};

// Our (Original Equipment Manufacturer" (OEM) name. OEM is how ACPI names the manufacturer of the
// hardware that is exposed to the OS, through ACPI tables. The OEM name is passed in every ACPI
// table, to let the OS know that we are the owner of the table.
const OEM_ID: [u8; 6] = *b"TOYVMM";

// In reality the OEM revision is per table and it defines the revision of the OEM's implementation
// of the particular ACPI table. For our purpose, we can set it to a fixed value for all the tables
const OEM_REVISION: u32 = 0;

// This is needed for an entry in the FADT table. Populating this entry in FADT is a way to let the
// guest know that it runs within a Firecracker microVM.
const HYPERVISOR_VENDOR_ID: [u8; 8] = *b"TOYVMM  ";

#[derive(Debug, thiserror::Error)]
/// Error type for ACPI related operations
pub enum AcpiError {
    /// ACPI tables error
    #[error("ACPI tables error: {0}")]
    AcpiTables(acpi::AcpiError),
    /// Error creating AML bytecode
    #[error("Error creating AML bytecode: {0}")]
    AmlError(aml::AmlError),
}

/// Helper type that holds the guest memory in which we write the tables in and a resource
/// allocator for allocating space for the tables
struct AcpiTableWriter<'a> {
    mem: &'a GuestMemoryMmap,
}

impl AcpiTableWriter<'_> {
    /// Write a table in guest memory
    ///
    /// This will allocate enough space inside guest memory and write the table in the allocated
    /// buffer. It returns the address in which it wrote the table.
    fn write_acpi_table<S: Sdt>(
        &mut self,
        table: &mut S,
        addr: GuestAddress,
    ) -> Result<(), AcpiError>
    where
        S: Sdt,
    {
        table
            .write_to_guest(self.mem, addr)
            .map_err(AcpiError::AcpiTables)?;
        Ok(())
    }

    /// Build the DSDT table for the guest
    fn build_dsdt(
        &mut self,
        mmio_device_manager: &MmioDeviceManager,
        pio_device_manager: &PortIoDeviceManager,
        dsdt_offset: GuestAddress,
    ) -> Result<u64, AcpiError> {
        let mut dsdt_data = Vec::new();

        // Virtio device
        for (_, dev_info) in mmio_device_manager.device_requests.iter().enumerate() {
            add_virtio_aml(&mut dsdt_data, dev_info.addr, dev_info.len, dev_info.irq)
                .map_err(AcpiError::AmlError)?;
        }

        // Architecture specific DSDT data
        pio_device_manager.append_aml_bytes(&mut dsdt_data).unwrap();

        let mut dsdt = Dsdt::new(OEM_ID, *b"TVDSDT  ", OEM_REVISION, dsdt_data);
        self.write_acpi_table(&mut dsdt, dsdt_offset);
        Ok(dsdt.len() as u64)
    }

    /// Build the FADT table for the guest
    ///
    /// This includes a pointer with the location of the DSDT in guest memory
    fn build_fadt(&mut self, dsdt_addr: u64, fadt_offset: GuestAddress) -> Result<u64, AcpiError> {
        let mut fadt = Fadt::new(OEM_ID, *b"FCVMFADT", OEM_REVISION);
        fadt.set_hypervisor_vendor_id(HYPERVISOR_VENDOR_ID);
        fadt.set_x_dsdt(dsdt_addr);
        fadt.set_flags(
            (1 << FADT_F_HW_REDUCED_ACPI) | (1 << FADT_F_PWR_BUTTON) | (1 << FADT_F_SLP_BUTTON),
        );
        setup_arch_fadt(&mut fadt);

        self.write_acpi_table(&mut fadt, fadt_offset);
        Ok(fadt.len() as u64)
    }

    /// Build the MADT table for the guest
    ///
    /// This includes information about the interrupt controllers supported in the platform
    fn build_madt(&mut self, nr_vcpus: u8, madt_offset: GuestAddress) -> Result<u64, AcpiError> {
        let mut madt = Madt::new(
            OEM_ID,
            *b"FCVMMADT",
            OEM_REVISION,
            APIC_DEFAULT_PHYS_BASE,
            setup_interrupt_controllers(nr_vcpus),
        );
        self.write_acpi_table(&mut madt, madt_offset);
        Ok(madt.len() as u64)
    }

    /// Build the XSDT table for the guest
    ///
    /// Currently, we pass to the guest just FADT and MADT tables.
    fn build_xsdt(
        &mut self,
        tables: Vec<u64>,
        xsdt_offset: GuestAddress,
    ) -> Result<u64, AcpiError> {
        let mut xsdt = Xsdt::new(OEM_ID, *b"FCMVXSDT", OEM_REVISION, tables);
        self.write_acpi_table(&mut xsdt, xsdt_offset);
        Ok(xsdt.len() as u64)
    }

    /// Build the RSDP pointer for the guest.
    ///
    /// This will build the RSDP pointer which points to the XSDT table and write it in guest
    /// memory. The address in which we write RSDP is pre-determined for every architecture.
    /// We will not allocate arbitrary memory for it
    fn build_rsdp(&mut self, xsdt_addr: u64) -> Result<(), AcpiError> {
        let mut rsdp = Rsdp::new(OEM_ID, xsdt_addr);
        rsdp.write_to_guest(self.mem, RSDP_POINTER).unwrap();
        Ok(())
    }
}

/// Create ACPI tables for the guest
///
/// This will create the ACPI tables needed to describe to the guest OS the available hardware,
/// such as interrupt controllers, vCPUs and VirtIO devices.
pub(crate) fn create_acpi_tables(
    mem: &GuestMemoryMmap,
    mmio_device_manager: &MmioDeviceManager,
    pio_device_manager: &PortIoDeviceManager,
    nr_vcpus: u8,
) -> Result<GuestAddress, AcpiError> {
    let mut writer = AcpiTableWriter { mem };
    let mut tables = Vec::new();

    // Calculate offsets and write down informations

    let rsdp_offset = RSDP_POINTER;
    let dsdt_offset = rsdp_offset
        .checked_add(core::mem::size_of::<Rsdp>() as u64)
        .unwrap();
    let dsdt_size = writer.build_dsdt(mmio_device_manager, pio_device_manager, dsdt_offset)?;

    let fadt_offset = dsdt_offset.checked_add(dsdt_size).unwrap();
    let fadt_size = writer.build_fadt(dsdt_offset.0, fadt_offset).unwrap();
    tables.push(fadt_offset.0);

    let madt_offset = fadt_offset.checked_add(fadt_size).unwrap();
    let madt_size = writer.build_madt(nr_vcpus, madt_offset)?;
    tables.push(madt_offset.0);

    let xsdt_offset = madt_offset.checked_add(madt_size).unwrap();
    let _ = writer.build_xsdt(tables, xsdt_offset)?;
    writer.build_rsdp(xsdt_offset.0).unwrap();
    Ok(rsdp_offset)
}

#[inline(always)]
pub(crate) fn setup_interrupt_controllers(nr_vcpus: u8) -> Vec<u8> {
    let mut ic =
        Vec::with_capacity(size_of::<IoAPIC>() + (nr_vcpus as usize) * size_of::<LocalAPIC>());

    ic.extend_from_slice(IoAPIC::new(0, IO_APIC_DEFAULT_PHYS_BASE).as_bytes());
    for i in 0..nr_vcpus {
        ic.extend_from_slice(LocalAPIC::new(i).as_bytes());
    }
    ic
}

#[inline(always)]
pub(crate) fn setup_arch_fadt(fadt: &mut Fadt) {
    // Let the guest kernel know that there is not VGA hardware present
    // neither do we support ASPM, or MSI type of interrupts.
    // More info here:
    // https://uefi.org/specs/ACPI/6.5/05_ACPI_Software_Programming_Model.html?highlight=0a06#ia-pc-boot-architecture-flags
    fadt.setup_iapc_flags(
        (1 << IAPC_BOOT_ARG_FLAGS_VGA_NOT_PRESENT)
            | (1 << IAPC_BOOT_ARG_FLAGS_PCI_ASPM)
            | (1 << IAPC_BOOT_ARG_FLAGS_MSI_NOT_PRESENT),
    );
}

// #[inline(always)]
// pub(crate) fn setup_arch_dsdt(dsdt_data: &mut Vec<u8>) -> Result<(), aml::AmlError> {
//     PortIODeviceManager::append_aml_bytes(dsdt_data)
// }
//
// pub(crate) const fn apic_addr() -> u32 {
//     layout::APIC_ADDR
// }
//
// pub(crate) const fn rsdp_addr() -> GuestAddress {
//     GuestAddress(layout::RSDP_ADDR)
// }
