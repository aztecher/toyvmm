// Copyright 2023 aztecher, or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vmm::builder::{build_and_boot_vm, StartVmError};
use vmm::resources::VmResources;

#[derive(Debug, thiserror::Error)]
pub enum UtilsError {
    /// Failed to create VmResources.
    #[error("Failed to create VmResources: {0}")]
    CreateVmResources(#[from] vmm::resources::ResourcesError),
    /// Failed to build Vm.
    #[error("Failed to build virtual machine: {0}")]
    BuildVm(#[from] StartVmError),
}

pub fn run_vm_from_config(config: &str) -> Result<(), UtilsError> {
    // Prepare resources from the given configuraiton file.
    let vm_resources = VmResources::from_json(config)?;
    // Run virtual machine from configuration file.
    build_and_boot_vm(vm_resources).map_err(UtilsError::BuildVm)?;
    Ok(())
}
