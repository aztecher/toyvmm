use vmm::builder::{build_and_boot_vm, StartVmError};
use vmm::resources::VmResources;

#[derive(Debug, thiserror::Error)]
pub enum UtilsError {
    /// Failed to create VmResources.
    #[error("Failed to create VmResources: {0}")]
    CreateVmResources(#[from] vmm::resources::ResourcesError),
    /// Failed to build Vm.
    #[error("Failed to build virtual machine: {0}")]
    BuildVm(StartVmError),
}

pub fn build_vm_from_config(config: &str) -> Result<(), UtilsError> {
    // Prepare resources from the given configuraiton file.
    let vm_resources = VmResources::from_json(config)?;
    // TODO) EventManager setup

    // TODO) EventManager instance is passed to build_vm_for_boot
    build_and_boot_vm(vm_resources).map_err(UtilsError::BuildVm)?;
    Ok(())
}
