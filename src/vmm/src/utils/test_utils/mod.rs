// use crate::builder::build;
// use crate::utils::mock_resources::{MockBootSourceConfig, MockVmResources};
// use crate::vm_resources::BootSourceConfig;
// use crate::{kvm::vcpu::Vcpu, vmm::Vmm};
//
// pub fn create_vmm(kernel_image: Option<&str>) -> (Vmm, Vec<Vcpu>) {
//     let boot_source_cfg = MockBootSourceConfig::new().with_default_boot_args();
//
//     #[cfg(target_arch = "x86_64")]
//     let boot_source_cfg: BootSourceConfig = match kernel_image {
//         Some(kernel) => boot_source_cfg.with_kernel(kernel).into(),
//         None => boot_source_cfg.into(),
//     };
//     let resources = MockVmResources::new()
//         .with_boot_source(boot_source_cfg)
//         .into();
//
//     build(&resources).unwrap()
// }
//
// pub fn default_vmm(kernel_image: Option<&str>) -> (Vmm, Vec<Vcpu>) {
//     create_vmm(kernel_image)
// }
