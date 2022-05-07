// use toyvmm::{
//     builder::build,
//     vm_resources::VmResources,
//     utils::{
//         mock_resources::MockVmResources,
//         test_utils::default_vmm,
//     },
// };
//
// #[test]
// fn test_build() {
//     // Error case: no boot source configured
//     {
//         let resources: VmResources = MockVmResources::new().into();
//         let vmm_ret = build(&resources);
//         assert_eq!(format!("{:?}", vmm_ret.err()), "Some(MissingKernelConfig)");
//     }
//     // Success case.
//     let (vmm, vcpus) = default_vmm(None);
// }
//
// #[test]
// fn test_linux_kernel() {
//     let (vmm, vcpus) = default_vmm(None);
//     // how to run vcpu
//     for vcpu in vcpus.iter() {
//         // match vcpu.run_emulation() {
//         //     Ok(o) => println!("ok: {:?}", o),
//         //     Err(e) => println!("error: {:?}", e),
//         // }
//         loop {
//             match vcpu.run_emulation() {
//                 Ok(o) => println!("ok: {:?}", o),
//                 Err(e) => {
//                     println!("error: {:?}", e);
//                     break;
//                 }
//             }
//         }
//     }
// }
