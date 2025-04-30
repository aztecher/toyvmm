// // Copyright © 2019 Intel Corporation
// //
// // SPDX-License-Identifier: Apache-2.0
// //
//
// use super::sdt::Sdt;
//
// pub fn create_table() -> Sdt {
//     let mut mcfg = Sdt::new(*b"MCFG", 36, 1, *b"TOYVMM", *b"TVMCFG  ", 1);
//     // let mut mcfg = Sdt::new(*b"MCFG", 36, 1, *b"CLOUDH", *b"CHMCFG  ", 1);
//     // MCFG reserved 8 bytes
//     mcfg.append(0u64);
//
//     // PCI Segment Reserved
//
//     mcfg
// }
