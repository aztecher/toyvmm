// Copyright 2023 aztecher, or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// extern in src/lib.rs
use super::if_tun::sock_fprog;
use utils::{ioctl_ior_nr, ioctl_iow_nr};

pub const TUNTAP: ::std::os::raw::c_uint = 84;

ioctl_iow_nr!(TUNSETNOCSUM, TUNTAP, 200, ::std::os::raw::c_int);
ioctl_iow_nr!(TUNSETDEBUG, TUNTAP, 201, ::std::os::raw::c_int);
ioctl_iow_nr!(TUNSETIFF, TUNTAP, 202, ::std::os::raw::c_int);
ioctl_iow_nr!(TUNSETPERSIST, TUNTAP, 203, ::std::os::raw::c_int);
ioctl_iow_nr!(TUNSETOWNER, TUNTAP, 204, ::std::os::raw::c_int);
ioctl_iow_nr!(TUNSETLINK, TUNTAP, 205, ::std::os::raw::c_int);
ioctl_iow_nr!(TUNSETGROUP, TUNTAP, 206, ::std::os::raw::c_int);
ioctl_ior_nr!(TUNGETFEATURES, TUNTAP, 207, ::std::os::raw::c_uint);
ioctl_iow_nr!(TUNSETOFFLOAD, TUNTAP, 208, ::std::os::raw::c_uint);
ioctl_iow_nr!(TUNSETTXFILTER, TUNTAP, 209, ::std::os::raw::c_uint);
ioctl_ior_nr!(TUNGETIFF, TUNTAP, 210, ::std::os::raw::c_uint);
ioctl_ior_nr!(TUNGETSNDBUF, TUNTAP, 211, ::std::os::raw::c_int);
ioctl_iow_nr!(TUNSETSNDBUF, TUNTAP, 212, ::std::os::raw::c_int);
ioctl_iow_nr!(TUNATTACHFILTER, TUNTAP, 213, sock_fprog);
ioctl_iow_nr!(TUNDETACHFILTER, TUNTAP, 214, sock_fprog);
ioctl_ior_nr!(TUNGETVNETHDRSZ, TUNTAP, 215, ::std::os::raw::c_int);
ioctl_iow_nr!(TUNSETVNETHDRSZ, TUNTAP, 216, ::std::os::raw::c_int);
ioctl_iow_nr!(TUNSETQUEUE, TUNTAP, 217, ::std::os::raw::c_int);
ioctl_iow_nr!(TUNSETIFINDEX, TUNTAP, 218, ::std::os::raw::c_uint);
ioctl_ior_nr!(TUNGETFILTER, TUNTAP, 219, sock_fprog);
ioctl_iow_nr!(TUNSETVNETLE, TUNTAP, 220, ::std::os::raw::c_int);
ioctl_ior_nr!(TUNGETVNETLE, TUNTAP, 221, ::std::os::raw::c_int);
ioctl_iow_nr!(TUNSETVNETBE, TUNTAP, 222, ::std::os::raw::c_int);
ioctl_ior_nr!(TUNGETVNETBE, TUNTAP, 223, ::std::os::raw::c_int);
