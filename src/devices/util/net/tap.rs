// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::net;
use std::fs::File;
use std::io::{Error as IoError, ErrorKind, Read, Result as IoResult, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

use crate::devices::util::{
    Error, Result, create_socket, create_sockaddr,
    sys::net as netsys,
};
use vmm_sys_util::ioctl::{
    ioctl_with_val,
    ioctl_with_ref,
    ioctl_with_mut_ref,
};

/// Handle for a network tap interface.
///
/// For now, this simply wraps the file descriptor for the tap device so methods
/// can run ioctls on the interface. The tap interface fd will be closed when
/// Tap goes out of scope, and the kernel will clean up the interface
/// automatically.
#[derive(Debug)]
pub struct Tap {
    tap_file: File,
    if_name: [u8; 16usize],
}

impl Tap {
    /// Create a new tap interface
    pub fn new() -> Result<Tap> {
        // Open calls are safe because we give a constant nul-terminated
        // string and verify the result.
        let fd = unsafe {
            libc::open(
                b"/dev/net/tun\0".as_ptr() as *const libc::c_char,
                libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(Error::OpenTun(IoError::last_os_error()));
        }

        // We just checked that the fd is valid
        let tuntap = unsafe { File::from_raw_fd(fd) };

        const TUNTAP_DEV_FORMAT: &'static [u8; 8usize] = b"vmtap%d\0";

        // This is pretty messy because of the unions used by ifreq. Since we
        // don't call as_mut on the same union field more than once, this block
        // is safe.
        let mut ifreq: netsys::ifreq = Default::default();
        unsafe {
            let ifrn_name = ifreq.ifr_ifrn.ifrn_name.as_mut();
            let ifru_flags = ifreq.ifr_ifru.ifru_flags.as_mut();
            let name_slice = &mut ifrn_name[..TUNTAP_DEV_FORMAT.len()];
            name_slice.copy_from_slice(TUNTAP_DEV_FORMAT);
            *ifru_flags =
                (netsys::IFF_TAP | netsys::IFF_NO_PI | netsys::IFF_VNET_HDR) as libc::c_short;
        }

        // ioctl is safe since we call it with a valid tap fd and check the return value.
        let ret = unsafe { ioctl_with_mut_ref(&tuntap, netsys::TUNSETIFF(), &mut ifreq) };

        if ret < 0 {
            let error = IoError::last_os_error();

            // In a non-root, test environment, we won't have permission to call this; allow
            if !(cfg!(test) && error.kind() == ErrorKind::PermissionDenied) {
                return Err(Error::CreateTap(error));
            }
        }

        // Safe since only the name is accessed, and it's cloned out.
        Ok(Tap {
            tap_file: tuntap,
            if_name: unsafe { ifreq.ifr_ifrn.ifrn_name.as_ref().clone() },
        })
    }

    /// Set the host-side IP address for the tap interface
    pub fn set_ip_addr(&self, ip_addr: net::Ipv4Addr) -> Result<()> {
        let sock = create_socket()?;
        let addr = create_sockaddr(ip_addr);

        let mut ifreq = self.get_ifreq();

        // We only access one field of the ifru union, hence this is safe
        unsafe {
            let ifru_addr = ifreq.ifr_ifru.ifru_addr.as_mut();
            *ifru_addr = addr;
        }

        // ioctl is safe. Called with a valid sock fd, annd we check the return.
        let ret = unsafe {
            ioctl_with_ref(&sock, netsys::sockios::SIOCSIFADDR as libc::c_ulong, &ifreq)
        };
        if ret < 0 {
            return Err(Error::IoctlError(IoError::last_os_error()));
        }

        Ok(())
    }


    /// Set the netmask for the subnet that the tap interface will exist on.
    pub fn set_netmask(&self, netmask: net::Ipv4Addr) -> Result<()> {
        let sock = create_socket()?;
        let addr = create_sockaddr(netmask);

        let mut ifreq = self.get_ifreq();

        // We only access one field of the ifru union, hence this is safe.
        unsafe {
            let ifru_addr = ifreq.ifr_ifru.ifru_addr.as_mut();
            *ifru_addr = addr;
        }

        // ioctl is safe. Called with a valid sock fd, and we check the return
        let ret = unsafe {
            ioctl_with_ref(&sock, netsys::sockios::SIOCSIFNETMASK as libc::c_ulong, &ifreq)
        };
        if ret < 0 {
            return Err(Error::IoctlError(IoError::last_os_error()));
        }
        Ok(())
    }

    /// Set the offload flags for the tap interface.
    pub fn set_offload(&self, flags: libc::c_uint) -> Result<()> {
        // ioctl is safe. Called with a valid tap fd, and we check the return.
        let ret = unsafe {
            ioctl_with_val(&self.tap_file, netsys::TUNSETOFFLOAD(), flags as libc::c_ulong)
        };
        if ret < 0 {
            return Err(Error::IoctlError(IoError::last_os_error()));
        }
        Ok(())
    }

    /// Enable the tap interface
    pub fn enable(&self) -> Result<()> {
        let sock = create_socket()?;

        let mut ifreq = self.get_ifreq();

        // We only access one field of the ifru union, hence this is safe.
        unsafe {
            let ifru_flags = ifreq.ifr_ifru.ifru_flags.as_mut();
            *ifru_flags =
                (netsys::net_device_flags_IFF_UP | netsys::net_device_flags_IFF_RUNNING) as i16;
        }

        // ioctl is safe. Called with a valid sock fd, and we check the return.
        let ret = unsafe {
            ioctl_with_ref(&sock, netsys::sockios::SIOCSIFFLAGS as libc::c_ulong, &ifreq)
        };
        if ret < 0 {
            return Err(Error::IoctlError(IoError::last_os_error()));
        }
        Ok(())
    }

    /// Set the size of the vnet hdr
    pub fn set_vnet_hdr_size(&self, size: libc::c_int) -> Result<()> {
        // ioctl is safe. Called with a valid tap fd, and we check the return.
        let ret =
            unsafe { ioctl_with_ref(&self.tap_file, netsys::TUNSETVNETHDRSZ(), &size) };
        if ret < 0 {
            return Err(Error::IoctlError(IoError::last_os_error()));
        }
        Ok(())
    }

    fn get_ifreq(&self) -> netsys::ifreq {
        let mut ifreq: netsys::ifreq = Default::default();

        // This set the name of the interface, which is the only entry
        // in a single-field union.
        unsafe {
            let ifrn_name = ifreq.ifr_ifrn.ifrn_name.as_mut();
            ifrn_name.clone_from_slice(&self.if_name);
        }
        ifreq
    }
}


impl Read for Tap {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        self.tap_file.read(buf)
    }
}

impl Write for Tap {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        self.tap_file.write(&buf)
    }

    fn flush(&mut self) -> IoResult<()> {
        Ok(())
    }
}

impl AsRawFd for Tap {
    fn as_raw_fd(&self) -> RawFd {
        self.tap_file.as_raw_fd()
    }
}
