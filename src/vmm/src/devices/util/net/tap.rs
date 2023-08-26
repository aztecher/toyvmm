// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::io::{Error as IoError, ErrorKind, Read, Result as IoResult, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

use crate::devices::util::sys::net as SysNetUtil;
use utils::ioctl::{ioctl_with_mut_ref, ioctl_with_ref, ioctl_with_val};

/// Errors associated with actions on configuring tap device.
#[derive(Debug, thiserror::Error)]
pub enum TapError {
    /// Failed to create a socket.
    #[error("Failed to create a socket: {0}")]
    CreateSocket(#[source] IoError),
    /// Failed to open /dev/net/tun.
    #[error("Failed to open /dev/net/tun: {0}")]
    OpenTun(#[source] IoError),
    /// Failed to create tap device.
    #[error("Failed to create tap device: {0}")]
    CreateTap(#[source] IoError),
    /// Error while setting the offload flags.
    #[error("Error while setting the offload floags: {0}")]
    SetOffloadFlags(#[source] IoError),
    /// Error while setting size of vnet header.
    #[error("Error while setting size of vnet header: {0}")]
    SetSizeOfVnetHdr(#[source] IoError),
    /// Error while setting linkup the host-side tap device.
    #[error("Error while setting linkup the host-side tap device: {0}")]
    LinkupTap(#[source] IoError),
}

fn create_socket() -> Result<std::net::UdpSocket, TapError> {
    // This is safe since we check the return value.
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(TapError::CreateSocket(std::io::Error::last_os_error()));
    }

    // This is safe; nothing else will use or hold onto the raw sock fd.
    Ok(unsafe { std::net::UdpSocket::from_raw_fd(sock) })
}

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
    pub fn new() -> Result<Tap, TapError> {
        // Open calls are safe because we give a constant nul-terminated
        // string and verify the result.
        let fd = unsafe {
            libc::open(
                b"/dev/net/tun\0".as_ptr() as *const libc::c_char,
                libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(TapError::OpenTun(IoError::last_os_error()));
        }

        // We just checked that the fd is valid
        let tuntap = unsafe { File::from_raw_fd(fd) };

        const TUNTAP_DEV_FORMAT: &[u8; 8usize] = b"vmtap%d\0";

        // This is pretty messy because of the unions used by ifreq. Since we
        // don't call as_mut on the same union field more than once, this block
        // is safe.
        let mut ifreq: SysNetUtil::ifreq = Default::default();
        unsafe {
            let ifrn_name = ifreq.ifr_ifrn.ifrn_name.as_mut();
            let ifru_flags = ifreq.ifr_ifru.ifru_flags.as_mut();
            let name_slice = &mut ifrn_name[..TUNTAP_DEV_FORMAT.len()];
            name_slice.copy_from_slice(TUNTAP_DEV_FORMAT);
            *ifru_flags = (SysNetUtil::IFF_TAP | SysNetUtil::IFF_NO_PI | SysNetUtil::IFF_VNET_HDR)
                as libc::c_short;
        }

        // ioctl is safe since we call it with a valid tap fd and check the return value.
        if unsafe { ioctl_with_mut_ref(&tuntap, SysNetUtil::TUNSETIFF(), &mut ifreq) } < 0 {
            let error = IoError::last_os_error();
            // In a non-root, test environment, we won't have permission to call this; allow
            if !(cfg!(test) && error.kind() == ErrorKind::PermissionDenied) {
                return Err(TapError::CreateTap(error));
            }
        }

        #[allow(clippy::clone_on_copy)]
        Ok(Tap {
            tap_file: tuntap,
            if_name: unsafe { ifreq.ifr_ifrn.ifrn_name.as_ref().clone() },
        })
    }

    /// Set the offload flags for the tap interface.
    pub fn set_offload(&self, flags: libc::c_uint) -> Result<(), TapError> {
        // ioctl is safe. Called with a valid tap fd, and we check the return.
        if unsafe {
            ioctl_with_val(
                &self.tap_file,
                SysNetUtil::TUNSETOFFLOAD(),
                libc::c_ulong::from(flags),
            )
        } < 0
        {
            return Err(TapError::SetOffloadFlags(IoError::last_os_error()));
        }
        Ok(())
    }

    /// Enable the tap interface
    pub fn enable(&self) -> Result<(), TapError> {
        let sock = create_socket()?;

        let mut ifreq = self.get_ifreq();

        // We only access one field of the ifru union, hence this is safe.
        unsafe {
            let ifru_flags = ifreq.ifr_ifru.ifru_flags.as_mut();
            *ifru_flags = (SysNetUtil::net_device_flags_IFF_UP
                | SysNetUtil::net_device_flags_IFF_RUNNING) as i16;
        }

        // ioctl is safe. Called with a valid sock fd, and we check the return.
        if unsafe {
            ioctl_with_ref(
                &sock,
                libc::c_ulong::from(SysNetUtil::sockios::SIOCSIFFLAGS),
                &ifreq,
            )
        } < 0
        {
            return Err(TapError::LinkupTap(IoError::last_os_error()));
        }
        Ok(())
    }

    /// Set the size of the vnet hdr
    pub fn set_vnet_hdr_size(&self, size: libc::c_int) -> Result<(), TapError> {
        // ioctl is safe. Called with a valid tap fd, and we check the return.
        if unsafe { ioctl_with_ref(&self.tap_file, SysNetUtil::TUNSETVNETHDRSZ(), &size) } < 0 {
            return Err(TapError::SetSizeOfVnetHdr(IoError::last_os_error()));
        }
        Ok(())
    }

    fn get_ifreq(&self) -> SysNetUtil::ifreq {
        let mut ifreq: SysNetUtil::ifreq = Default::default();

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
        self.tap_file.write(buf)
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
