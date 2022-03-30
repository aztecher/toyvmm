use std::io::Error as IOError;
use std::os::unix::io::RawFd;
use std::result::Result;

use vm_memory::{
    MmapRegion,
    mmap::MmapRegionError,
};

#[derive(Debug)]
pub enum Error {
    Os(IOError),
    BuildMmapRegion(MmapRegionError),
}

pub(crate) fn mmap(size: usize, fd: RawFd, offset: i64) -> Result<MmapRegion, Error> {
    let prot = libc::PROT_READ | libc::PROT_WRITE;
    let flags = libc::MAP_SHARED | libc::MAP_POPULATE;

    let ptr = unsafe { libc::mmap(std::ptr::null_mut(), size, prot, flags, fd, offset) };
    if (ptr as isize) < 0 {
        return Err(Error::Os(IOError::last_os_error()));
    }
    unsafe {
        MmapRegion::build_raw(ptr as *mut u8, size, prot, flags).map_err(Error::BuildMmapRegion)
    }
}
