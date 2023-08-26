use std::os::unix::io::RawFd;
use std::result::Result;

use vm_memory::{mmap::MmapRegionError, MmapRegion};

/// Errors associated with operations on memory.
#[derive(Debug, thiserror::Error)]
pub enum MemoryError {
    /// Genral error on I/O operation.
    #[error("General error on I/O operation: {0}")]
    Os(#[from] std::io::Error),
    /// Memory region for vm build error.
    #[error("Memory region for vm build error: {0}")]
    BuildMmapRegion(MmapRegionError),
}

pub(crate) fn mmap(size: usize, fd: RawFd, offset: i64) -> Result<MmapRegion, MemoryError> {
    let prot = libc::PROT_READ | libc::PROT_WRITE;
    let flags = libc::MAP_SHARED | libc::MAP_POPULATE;

    let ptr = unsafe { libc::mmap(std::ptr::null_mut(), size, prot, flags, fd, offset) };
    if (ptr as isize) < 0 {
        return Err(MemoryError::Os(std::io::Error::last_os_error()));
    }
    unsafe {
        MmapRegion::build_raw(ptr as *mut u8, size, prot, flags)
            .map_err(MemoryError::BuildMmapRegion)
    }
}
