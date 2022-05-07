pub mod x86_64;
pub mod msr_index;
pub mod gdt;

use vm_memory::{Address, GuestAddress, GuestMemory, GuestMemoryRegion};
use crate::kvm::memory;

pub const CMDLINE_MAX_SIZE: usize = 0x10000;

#[derive(Debug, PartialEq)]
pub enum Error {
    InitrdAddress,
    ZeroPageSetup,
    E820Configuration,
}

pub type Result<T> = std::result::Result<T, Error>;
pub const PAGE_SIZE: usize = 4096;

pub fn initrd_load_addr(
    guest_mem: &memory::GuestMemoryMmap,
    initrd_size: usize,
) -> Result<u64> {
    // Find first region from guest address
    let first_region = guest_mem
        .find_region(GuestAddress::new(0))
        .ok_or(Error::InitrdAddress)?;
    // Get first region length
    let lowmem_size = first_region.len() as usize;
    // Check if initrd size is lower than first region
    if lowmem_size < initrd_size {
        return Err(Error::InitrdAddress);
    }
    // bit operation to align to pagesize
    // intuitively, we can get bellow converter
    //   - 0 ~ (PAGE_SIZE - 1)                       -> 0
    //   - (PAGE_SIZE - 1) ~ (PAGE_SIZE * 2 - 1)     -> PAGE_SIZE
    //   - (PAGE_SIZE * 2 - 1) ~ (PAGE_SIZE * 3 - 1) -> PAGE_SIZE * 2
    //   ...
    //
    // to get above result, we operate bellow, all you have to do is
    // invert the bits of PAGE_SIZE and mask the target data.
    let align_to_pagesize = |address| address & !(PAGE_SIZE - 1);
    Ok(align_to_pagesize(lowmem_size - initrd_size) as u64)
}

const FIRST_ADDR_PAST_32BITS: u64 = 1 << 32;
const MEM_32BIT_GAP_SIZE: u64 = 768 << 20;
pub const MMIO_MEM_START: u64 = FIRST_ADDR_PAST_32BITS - MEM_32BIT_GAP_SIZE;

pub fn arch_memory_regions(size: usize) -> Vec<(GuestAddress, usize)> {
    match size.checked_sub(MMIO_MEM_START as usize) {
        None | Some(0) => vec![(GuestAddress(0), size)],
        Some(remaining) => vec![
            (GuestAddress(0), MMIO_MEM_START as usize),
            (GuestAddress(FIRST_ADDR_PAST_32BITS), remaining),
        ],
    }
}

#[cfg(test)]
pub mod tests {
    #[test]
    fn test_align_to_pagesize() {
        let pagesize = 4096;
        let align_to_pagesize = |addr| addr & !(pagesize - 1);
        assert_eq!(0, align_to_pagesize(0) as u64);
        assert_eq!(0, align_to_pagesize(pagesize - 1) as u64);
        assert_eq!(pagesize, align_to_pagesize(pagesize) as u64);
        assert_eq!(pagesize, align_to_pagesize(pagesize * 2 - 1) as u64);
        assert_eq!(pagesize * 2, align_to_pagesize(pagesize * 2) as u64);
        assert_eq!(pagesize * 2, align_to_pagesize(pagesize * 3 - 1) as u64);
    }
}
