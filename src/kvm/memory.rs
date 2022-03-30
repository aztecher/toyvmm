use vm_memory::{
    bitmap::AtomicBitmap,
    mmap::{
        MmapRegionBuilder,
        MmapRegionError,
        NewBitmap,
        check_file_offset,
    },
    FileOffset, GuestAddress, Error
};
use std::os::unix::io::AsRawFd;
use crate::utils::util::get_page_size;

pub type GuestMemoryMmap = vm_memory::GuestMemoryMmap<Option<AtomicBitmap>>;
pub type GuestRegionMmap = vm_memory::GuestRegionMmap<Option<AtomicBitmap>>;
pub type GuestMmapRegion = vm_memory::MmapRegion<Option<AtomicBitmap>>;

const GUARD_PAGE_COUNT: usize = 1;

pub fn create_region(
    maybe_file_offset: Option<FileOffset>,
    size: usize,
    prot: i32,
    flags: i32,
    track_dirty_pages: bool,
) -> Result<GuestMmapRegion, MmapRegionError> {
    let page_size = get_page_size().expect("Cannot retrieve page size.");
    let guarded_size = size + GUARD_PAGE_COUNT * 2 * page_size;
    let guard_addr = unsafe {
        /* > https://linuxjm.osdn.jp/html/LDP_man-pages/man2/mmap.2.html
         * mmap(NULL, size, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0)
         * NULL : kernel find and return mapped address
         * PROT_NONE: inhibit page access
         * flags
         *   - MAP_PRIVATE / MAP_SHARED
         *       Determines whether updates to a mapping are visible to other processes
         *       mapping the same area, or whether updates are communicated
         *       through the mapping source file.
         *   - MAP_ANONYMOUS
         *       Mapping is not associated with any file
         *       However, some implementations require fd to be -1 if MAP_ANONYMOUS
         *       (or MAP_ANON) is specified, and fd should always be -1
         *       for applications requiring portability.
         *   - MAP_NORESERVE
         *       No swap space is reserved for this mapping
         * * fd / offset
         *     The contents of the file mapping are initialized with length bytes of data
         *     starting at offset of the file (or other object)
         *     referenced by file descriptor fd.
         *     Now, MAP_ANONYMOUS is used, so fd=-1 and offset=0 to be set.
         */
        libc::mmap(
            std::ptr::null_mut(), // null mutable raw pointer (= NULL)
            guarded_size, // desired size + guarded pages
            libc::PROT_NONE, // PORT_NONE (inhibit memory access)
            libc::MAP_ANONYMOUS | libc::MAP_PRIVATE | libc::MAP_NORESERVE,
            -1,
            0,
        )
    };
    if guard_addr == libc::MAP_FAILED {
        return Err(MmapRegionError::Mmap(std::io::Error::last_os_error()));
    }

    let (fd, offset) = match maybe_file_offset {
        // maybe_file_offset: Option<FileOffset>
        Some(ref file_offset) => {
            check_file_offset(file_offset, size)?;
            (file_offset.file().as_raw_fd(), file_offset.start())
        }
        None => (-1, 0),
    };

    let region_start_addr = guard_addr as usize + page_size * GUARD_PAGE_COUNT;
    let region_addr = unsafe {
        /* Re mmap inside pre protected range
         * mmap(addr, size, prot, flags, fd, offset)
         * addr : starting address to try to map memory
         * prot : PROT_READ | PROT_WRITE
         * flags : describe bellow
         * fd : FileOption's file descriptor
         * offset : starting point of 'File'
         *
         * Strategy: create_guest_memry -> create_memory
         *   - if Option<FileOffset> is ...
         *     Some(_) => flags = MAP_NORESERVE | MAP_PRIVATE
         *     None    => flags = MAP_NORESERVE | MAP_PRIVATE | MAP_ANONYMOUS
         *   and then using above 'flags' variable and
         *     flags | MAP_FIXED
         *   where
         *     MAP_FIXED
         *       Instead of using addr as an address hint, the mapping is placed using the address specified by addr as is.
         *       addr must be a multiple of the page size.
         *       If the memory area specified by addr and len overlaps with a page of an existing mapping,
         *       the overlapping portion of the existing mapping is discarded.
         *       If the specified address is not available, mmap() fails.
         *       It is recommended that this option not be used, since requiring a fixed address for a mapping is not portable.
         *
         * and then, fd, offset is specified, so map fd's data from offset to pre allocated range (start from region_start_addr)
         */
        libc::mmap(
            region_start_addr as *mut libc::c_void,
            size,
            prot,
            flags | libc::MAP_FIXED,
            fd,
            offset as libc::off_t,
        )
    };
    let bitmap = match track_dirty_pages {
        true => Some(AtomicBitmap::with_len(size)),
        false => None,
    };
    unsafe {
        MmapRegionBuilder::new_with_bitmap(size, bitmap)
            .with_raw_mmap_pointer(region_addr as *mut u8)
            .with_mmap_prot(prot)
            .with_mmap_flags(flags)
            .build()
    }
}

pub fn create_guest_memory(
    regions: &[(Option<FileOffset>, GuestAddress, usize)],
    track_dirty_pages: bool,
) -> std::result::Result<GuestMemoryMmap, Error> {
    let prot = libc::PROT_READ | libc::PROT_WRITE;
    let mut mmap_regions = Vec::with_capacity(regions.len());

    for region in regions {
        let flags = match region.0 {
            None => libc::MAP_NORESERVE | libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            Some(_) => libc::MAP_NORESERVE | libc::MAP_PRIVATE,
        };

        let mmap_region = create_region(region.0.clone(), region.2, prot, flags, track_dirty_pages)
            .map_err(Error::MmapRegion)?;
        mmap_regions.push(GuestRegionMmap::new(mmap_region, region.1)?);
    }
    GuestMemoryMmap::from_regions(mmap_regions)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_create_region() {
        use vmm_sys_util::tempfile::TempFile;
        {
            let page_size = get_page_size().unwrap();
            let size = page_size * 10;
            let prot = libc::PROT_READ | libc::PROT_WRITE;
            let flags = libc::MAP_ANONYMOUS | libc::MAP_NORESERVE | libc::MAP_PRIVATE;
            let region = create_region(None, size, prot, flags, false).unwrap();

            assert_eq!(region.size(), size);
            assert!(region.file_offset().is_none());
            assert_eq!(region.prot(), prot);
            assert_eq!(region.flags(), flags);
        }
        {
            let file = TempFile::new().unwrap().into_file();
            let page_size = get_page_size().unwrap();
            let prot = libc::PROT_READ | libc::PROT_WRITE;
            let flags = libc::MAP_NORESERVE | libc::MAP_PRIVATE;
            let offset = 0;
            let size = 10 * page_size;
            /* ftruncate
             * https://nxmnpg.lemoda.net/ja/2/ftruncate
             * now, use it to expand data of TempFile to specified size as null value
             */
            assert_eq!(unsafe { libc::ftruncate(file.as_raw_fd(), 4096 * 10) }, 0);
            let region = create_region(
                Some(FileOffset::new(file, offset)),
                size,
                prot,
                flags,
                false,
            ).unwrap();
            println!("region = {:?}", region);
            assert_eq!(region.size(), size);
            assert_eq!(region.prot(), prot);
            assert_eq!(region.flags(), flags);
        }
    }

    #[test]
    fn test_create_guest_memory() {
        let region_size = 0x10000;
        let regions = vec![
            (None, GuestAddress(0x0), region_size),
            (None, GuestAddress(0x10000), region_size),
            (None, GuestAddress(0x20000), region_size),
            (None, GuestAddress(0x30000), region_size),
        ];
        let guest_memory = create_guest_memory(&regions, false).unwrap();
        println!("guest_memory = {:?}", guest_memory);
    }
}
