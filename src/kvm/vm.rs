#[allow(unused_imports)]
use std::{
    os::unix::io::{AsRawFd, FromRawFd, RawFd},
    result,
};
use kvm_ioctls::{
    VmFd,
    Kvm,
};
use kvm_bindings::{
    kvm_userspace_memory_region,
    KVM_MEM_LOG_DIRTY_PAGES,
};
use vm_memory::{Address, GuestMemory, GuestMemoryRegion};
use crate::kvm::memory::GuestMemoryMmap;

#[derive(Debug)]
pub enum Error {
    // KVM Errors
    // Failed to open fd from /dev/kvm
    VmFd(kvm_ioctls::Error),
    // Failed to get mmap size
    VcpuMmapSize(kvm_ioctls::Error),
    // Cannot set memory region
    SetUserMemoryRegion(kvm_ioctls::Error),
    // The number of configured slots is bigger than maximum
    NotEnoughMemorySlots,
}

pub struct Vm {
    fd: VmFd
}

pub type Result<T> = result::Result<T, Error>;

impl Vm {
    pub fn new(kvm: &Kvm) -> Result<Self> {
        /* kvm.create_vm() : create VM fd using KVM of type 0
         * file descriptor : kvm_ioctls::Kvm::kvm.as_raw_fd()
         *   - kvm_ioctls::Kvm::kvm has type std::fs::File
         *
         * execute bellow instruction
         * > ioctl(fd, KVM_CREATE_VM, 0)
         *
         * Example:
         *   let kvm = Kvm::new().unwrap();
         *   let vm = kvm.create_vm() (= kvm.create_vm_with_type(0))
         *
         *   - Kvm::new() open the /dev/kvm file descriptor
         *                and wrap it into Kvm struct
         *
         * file descriptor is automatically closed when dropping.
         */
        let vm_fd = kvm.create_vm().map_err(Error::VmFd)?;
        Ok(Vm {fd: vm_fd})
    }

    pub fn set_kvm_memory_regions(
        &self,
        guest_mem: &GuestMemoryMmap,
        track_dirty_pages: bool,
        ) -> Result<()> {
        /* vmfd.set_user_memory_region() : create/modify guest physical memory slot
         * file descriptior : vmfd
         *
         * execute bellow instrurction
         * > ioctl(vmfd, KVM_SET_USER_MEMORY_REGION(), &use_memory_region)
         *   where
         *     (Example)
         *     let use_memory_region = kvm_userspace_memory_region {
         *         slot: 0,
         *         guest_phys_addr: 0x10000 as u64,
         *         memory_size: 0x10000 as u64,
         *         userspace_addr: 0x0 as u64,
         *         flags: 0,
         *     }
         *
         * Example:
         *   let kvm = Kvm::new().unwrap();
         *   let vm = kvm.create_vm()
         *   let mem_region = kvm_userspace_memory_region {
         *     slot: 0,
         *     guest_phys_addr: 0x10000 as u64,
         *     memory_size: 0x10000 as u64,
         *     userspace_addr: 0x0 as u64,
         *     flags: 0,
         *   };
         *   unsafe {
         *     vm.set_user_memory_region(mem_region).unwrap();
         *   };
         */
        let mut flags = 0u32;
        if track_dirty_pages {
            flags |= KVM_MEM_LOG_DIRTY_PAGES;
        }
        guest_mem
            .iter()
            .enumerate()
            .try_for_each(|(index, region)| {
                let memory_region = kvm_userspace_memory_region {
                    slot: index as u32,
                    guest_phys_addr: region.start_addr().raw_value() as u64,
                    memory_size: region.len() as u64,
                    userspace_addr: guest_mem.get_host_address(region.start_addr()).unwrap() as u64,
                    flags,
                };
                unsafe { self.fd.set_user_memory_region(memory_region) }
            })
        .map_err(Error::SetUserMemoryRegion)?;
        Ok(())
    }

    pub fn memory_init(
        &mut self,
        guest_mem: &GuestMemoryMmap,
        kvm_max_memslots: usize,
        track_dirty_pages: bool,
    ) -> Result<()> {
        if guest_mem.num_regions() > kvm_max_memslots {
            return Err(Error::NotEnoughMemorySlots);
        }
        self.set_kvm_memory_regions(guest_mem, track_dirty_pages)?;
        Ok(())
    }

    pub fn fd(&self) -> &VmFd {
        &self.fd
    }
}


#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn setup_vm() -> Vm {
        let kvm = Kvm::new().expect("Failed to open /dev/kvm or unexpected error");
        Vm::new(&kvm).unwrap()
    }

    #[test]
    fn test_new() {
        // check if fd is not from /dev/kvm then error
        use vmm_sys_util::tempfile::TempFile;
        let vm = Vm::new(
            &unsafe { Kvm::from_raw_fd(TempFile::new().unwrap().as_file().as_raw_fd()) }
        );
        assert!(vm.is_err());

        // check if fd from /dev/kvm is accepted
        let kvm = Kvm::new().expect("Failed to open /dev/kvm or unexpected error");
        assert!(Vm::new(&kvm).is_ok())
    }

    #[test]
    fn test_vcpu_mmap_size() {
        let kvm = Kvm::new().expect("Failed to open /dev/kvm or unexpected error");
        let size = kvm.get_vcpu_mmap_size()
            .expect("Faield to get vcpu mmap size");
        assert_ne!(0, size)
    }
}
