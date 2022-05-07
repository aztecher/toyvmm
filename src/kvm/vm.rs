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
    CpuId,
    kvm_pit_config,
    kvm_userspace_memory_region,
    KVM_MEM_LOG_DIRTY_PAGES,
    KVM_MAX_CPUID_ENTRIES,
    KVM_PIT_SPEAKER_DUMMY,
};
use vm_memory::{Address, GuestAddress, GuestMemory, GuestMemoryRegion};
use crate::{
    arch,
    kvm::memory::GuestMemoryMmap,
};

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
    // Cannot configure the microvm
    VmSetup(kvm_ioctls::Error),
}

pub struct Vm {
    fd: VmFd,

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    supported_cpuid: CpuId,
}

pub type Result<T> = result::Result<T, Error>;

impl Vm {
    pub fn new(kvm: &Kvm) -> Result<Self> {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        let supported_cpuid = kvm
            .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)
            .map_err(Error::VmFd)?;

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
        Ok(Vm {
            fd: vm_fd,
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            supported_cpuid,
        })
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn supported_cpuid(&self) -> &CpuId {
        &self.supported_cpuid
    }

    #[cfg(target_arch = "x86_64")]
    pub fn setup_irqchip(&self) -> Result<()> {
        self.fd.create_irq_chip().map_err(Error::VmSetup)?;
        let pit_config = kvm_pit_config {
            flags: KVM_PIT_SPEAKER_DUMMY,
            ..Default::default()
        };
        self.fd.create_pit2(pit_config).map_err(Error::VmSetup)
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
        #[cfg(target_arch = "x86_64")]
        self.fd
            .set_tss_address(arch::x86_64::KVM_TSS_ADDRESS as usize)
            .map_err(Error::VmSetup)?;
        Ok(())
    }

    pub fn fd(&self) -> &VmFd {
        &self.fd
    }
}


#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::kvm::memory::tests::create_anon_guest_memory;

    pub(crate) fn setup_vm() -> Vm {
        let kvm = Kvm::new().expect("Failed to open /dev/kvm or unexpected error");
        Vm::new(&kvm).unwrap()
    }

    pub(crate) fn setup_vm_with_mem(mem_size: usize) ->(Vm, GuestMemoryMmap) {
        let kvm = Kvm::new().expect("Faled to open /dev/kvm or unexpected error");
        let gm = create_anon_guest_memory(&[(GuestAddress(0), mem_size)], false)
            .unwrap();
        let mut vm = Vm::new(&kvm).expect("Cannot create new vm");
        (vm, gm)
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
