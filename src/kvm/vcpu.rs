use std::{
    result,
    os::unix::io::AsRawFd,
};
use kvm_bindings::{kvm_sregs, kvm_regs};
use kvm_ioctls::{
    Kvm,
    VcpuFd,
    VcpuExit,
};
use vm_memory::MmapRegion;
use crate::{
    kvm::vm::Vm,
    utils::memory,
};

#[derive(Debug)]
pub enum Error {
    // Vcpu Errors
    VcpuFd(kvm_ioctls::Error),
    // VcpuMmapSize
    VcpuMmapSize(kvm_ioctls::Error),
    VcpuMmapError(memory::Error),
    VcpuGetSregs(kvm_ioctls::Error),
    VcpuSetSregs(kvm_ioctls::Error),
    VcpuSetRegs(kvm_ioctls::Error),
    VcpuRun(kvm_ioctls::Error),
}

type Result<T> = result::Result<T, Error>;

pub struct Vcpu {
    fd: VcpuFd
}

impl Vcpu {
    pub fn new(index: u8, vm: &Vm) -> Result<Self> {
        /* vmfd.create_vcpu() : Create Vcpu fd using KVM
         * file descriptior : vmfd (from /dev/kvm)
         *
         * execute bellow instruction
         * > ioctl(fd, KVM_CREATE_VCPU, index)
         *   - index represents the vcpu id that is created
         *
         * Example:
         *   let kvm = Kvm::new().unwrap()
         *   let vm = kvm.create_vm().unwrap()
         *   // Create one vCPU with the ID=0
         *   let vcpu = vm.create_vcpu(0)
         */
        let vcpu = vm.fd().create_vcpu(index.into()).map_err(Error::VcpuFd)?;
        Ok (Vcpu { fd: vcpu })
    }

    pub fn setup_kvm_run(&self, kvm: &Kvm) -> Result<MmapRegion>{
        /* This function acts bellow operation
         *
         * 1. Get vCPU mmap size info from KVM
         * > ioctl(fd, KVM_GET_VCPU_MMAP_SIZE, NULL)
         *
         * 2. Map kvm_run structure (that is created at KVM_CREATE_VCPU in host kernel)
         *    into VM process memory (host process's virtual memory address)
         *    using mmap
         * > mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, vcpufd, 0)
         *
         * and return the MmapRegion value that wrap libc::mmap result
         */
        let mmap_size = kvm.get_vcpu_mmap_size().map_err(Error::VcpuMmapSize)?;
        let kvm_run = memory::mmap(mmap_size, self.fd.as_raw_fd(), 0).map_err(Error::VcpuMmapError)?;
        Ok(kvm_run)
    }

    pub fn get_sregs(&self) -> Result<kvm_sregs> {
        self.fd.get_sregs().map_err(Error::VcpuGetSregs)
    }

    pub fn set_sregs(&self, sregs: &kvm_sregs) -> Result<()> {
        self.fd.set_sregs(sregs).map_err(Error::VcpuSetSregs)
    }

    pub fn set_regs(&self, regs: &kvm_regs) -> Result<()> {
        self.fd.set_regs(regs).map_err(Error::VcpuSetRegs)
    }

    pub fn run(&self) -> Result<VcpuExit>{
        self.fd.run().map_err(Error::VcpuRun)
    }

    pub fn fd(&self) -> &VcpuFd{
        return &self.fd
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::kvm::vm::tests::setup_vm;

    #[test]
    fn test_new() {
        let vm = setup_vm();
        assert!(Vcpu::new(0, &vm).is_ok())
    }

    // #[test]
    // fn test_setup_vcpu_memory() {
    //     let kvm = Kvm::new().expected("Failed to open /dev/kvm or unexpected error");
    //     let vm = Vm::new(&kvm).unwrap();
    //     let vcpu = Vcpu::new(0, &vm).unwrap();
    // }

}
