pub mod x86_64;

use crate::{
    arch,
    utils::memory,
    vstate::{memory::GuestMemoryMmap, vcpu::x86_64::KvmVcpuConfigureError, vm::Vm},
};
use kvm_bindings::{kvm_regs, kvm_sregs, CpuId};
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd};
use std::os::unix::io::AsRawFd;
use utils::eventfd::EventFd;
use vm_memory::{GuestAddress, MmapRegion};

/// Errors associated with actions on vcpu.
#[derive(Debug, thiserror::Error)]
pub enum VcpuError {
    /// Cannot open the vcpu file descriptor.
    #[error("{0}")]
    VcpuFd(x86_64::KvmVcpuError),
    /// Failed to get vcpu mmap size.
    #[error("Failed to get vcpu mmap size: {0}")]
    VcpuMmapSize(#[source] kvm_ioctls::Error),
    /// Failed to execute mmap.
    #[error("Memory operation error: {0}")]
    VcpuMmapError(#[source] memory::MemoryError),
    /// Failed to set vcpu id.
    #[error("Failed to set vcpu id: {0}")]
    VcpuSetCpuid(#[source] kvm_ioctls::Error),
    /// Failed to get vcpu special registers.
    #[error("Failed to get vcpu special registers: {0}")]
    VcpuGetSregs(kvm_ioctls::Error),
    /// Failed to set vcpu special registers.
    #[error("Failed to set vcpu special registers: {0}")]
    VcpuSetSregs(kvm_ioctls::Error),
    /// Failed to set vcpu general purpose registers.
    #[error("Failed to set vcpu general purpose registers: {0}")]
    VcpuSetRegs(kvm_ioctls::Error),
    /// Failed to trigger the running of the current vcpu.
    #[error("Failed to trigger the running of the current vcpu: {0}")]
    VcpuRun(kvm_ioctls::Error),
    // FaultyKvmExit(String),
    // UnhandleKvmExit(String),
    // MsrsConfiguration(arch::x86_64::MsrError),
    /// Vcpu registers configuration error.
    #[error("Vcpu registers configuration error: {0}")]
    RegsConfiguration(arch::x86_64::RegError),
    // InterruptConfiguration(arch::x86_64::InterruptError),
    /// KvmVcpu configuration error.
    #[error("Kvm vcpu configuration error: {0}")]
    KvmVcpuConfiguration(KvmVcpuConfigureError),
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum VcpuEmulation {
    Handled,
    Interrupted,
    Stopped,
}

#[derive(Debug, Eq, PartialEq)]
pub struct VcpuConfig {
    pub vcpu_count: u8,
}

pub struct Vcpu {
    /// Access to kvm-arch specific functionality.
    kvm_vcpu: x86_64::KvmVcpu,

    /// File descriptor for vcpu to trigger exit event on vmm.
    pub exit_evt: EventFd,
}

impl Vcpu {
    pub fn new(index: u8, vm: &Vm, exit_evt: EventFd) -> Result<Self, VcpuError> {
        use x86_64::*;
        let kvm_vcpu = KvmVcpu::new(index, vm).map_err(VcpuError::VcpuFd)?;
        Ok(Vcpu { kvm_vcpu, exit_evt })
    }

    pub fn configure(
        &mut self,
        guest_memory: &GuestMemoryMmap,
        kernel_start_addr: GuestAddress,
        id: u64,
        num_cpus: u64,
        cpuid: &mut CpuId,
    ) -> Result<(), VcpuError> {
        self.kvm_vcpu
            .configure(guest_memory, kernel_start_addr, id, num_cpus, cpuid)
            .map_err(VcpuError::KvmVcpuConfiguration)?;

        // arch::x86_64::setup_cpuid(self.fd(), id, num_cpus, cpuid);
        //
        // // arch::x86_64::setup_msrs(&self.fd()).map_err(Error::MsrsConfiguration)?;
        // arch::x86_64::setup_regs(self.fd(), kernel_start_addr.raw_value() as u64)
        //     .map_err(VcpuError::RegsConfiguration)?;
        // // arch::x86_64::setup_fpu(&self.fd()).map_err(Error::RegsConfiguration)?;
        // arch::x86_64::setup_sregs(self.fd(), guest_mem).map_err(VcpuError::RegsConfiguration)?;
        // // arch::x86_64::set_lint(&self.fd()).map_err(Error::InterruptConfiguration)?;
        Ok(())
    }

    pub fn setup_kvm_run(&self, kvm: &Kvm) -> Result<MmapRegion, VcpuError> {
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
        let mmap_size = kvm.get_vcpu_mmap_size().map_err(VcpuError::VcpuMmapSize)?;
        let kvm_run = memory::mmap(mmap_size, self.kvm_vcpu.fd.as_raw_fd(), 0)
            .map_err(VcpuError::VcpuMmapError)?;
        Ok(kvm_run)
    }

    pub fn get_sregs(&self) -> Result<kvm_sregs, VcpuError> {
        self.kvm_vcpu
            .fd
            .get_sregs()
            .map_err(VcpuError::VcpuGetSregs)
    }

    pub fn set_sregs(&self, sregs: &kvm_sregs) -> Result<(), VcpuError> {
        self.kvm_vcpu
            .fd
            .set_sregs(sregs)
            .map_err(VcpuError::VcpuSetSregs)
    }

    pub fn set_regs(&self, regs: &kvm_regs) -> Result<(), VcpuError> {
        self.kvm_vcpu
            .fd
            .set_regs(regs)
            .map_err(VcpuError::VcpuSetRegs)
    }

    pub fn run(&self) -> Result<VcpuExit, VcpuError> {
        self.kvm_vcpu.fd.run().map_err(VcpuError::VcpuRun)
    }

    pub fn fd(&self) -> &VcpuFd {
        &self.kvm_vcpu.fd
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::vstate::memory;
    use ::utils::eventfd::EventFd;

    #[test]
    fn test_vcpu_configure() {
        {
            let mut vm = Vm::new().unwrap();
            let gm =
                memory::create_guest_memory(&[(None, GuestAddress(0), 0x1000)], false).unwrap();
            vm.memory_init(&gm, false).unwrap();
            vm.setup_irqchip().unwrap();
            let mut vcpu = Vcpu::new(0, &vm, EventFd::new(libc::EFD_NONBLOCK).unwrap()).unwrap();
            let mut kvm_cpuid = vm.supported_cpuid().clone();
            assert!(vcpu
                .configure(&gm, GuestAddress(0), 0, 1, &mut kvm_cpuid)
                .is_err());
        }

        {
            let mut vm = Vm::new().unwrap();
            let gm =
                memory::create_guest_memory(&[(None, GuestAddress(0), 128 << 20)], false).unwrap();
            vm.memory_init(&gm, false).unwrap();
            vm.setup_irqchip().unwrap();
            let mut vcpu = Vcpu::new(0, &vm, EventFd::new(libc::EFD_NONBLOCK).unwrap()).unwrap();
            let mut kvm_cpuid = vm.supported_cpuid().clone();
            assert!(vcpu
                .configure(&gm, GuestAddress(0), 0, 1, &mut kvm_cpuid)
                .is_ok());
        }
    }
}
