use crate::{
    arch,
    vstate::{memory::GuestMemoryMmap, vm::Vm},
};
use kvm_bindings::CpuId;
use kvm_ioctls::VcpuFd;
use vm_memory::{Address, GuestAddress};

#[derive(Debug, thiserror::Error)]
pub enum KvmVcpuError {
    /// Cannot open the vcpu file descriptor.
    #[error("Cannot open the vcpu file descriptor")]
    VcpuFd(kvm_ioctls::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum KvmVcpuConfigureError {
    /// Vcpu registers configuration error.
    #[error("Vcpu registers configuration error: {0}")]
    RegsConfiguration(arch::x86_64::RegError),
}

/// A wrapper around creating and using a kvm x86_65 vcpu.
#[derive(Debug)]
pub struct KvmVcpu {
    /// KVM vcpu id.
    pub fd: VcpuFd,
}

impl KvmVcpu {
    pub fn new(index: u8, vm: &Vm) -> Result<Self, KvmVcpuError> {
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
        let kvm_vcpu = vm
            .fd()
            .create_vcpu(index.into())
            .map_err(KvmVcpuError::VcpuFd)?;
        Ok(KvmVcpu { fd: kvm_vcpu })
    }

    pub fn configure(
        &mut self,
        guest_memory: &GuestMemoryMmap,
        kernel_start_addr: GuestAddress,
        cpu_idx: u64,
        num_cpus: u64,
        cpuid: &mut CpuId,
    ) -> Result<(), KvmVcpuConfigureError> {
        arch::x86_64::setup_cpuid(&self.fd, cpu_idx, num_cpus, cpuid);
        arch::x86_64::setup_regs(&self.fd, kernel_start_addr.raw_value() as u64)
            .map_err(KvmVcpuConfigureError::RegsConfiguration)?;
        arch::x86_64::setup_sregs(&self.fd, guest_memory)
            .map_err(KvmVcpuConfigureError::RegsConfiguration)?;
        // arch::x86_64::setup_msrs(&self.fd).map_err(KvmVcpuConfigureError::MsrsConfiguration)
        // arch::x86_64::setup_fpu(&self.fd).map_err(KvmVcpuConfigureError::...)
        // arch::x86_64::set_lint(&self.fd).map_err(KvmVcpuConfigureError::InterruptConfiguration)
        Ok(())
    }
}
