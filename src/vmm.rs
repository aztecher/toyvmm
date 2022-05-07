use crate::kvm::{
    vm::{Vm, Error as VmError},
    vcpu::Vcpu,
    memory::GuestMemoryMmap,
};

#[derive(Debug)]
pub enum Error {
    KernelFile(std::io::Error),
    Vm(VmError),
}

pub type Result<T> = std::result::Result<T, Error>;

pub struct Vmm {
    pub vm: Vm,
    pub guest_memory: GuestMemoryMmap,
}

impl Vmm {
    pub fn start_vcpus(
        &mut self,
        mut vcpus: Vec<Vcpu>,
    ) -> Result<()> {
        let vcpu_count = vcpus.len();
        // for mut vcpu in vcpus.drain(..) {
        //     // #[cfg(target_arch = "x86_64")]
        // }
        Ok(())
    }

    pub fn guest_memory(&self) -> &GuestMemoryMmap {
        &self.guest_memory
    }
}
