use std::{
    result,
    os::unix::io::AsRawFd,
};
use kvm_bindings::{CpuId, kvm_sregs, kvm_regs, KVM_SYSTEM_EVENT_RESET, KVM_SYSTEM_EVENT_SHUTDOWN};
use kvm_ioctls::{
    Kvm,
    VcpuFd,
    VcpuExit,
};
use vm_memory::{MmapRegion, GuestAddress, Address};
use vmm_sys_util::errno;
use crate::{
    kvm::{
        vm::Vm,
        memory::GuestMemoryMmap,
    },
    utils::memory,
    arch,
};

#[derive(Debug)]
pub enum Error {
    // Vcpu Errors
    VcpuFd(kvm_ioctls::Error),
    // VcpuMmapSize
    VcpuMmapSize(kvm_ioctls::Error),
    VcpuMmapError(memory::Error),
    VcpuSetCpuid(kvm_ioctls::Error),
    VcpuGetSregs(kvm_ioctls::Error),
    VcpuSetSregs(kvm_ioctls::Error),
    VcpuSetRegs(kvm_ioctls::Error),
    VcpuRun(kvm_ioctls::Error),

    FaultyKvmExit(String),
    UnhandleKvmExit(String),

    MsrsConfiguration(arch::x86_64::MsrError),
    RegsConfiguration(arch::x86_64::RegError),
    InterruptConfiguration(arch::x86_64::InterruptError)
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum VcpuEmulation {
    Handled,
    Interrupted,
    Stopped,
}

type Result<T> = result::Result<T, Error>;

#[derive(Debug, PartialEq)]
pub struct VcpuConfig {
    pub vcpu_count: u8,
}

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

    pub fn configure(
        &mut self,
        guest_mem: &GuestMemoryMmap,
        kernel_start_addr: GuestAddress,
        id: u64,
        num_cpus: u64,
        cpuid: &mut CpuId,
    ) -> Result<()> {
        arch::x86_64::setup_cpuid(self.fd(), id, num_cpus, cpuid);

        // arch::x86_64::setup_msrs(&self.fd()).map_err(Error::MsrsConfiguration)?;
        arch::x86_64::setup_regs(&self.fd(), kernel_start_addr.raw_value() as u64)
            .map_err(Error::RegsConfiguration)?;
        // arch::x86_64::setup_fpu(&self.fd()).map_err(Error::RegsConfiguration)?;
        arch::x86_64::setup_sregs(&self.fd(), guest_mem).map_err(Error::RegsConfiguration)?;
        // arch::x86_64::set_lint(&self.fd()).map_err(Error::InterruptConfiguration)?;
        Ok(())
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

    pub fn run_arch_emulation(&self, exit: VcpuExit) -> Result<VcpuEmulation> {
        let read = |bytes: &[u8]| -> String {
            // String::from_utf8(bytes.to_vec()).unwrap()
            bytes.iter().map(|&s| s as char).collect::<String>()
        };
        match exit {
            VcpuExit::IoIn(addr, data) => {
                println!("IoIn: {}", read(data));
                Ok(VcpuEmulation::Handled)
            }
            VcpuExit::IoOut(addr, data) => {
                println!("IoOut: {}", read(data));
                Ok(VcpuEmulation::Handled)
            }
            unexpected_exit => {
                Err(Error::UnhandleKvmExit(format!("{:?}", unexpected_exit)))
            }
        }
    }

    pub fn emulate(&self) -> std::result::Result<VcpuExit, errno::Error> {
        self.fd.run()
    }

    pub fn run_emulation(&self) -> Result<VcpuEmulation> {
        let read = |bytes: &[u8]| -> String {
            // String::from_utf8(bytes.to_vec()).unwrap()
            bytes.iter().map(|&s| s as char).collect::<String>()
        };
        match self.emulate() {
            Ok(run) => match run {
                VcpuExit::MmioRead(addr, data) => {
                    println!("MmioRead: {}", read(data));
                    Ok(VcpuEmulation::Handled)
                }
                VcpuExit::MmioWrite(addr, data) => {
                    println!("MmioWrite: {}", read(data));
                    Ok(VcpuEmulation::Handled)
                }
                VcpuExit::Hlt => {
                    println!("Hlt");
                    Ok(VcpuEmulation::Stopped)
                }
                VcpuExit::Shutdown => {
                    println!("Shutdown");
                    Ok(VcpuEmulation::Stopped)
                }
                VcpuExit::FailEntry => {
                    // TODO handle failure
                    Err(Error::FaultyKvmExit(format!("{:?}", VcpuExit::FailEntry)))
                }
                VcpuExit::InternalError => {
                    // TODO handle failure
                    Err(Error::FaultyKvmExit(format!("{:?}", VcpuExit::InternalError)))
            }
                VcpuExit::SystemEvent(event_type, event_flags) => match event_type {
                    KVM_SYSTEM_EVENT_RESET | KVM_SYSTEM_EVENT_SHUTDOWN => {
                        // TODO
                        println!("KVM_SYSTEM_EVENT_RESET | KVM_SYSTEM_EVENT_SHUTDOWN");
                        Ok(VcpuEmulation::Stopped)
                    }
                    _ => {
                        // TODO
                        Err(Error::FaultyKvmExit(format!("{:?}", VcpuExit::SystemEvent(event_type, event_flags))))
                    }
                },
                arch_specific_reason => {
                    self.run_arch_emulation(arch_specific_reason)
                }
            },
            Err(ref e) => {
                match e.errno() {
                    libc::EAGAIN => {
                        println!("libc::EAGAIN");
                        Ok(VcpuEmulation::Handled)
                    },
                    libc::EINTR => {
                        // TODO
                        println!("libc::EINTER");
                        Ok(VcpuEmulation::Interrupted)
                    }
                    libc::ENOSYS => {
                        Err(Error::FaultyKvmExit(
                            "Received ENOSYS error because KVM failed to emulate an instruction.".to_string(),
                        ))
                    }
                    _ => {
                        // TODO
                        Err(Error::FaultyKvmExit(format!("{}", e)))
                    }
                }
            }
        }
    }

    pub fn fd(&self) -> &VcpuFd{
        return &self.fd
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::kvm::vm::tests::{setup_vm, setup_vm_with_mem};

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

    // #[test]
    // fn test_run_emulation() {
    //     let (_vm, mut vcpu, _vm_mem) = setup_vcpu(0x1000);
    //     let res = vcpu.run_emulation();
    //     println!("res = {:?}", res);
    //     assert!(res.is_ok());
    //     assert_eq!(res.unwrap(), VcpuEmulation::Stopped);
    // }

    // Auxiliary function being used throughout the tests.
    #[allow(unused_mut)]
    pub(crate) fn setup_vcpu(mem_size: usize) -> (Vm, Vcpu, GuestMemoryMmap) {
        let (mut vm, gm) = setup_vm_with_mem(mem_size);
        let vcpu = Vcpu::new(0, &vm).unwrap();
        (vm, vcpu, gm)
    }
}
