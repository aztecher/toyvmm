use kvm_ioctls::Kvm;
use kvm_bindings::kvm_regs;
use vm_memory::{FileOffset, GuestAddress};
use std::{
    io::Write,
    os::unix::io::AsRawFd,
};
use toyvmm::kvm::{
    vm::Vm,
    vcpu::Vcpu,
    memory::{
        GuestRegionMmap,
        GuestMemoryMmap,
        create_region,
    },
};
use vmm_sys_util::tempfile::TempFile;

fn main() {
    let kvm = Kvm::new().expect("Failed to open /dev/kvm or unexpected error");
    let mut vm = Vm::new(&kvm).expect("Failed to setup vm");

    // setup userspace code
    let mut file = TempFile::new().unwrap().into_file();
    assert_eq!(unsafe { libc::ftruncate(file.as_raw_fd(), 4096 * 10) }, 0);
    let code: &[u8] = &[
        0xba, 0xf8, 0x03, /* mov $0x3f8, %dx */
        0x00, 0xd8, /* add %bl, %al */
        0x04, b'0', /* add $'0', %al */
        0xee, /* out %al, %dx */
        0xb0, b'\n', /* mov $'\n', %al */
        0xee, /* out %al, %dx */
        0xf4, /* hlt */
    ];
    file.write_all(code).expect("Failed to write code to tempfile");
    let mut mmap_regions = Vec::with_capacity(1);
    let region = create_region(
        Some(FileOffset::new(file, 0)),
        0x1000,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_NORESERVE | libc::MAP_PRIVATE,
        false,
    ).unwrap();
    mmap_regions.push(GuestRegionMmap::new(region, GuestAddress(0x1000)).unwrap());
    let guest_memory = GuestMemoryMmap::from_regions(mmap_regions).unwrap();
    let track_dirty_page = false;
    vm.memory_init(&guest_memory, kvm.get_nr_memslots(), track_dirty_page).unwrap();

    let vcpu = Vcpu::new(0, &vm).expect("Failed to create vcpu 0");

    // setup segument register
    let mut sregs = vcpu.get_sregs().unwrap();
    sregs.cs.base = 0;
    sregs.cs.selector = 0;
    let mut regs = kvm_regs::default();
    regs.rip = 0x1000;
    regs.rax = 2;
    regs.rbx = 2;
    regs.rflags = 0x2;
    vcpu.set_sregs(&sregs).unwrap();
    vcpu.set_regs(&regs).unwrap();

    loop {
        match vcpu.run().expect("vcpu run failed") {
            kvm_ioctls::VcpuExit::IoOut(addr, data) => {
                println!(
                    "Recieved I/O out exit. \
                    Address: {:#x}, Data(hex): {:#x}",
                    addr, data[0],
                );
            },
            kvm_ioctls::VcpuExit::Hlt => {
                break;
            }
            exit => panic!("unexpected exit reason: {:?}", exit),
        }
    }
}
