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
use clap::{Arg, App};
use nix::unistd::getuid;

const _ZERO_PAGE_START: u64 = 0x7000;

const DEFAULT_VMLINUX_PATH: &str = "vmlinux.bin";
const DEFAULT_CMDLINE_ARGS: &str = "console=ttyS0 noapic noacpi reboot=k panic=1 pci=off nomodule";

fn main() {
    let app = App::new("ToyVMM is a hypervisor for learning virtualization technology")
        .version("0.0.1")
        .author("aztecher <mikiyaf.business@gmail.com>")
        .subcommand(App::new("lwn_sample")
            .about("example of LWN article sample"))
        .subcommand(App::new("boot_kernel")
            .about("example of booting linux kernel (custom)")
            .arg(Arg::new("kernel-file")
                .short('k')
                .value_name("FILE"))
            .arg(Arg::new("initrd-file")
                .short('i')
                .value_name("FILE"))
            .arg(Arg::new("boot-cmdline")
                .short('c')
                .value_name("BOOT_CMD_LINE")))
        .get_matches();

    let verify_root = || if !getuid().is_root() {
        println!("Only root user can run this command");
        std::process::exit(1);
    };

    if let Some(ref _matches) = app.subcommand_matches("lwn_sample") {
        verify_root();
        lwn_kvm_api_sample();
    }
    if let Some(ref matches) = app.subcommand_matches("boot_kernel") {
        verify_root();
        let kernel_image_path = match matches.value_of("kernel-file") {
            Some(p) => p,
            None => DEFAULT_VMLINUX_PATH,
        };
        let mut kernel_file = std::fs::File::open(kernel_image_path).unwrap();
        let boot_args = match matches.value_of("boot-cmdline") {
            Some(cmd) => cmd,
            None => DEFAULT_CMDLINE_ARGS,
        };
        let mut initrd_file = match matches.value_of("initrd-file") {
            Some(p) => {
                let initrd_file = std::fs::File::open(p).unwrap();
                Some(initrd_file)
            }
            None => None,
        };
        let mut boot_cmdline = linux_loader::cmdline::Cmdline::new(0x10000);
        boot_cmdline.insert_str(boot_args).unwrap();
        toyvmm::builder::boot_kernel(&mut kernel_file, &mut initrd_file, &mut boot_cmdline)
    }
}

fn lwn_kvm_api_sample() {
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
