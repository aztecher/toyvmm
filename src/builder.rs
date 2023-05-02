use linux_loader::{
    cmdline::Cmdline,
    loader::{
        load_cmdline,
        KernelLoader,
        elf::Elf as Loader,
    }
};
use ::epoll as ep;
use linux_loader::cmdline::Cmdline as LoaderKernelCmdline;
use vm_memory::{Bytes, GuestAddress};
use vmm_sys_util::eventfd::EventFd;
use vm_superio::serial;
use std::{
    net::Ipv4Addr,
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    sync::{
        Arc, Barrier, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    os::unix::io::AsRawFd,
};
use crate::{
    vm_resources,
    vm_control::VmResponse,
    arch,
    device_manager::DeviceManager,
    devices::{
        epoll,
        bus::Bus as IoBus,
        legacy::{
            EventFdTrigger,
            serial::{SerialEventsWrapper, SerialDevice},
        },
        virtio::net::Net,
    },
    vmm::{Error, Vmm},
    kvm::{
        vm::Vm,
        vcpu::{VcpuConfig, Vcpu},
        vcpu::Error as VcpuError,
        memory,
    },
};
use kvm_ioctls::{Kvm, VcpuExit};

#[derive(Debug)]
pub enum StartVmError {
    ConfigureSystem(arch::Error),
    KernelCmdline(String),
    KernelLoader(linux_loader::loader::Error),
    GuestMemoryMmap(vm_memory::Error),
    InvalidCmdline,
    InitrdLoad,
    InitrdRead(io::Error),
    Internal(Error),
    LoadCommandline(linux_loader::loader::Error),
    MissingKernelConfig,
    Vm,
    VcpuCreate,
    VcpuConfigure(VcpuError)
}

pub struct InitrdConfig {
    pub address: GuestAddress,
    pub size: usize,
}

fn create_serial(com_event: EventFdTrigger) -> Arc<Mutex<SerialDevice>> {
    let serial_device = Arc::new(Mutex::new(SerialDevice {
        serial: serial::Serial::with_events(
            com_event.try_clone().unwrap(),
            SerialEventsWrapper { buffer_read_event_fd: None },
            Box::new(std::io::sink()),
        ),
    }));
    serial_device
}

pub fn boot_kernel(
    kernel_file: &mut File,
    initrd_file: &mut Option<File>,
    boot_cmdline: &mut Cmdline,
) {
    // let mem_size_mib = 128; // MiB
    // let mem_size_mib = 256; // MiB
    let mem_size_mib = 2048; // MiB
    let track_dirty_page = false;
    let kvm = Kvm::new().expect("Failed to open /dev/kvm");
    let mut vm = Vm::new(&kvm).expect("Failed to create vm");
    let mut kvm_cpuid = vm.supported_cpuid().clone();
    vm.setup_irqchip().unwrap();
    let guest_memory = create_guest_memory(
        mem_size_mib,
        track_dirty_page,
    ).unwrap();
    vm.memory_init(&guest_memory, kvm.get_nr_memslots(), track_dirty_page).unwrap();

    // DeviceManager for virtio mmio device
    let exit_evt = EventFd::new(libc::EFD_NONBLOCK).unwrap();
    let mut epoll_context = epoll::EpollContext::new(exit_evt.as_raw_fd()).unwrap();
    let mut device_manager = DeviceManager::new(guest_memory.clone(), 0x1000, arch::MMIO_MEM_START, 5);
    // let mut device_manager = DeviceManager::new(guest_memory.clone(), 0x10000000, arch::MMIO_MEM_START, 5);
    let epoll_config = epoll_context.allocate_virtio_net_tokens();
    let net = Box::new(Net::new(
        Ipv4Addr::new(192, 168, 0, 10),
        Ipv4Addr::new(255, 255, 255, 0),
        epoll_config,
    ).unwrap());
    device_manager.register_mmio(net, boot_cmdline).unwrap();
    for request in device_manager.vm_requests {
        if let VmResponse::Err(e) = request.execute(vm.fd()) {
            println!("error vm response : {}", e);
            return;
        }
        // if let VmResponse::Err(e) = request.execute(vm.fd()) {
        //     return e
        // }
    }
    let mmio_bus = device_manager.bus.clone();

    let kernel_entry = Loader::load::<File, memory::GuestMemoryMmap>(
        &guest_memory,
        None,
        kernel_file,
        Some(vm_memory::GuestAddress(arch::x86_64::get_kernel_start())),
    ).unwrap();
    let initrd = Some(load_initrd(
        &guest_memory,
        initrd_file.as_mut().unwrap(),
    ).unwrap());

    load_cmdline::<memory::GuestMemoryMmap>(
        &guest_memory,
        GuestAddress(arch::x86_64::CMDLINE_START),
        &boot_cmdline,
    ).unwrap();
    let entry_addr = kernel_entry.kernel_load;
    arch::x86_64::configure_system(
        &guest_memory,
        GuestAddress(arch::x86_64::CMDLINE_START),
        boot_cmdline.as_str().len() + 1,
        &initrd,
        1,
    ).unwrap();

    // serial device
    let mut io_bus = IoBus::new();
    let com_evt_1_3 = EventFdTrigger::new(EventFd::new(libc::EFD_NONBLOCK).unwrap());
    let com_evt_2_4 = EventFdTrigger::new(EventFd::new(libc::EFD_NONBLOCK).unwrap());
    // let exit_evt = EventFd::new(libc::EFD_NONBLOCK).unwrap();
    let stdio_serial = Arc::new(Mutex::new(SerialDevice {
        serial: serial::Serial::with_events(
            com_evt_1_3.try_clone().unwrap(),
            SerialEventsWrapper { buffer_read_event_fd: None },
            Box::new(std::io::stdout()),
        ),
    }));
    let serial_1_3 = create_serial(com_evt_1_3.try_clone().unwrap());
    let serial_2_4 = create_serial(com_evt_2_4.try_clone().unwrap());
    io_bus.insert(stdio_serial.clone(), 0x3f8, 0x8).unwrap();
    io_bus.insert(serial_2_4.clone(), 0x2f8, 0x8).unwrap();
    io_bus.insert(serial_1_3.clone(), 0x3e8, 0x8).unwrap();
    io_bus.insert(serial_2_4, 0x2e8, 0x8).unwrap();
    vm.fd().register_irqfd(&com_evt_1_3, 4).unwrap();
    vm.fd().register_irqfd(&com_evt_2_4, 3).unwrap();

    let id = 0;
    let num_cpus = 1;
    let vcpu_thread_barrier = Arc::new(Barrier::new(num_cpus + 1));
    let kill_signaled = Arc::new(AtomicBool::new(false));

    let mut vcpu = Vcpu::new(id, &vm).expect("Failed to create vcpu 0");
    let mut vcpu_handles = Vec::with_capacity(num_cpus as usize);
    vcpu.configure(
        &guest_memory,
        entry_addr,
        id as u64,
        num_cpus as u64,
        &mut kvm_cpuid,
    ).unwrap();

    let barrier = vcpu_thread_barrier.clone();
    let vcpu_exit_evt = exit_evt.try_clone().unwrap();
    vcpu_handles.push(std::thread::Builder::new()
        .name(String::from("vcpu_0"))
        .spawn(move || {
            barrier.wait();
            loop {
                match vcpu.run() {
                    Ok(run) => {
                        match run {
                            VcpuExit::IoIn(addr, data) => {
                                io_bus.read(addr as u64, data);
                            }
                            VcpuExit::IoOut(addr, data) => {
                                io_bus.write(addr as u64, data);
                            }
                            VcpuExit::MmioRead(addr, data) => {
                                mmio_bus.read(addr, data);
                            },
                            VcpuExit::MmioWrite(addr, data) => {
                                mmio_bus.write(addr, data);
                            }
                            VcpuExit::Hlt => {
                                break;
                            }
                            VcpuExit::Shutdown => {
                                break;
                            }
                            _ => {
                                println!("unexpected exit reason");
                                break;
                           }
                        }
                    }
                    Err(e) => {
                        println!("vcpu hit unknown error: {:?}", e);
                        break;
                    }
                }
                if kill_signaled.load(Ordering::SeqCst) {
                    break;
                }
            }
            vcpu_exit_evt.write(1).expect("failed to signal vcpu exit eventfd");
        }).unwrap()
    );

    // run vcpu threads!
    vcpu_thread_barrier.wait();

    use vmm_sys_util::{
        poll::{PollToken, PollContext, PollEvents},
        terminal::Terminal,
    };
    #[derive(Debug, Clone, Copy)]
    enum Token {
        Exit,
        Stdin,
    }
    impl PollToken for Token {
        fn as_raw_token(&self) -> u64 {
            match *self {
                Token::Exit => 0,
                _ => 1,
            }
        }
        fn from_raw_token(data: u64) -> Self {
            match data {
                0 => Token::Exit,
                _ => Token::Stdin,
            }
        }
    }

    let stdin_handle = io::stdin();
    let stdin_lock = stdin_handle.lock();
    stdin_lock.set_raw_mode().expect("failed to set terminal raw mode");
    defer! {{
        if let Err(e) = stdin_lock.set_canon_mode() {
            println!("cannot set canon mode for stdin: {:?}", e);
        }
    }};

    const EPOLL_EVENT_LEN: usize = 100;
    let mut events = Vec::<ep::Event>::with_capacity(EPOLL_EVENT_LEN);
    // Safe as we pass to set_len the value passed to with_capacity
    unsafe { events.set_len(EPOLL_EVENT_LEN) };
    let epoll_raw_fd = epoll_context.epoll_raw_fd;
    'poll: loop {
        let num_events = ep::wait(
            epoll_raw_fd,
            -1,
            &mut events[..],
        ).unwrap();
        for i in 0..num_events {
            let dispatch_idx = events[i].data() as usize;
            let dispatch_type = epoll_context.dispatch_table[dispatch_idx];
            match dispatch_type {
                epoll::EpollDispatch::Exit => {
                    break 'poll
                }
                epoll::EpollDispatch::Stdin => {
                    let mut out = [0u8; 64];
                    match stdin_lock.read_raw(&mut out[..]) {
                        Ok(0) => {
                            // Zero-length read indicates EOF. Remove from pollable
                            ep::ctl(
                                epoll_raw_fd,
                                ep::EPOLL_CTL_DEL,
                                libc::STDIN_FILENO,
                                events[i],
                            ).unwrap();
                        }
                        Ok(count) => {
                            stdio_serial
                                .lock()
                                .unwrap()
                                .serial
                                .enqueue_raw_bytes(&out[..count])
                                .expect("failed to enqueue bytes");
                        }
                        Err(e) => {
                            println!("error while reading stdin: {:?}", e);
                        }
                    }
                }
                epoll::EpollDispatch::DeviceHandler(device_idx, device_token) => {
                    let handler = epoll_context.get_device_handler(device_idx);
                    handler.handle_event(device_token, events[i].events().bits());
                }
            }
        }
    }

    // wait for stopping all threads
    for handle in vcpu_handles {
        if let Err(e) = handle.join() {
            println!("failed to join vcpu thread: {:?}", e);
        }
    }
}

pub fn build(
    vm_resources: &vm_resources::VmResources,
) -> std::result::Result<(Vmm, Vec<Vcpu>), StartVmError> {
    use self::StartVmError::*;

    let boot_config = vm_resources.boot_source().ok_or(MissingKernelConfig)?;
    let track_dirty_page = vm_resources.track_dirty_pages();
    let guest_memory = create_guest_memory(
        vm_resources.vm_config().mem_size_mib,
        track_dirty_page,
    )?;
    let vcpu_config = vm_resources.vcpu_config();
    let entry_addr = load_kernel(boot_config, &guest_memory)?;
    let initrd = load_initrd_from_config(boot_config, &guest_memory)?;
    let mut boot_cmdline = linux_loader::cmdline::Cmdline::new(arch::CMDLINE_MAX_SIZE);

    let (mut vmm, mut vcpus) = create_vmm_and_vcpus(
        guest_memory,
        track_dirty_page,
        vcpu_config.vcpu_count,
    )?;

    let init_and_regular = boot_config
        .cmdline
        .as_str()
        .split("--")
        .collect::<Vec<&str>>();
    if init_and_regular.len() > 2 {
        return Err(StartVmError::KernelCmdline(
                "Too many `--` in kernel cmdline.".to_string(),
        ));
    }
    let boot_args = init_and_regular[0];
    // let init_params = init_and_regular.get(1);
    boot_cmdline
        .insert_str(boot_args)
        .map_err(|_| StartVmError::InvalidCmdline);

    configure_system_for_boot(
        &vmm,
        vcpus.as_mut(),
        vcpu_config,
        entry_addr,
        &initrd,
        boot_cmdline,
    )?;

    // vmm.start_vcpus(vcpus).map_err(Internal)?;
    Ok((vmm, vcpus))
}

pub fn load_kernel(
    boot_config: &vm_resources::BootConfig,
    guest_memory: &memory::GuestMemoryMmap,
) -> std::result::Result<GuestAddress, StartVmError> {
    let mut kernel_file = boot_config
        .kernel_file
        .try_clone()
        .map_err(|e| StartVmError::Internal(Error::KernelFile(e)))?;
    /* Loader::load<F, M: GuestMemory>(...) where F: Read + Seek
     *  - load kernel from a vmlinux elf image into guest memory
     *
     * Arguments
     * 1. guest memory to load the kernel in
     * 2. offset to be added to default kernel load address in guest memory
     * 3. input vmlinux image
     * 4. address where hight memory starts
     *
     * Return
     *  - linux_loader::KernelLoaderResult that includes
     *    - kernel_load:  GuestAddress
     *    - kernel_end:   GuestUsize
     *    - setup_header: Option<bootparam::setup_header>
     *    - pvh_boot_cap: elf::PvhBootCapability
     *
     * TODO: Explain Loader::load
     */
    let entry_addr = Loader::load::<File, memory::GuestMemoryMmap>(
        guest_memory,
        None,
        &mut kernel_file,
        Some(GuestAddress(arch::x86_64::get_kernel_start())),
    ).map_err(StartVmError::KernelLoader)?;
    // let entry_addr = Loader::load::<File, memory::GuestMemoryMmap>(
    //     guest_memory,
    //     Some(GuestAddress(arch::x86_64::get_kernel_start())),
    //     &mut kernel_file,
    //     None,
    // ).map_err(StartVmError::KernelLoader)?;
    Ok(entry_addr.kernel_load)
}

fn load_initrd_from_config(
    boot_cfg: &vm_resources::BootConfig,
    vm_memory: &memory::GuestMemoryMmap,
) -> std::result::Result<Option<InitrdConfig>, StartVmError> {
    use self::StartVmError::InitrdRead;

    Ok(match &boot_cfg.initrd_file {
        Some(f) => Some(load_initrd(
            vm_memory,
            &mut f.try_clone().map_err(InitrdRead)?,
        )?),
        None => None,
    })
}

fn load_initrd<F>(
    vm_memory: &memory::GuestMemoryMmap,
    image: &mut F,
) -> std::result::Result<InitrdConfig, StartVmError>
where F: Read + Seek {
    let size: usize;
    // Get image size
    match image.seek(SeekFrom::End(0)) {
        Err(e) => return Err(StartVmError::InitrdRead(e)),
        Ok(0) => {
            return Err(StartVmError::InitrdRead(io::Error::new(
                io::ErrorKind::InvalidData,
                "Initrd image seek returned a size of zero",
            )))
        }
        Ok(s) => size = s as usize,
    };
    // Go back to the image start
    image.seek(SeekFrom::Start(0)).map_err(StartVmError::InitrdRead)?;
    // Get the target address
    let address = arch::initrd_load_addr(vm_memory, size)
        .map_err(|_| StartVmError::InitrdLoad)?;

    // Load the image into memory
    //   - read_from is defined as trait methods of Bytes<A>
    //     and GuestMemoryMmap implements this trait.
    // TODO: Explain arch::initrd_load_addr's return address is used in read_from ?
    vm_memory
        .read_from(GuestAddress(address), image, size)
        .map_err(|_| StartVmError::InitrdLoad)?;

    Ok(InitrdConfig{
        address: GuestAddress(address),
        size,
    })
}

fn create_vmm_and_vcpus(
    guest_memory: memory::GuestMemoryMmap,
    track_dirty_pages: bool,
    num_vcpus: u8,
) -> std::result::Result<(Vmm, Vec<Vcpu>), StartVmError> {
    // setup kvm & vm
    let kvm = Kvm::new().expect("Failed to open /dev/kvm or unexpected error");
    let mut vm = Vm::new(&kvm).expect("Failed to setup vm");
    vm.memory_init(&guest_memory, kvm.get_nr_memslots(), track_dirty_pages)
        .map_err(|_| StartVmError::Vm)?;

    #[cfg(target_arch = "x86_64")]
    vm.setup_irqchip()
        .map_err(Error::Vm)
        .map_err(StartVmError::Internal)?;

    // setup vcpu
    let mut vcpus = Vec::with_capacity(num_vcpus as usize);
    for cpu_id in 0..num_vcpus {
        let vcpu = Vcpu::new(cpu_id, &vm).map_err(|_| StartVmError::VcpuCreate)?;
        vcpus.push(vcpu);
    }
    let vmm = Vmm { vm, guest_memory };
    Ok((vmm, vcpus))
}

pub fn create_guest_memory(
    mem_size_mib: usize,
    track_dirty_pages: bool,
) -> std::result::Result<memory::GuestMemoryMmap, StartVmError> {
    let mem_size = mem_size_mib << 20;
    let arch_mem_regions = arch::arch_memory_regions(mem_size);

    memory::create_guest_memory(
        &arch_mem_regions
            .iter()
            .map(|(addr, size)| (None, *addr, *size))
            .collect::<Vec<_>>()[..],
        track_dirty_pages,
    ).map_err(StartVmError::GuestMemoryMmap)
}

fn configure_system_for_boot(
    vmm: &Vmm,
    vcpus: &mut [Vcpu],
    vcpu_config: VcpuConfig,
    entry_addr: GuestAddress,
    initrd: &Option<InitrdConfig>,
    boot_cmdline: LoaderKernelCmdline,
) -> std::result::Result<(), StartVmError> {
    use self::StartVmError::*;
    #[cfg(target_arch = "x86_64")]
    {
        // for vcpu in vcpus.iter_mut() {
        //     vcpu.configure(
        //         vmm.guest_memory(),
        //         entry_addr,
        //         vmm.vm.supported_cpuid().clone(),
        //     )
        //     .map_err(VcpuConfigure)?;
        // }

        // Write the kernel command line to guest memory
        // This is x86_64 specific
        linux_loader::loader::load_cmdline::<memory::GuestMemoryMmap>(
            vmm.guest_memory(),
            GuestAddress(arch::x86_64::CMDLINE_START),
            &boot_cmdline,
        ).map_err(LoadCommandline)?;
        arch::x86_64::configure_system(
            &vmm.guest_memory,
            GuestAddress(arch::x86_64::CMDLINE_START),
            boot_cmdline.as_str().len() + 1,
            initrd,
            vcpus.len() as u8,
        ).map_err(ConfigureSystem)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
}
