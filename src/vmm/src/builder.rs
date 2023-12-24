use crate::{
    arch, cpu,
    device_manager::{
        legacy::PortIoDeviceManager,
        mmio::{MmioDeviceError, MmioDeviceManager},
    },
    devices::{
        epoll,
        legacy::{
            serial::{SerialDevice, SerialEventsWrapper},
            EventFdTrigger,
        },
        virtio::{
            block::{Block, BlockError},
            net::{Net, NetError},
        },
    },
    resources,
    vstate::{
        memory,
        vcpu::{Vcpu, VcpuError},
        vm::Vm,
    },
    Vmm, VmmError,
};
use ::epoll as ep;
use kvm_ioctls::VcpuExit;
use linux_loader::loader::{elf::Elf as Loader, load_cmdline, KernelLoader};
use std::fs::File;

use std::{
    io::{self, Read, Seek, SeekFrom},
    os::unix::io::AsRawFd,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Barrier, Mutex,
    },
};
use utils::eventfd::EventFd;
use vm_memory::{Bytes, GuestAddress};
use vm_superio::serial;

/// Errors associated with starting the instance.
#[derive(Debug, thiserror::Error)]
pub enum StartVmError {
    /// Invalid memory configuration.
    #[error("Invalid memory configuration: {0}")]
    GuestMemoryMmap(vm_memory::Error),
    /// Failed to insert string to cmdline.
    #[error("Failed to insert string to cmdline: {0}")]
    InsertCommandline(linux_loader::cmdline::Error),
    /// Failed to load cmdline
    #[error("Failed to load cmdline: {0}")]
    LoadCommandline(linux_loader::loader::Error),
    /// Cannot load initrd due to an invalid memory configuration.
    #[error("Cannot load initrd due to an invalid memory configuration.")]
    InitrdLoad,
    /// Cannot load initrd due to an invalid image.
    #[error("Cannot load initrd due to an invalid image: {0}")]
    InitrdRead(io::Error),
    /// Internal error occured while starting VM.
    #[error("Internal error occured while starting VM")]
    Internal(VmmError),
    /// Cannot start the VM because the boot-source was not configured.
    #[error("Cannot start vm without boot-source")]
    MissingBootSource,
    /// Cannot load kernel due to invalid memory configuration or invalid kernel image.
    #[error(
        "Cannot load kernel due to invalid memory configuration or invalid kernel image: {}", .0)]
    KernelLoader(linux_loader::loader::Error),
    /// Cannot configure system for boot.
    #[error("System configuration error: {0}")]
    ConfigureSystem(arch::x86_64::ArchError),
    /// Cannot open the block device backing file.
    #[error("Cannot open the block device backing file: {0}")]
    OpenBlockDevice(std::io::Error),
    /// Clould not create a block device.
    #[error("Clould not create a block device: {0}")]
    CreateBlockDevice(BlockError),
    /// Clould not create a net device.
    #[error("Clould not create a net device: {0}")]
    CreateNetDevice(NetError),
    /// Cannot initialize a MMIO Device or add a device to the MMIO Bus or cmdline.
    #[error("Cannot initialize a MMIO Device or add a device to the MMIO Bus or cmdline: {0}")]
    RegisterMmioDevice(MmioDeviceError),
    #[error("Cannot initialize a epoll context for mmio device: {0}")]
    EpollCtx(epoll::EpollContextError),
}

pub struct InitrdConfig {
    pub address: GuestAddress,
    pub size: usize,
}

// TODO: unwrap -> Result<Arc..., XXXError>
pub fn setup_stdio_serial_device() -> Arc<Mutex<SerialDevice>> {
    let interrupt_evt = EventFdTrigger::new(EventFd::new(libc::EFD_NONBLOCK).unwrap());
    Arc::new(Mutex::new(SerialDevice {
        serial: serial::Serial::with_events(
            interrupt_evt.try_clone().unwrap(),
            SerialEventsWrapper {
                buffer_read_event_fd: None,
            },
            Box::new(std::io::stdout()),
        ),
    }))
}

pub fn setup_interrupt_controller(vm: &mut Vm) -> Result<(), StartVmError> {
    vm.setup_irqchip()
        .map_err(VmmError::Vm)
        .map_err(StartVmError::Internal)
}

fn load_kernel(
    vm_resources: &mut resources::VmResources,
    guest_memory: &memory::GuestMemoryMmap,
) -> Result<GuestAddress, StartVmError> {
    let kernel_entry_addr = Loader::load::<File, memory::GuestMemoryMmap>(
        guest_memory,
        None,
        &mut vm_resources.boot_config_mut().kernel_file,
        Some(vm_memory::GuestAddress(arch::x86_64::get_kernel_start())),
    )
    .map_err(StartVmError::KernelLoader)?;
    Ok(kernel_entry_addr.kernel_load)
}

fn load_initrd_from_resource(
    vm_resources: &mut resources::VmResources,
    vm_memory: &memory::GuestMemoryMmap,
) -> Result<Option<InitrdConfig>, StartVmError> {
    Ok(match vm_resources.boot_config_mut().initrd_file.as_mut() {
        Some(f) => Some(load_initrd(vm_memory, f)?),
        None => None,
    })
}

fn load_initrd<F>(
    vm_memory: &memory::GuestMemoryMmap,
    image: &mut F,
) -> std::result::Result<InitrdConfig, StartVmError>
where
    F: Read + Seek,
{
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
    image
        .seek(SeekFrom::Start(0))
        .map_err(StartVmError::InitrdRead)?;
    // Get the target address
    let address =
        arch::x86_64::initrd_load_addr(vm_memory, size).map_err(|_| StartVmError::InitrdLoad)?;

    // Load the image into memory
    //   - read_from is defined as trait methods of Bytes<A>
    //     and GuestMemoryMmap implements this trait.
    // TODO: Explain arch::initrd_load_addr's return address is used in read_from ?
    vm_memory
        .read_from(GuestAddress(address), image, size)
        .map_err(|_| StartVmError::InitrdLoad)?;

    Ok(InitrdConfig {
        address: GuestAddress(address),
        size,
    })
}

fn create_guest_memory(
    mem_size_mib: usize,
    track_dirty_pages: bool,
) -> std::result::Result<memory::GuestMemoryMmap, StartVmError> {
    let mem_size = mem_size_mib << 20;
    let arch_mem_regions = arch::x86_64::arch_memory_regions(mem_size);

    memory::create_guest_memory(
        &arch_mem_regions
            .iter()
            .map(|(addr, size)| (None, *addr, *size))
            .collect::<Vec<_>>()[..],
        track_dirty_pages,
    )
    .map_err(StartVmError::GuestMemoryMmap)
}

fn create_vcpus(vm: &Vm, vcpu_count: u8, exit_evt: &EventFd) -> Result<Vec<Vcpu>, VmmError> {
    let mut vcpus = Vec::new();
    for cpu_idx in 0..vcpu_count {
        let exit_evt = exit_evt.try_clone().map_err(VmmError::EventFd)?;
        let vcpu = Vcpu::new(cpu_idx, vm, exit_evt).map_err(VmmError::VcpuCreate)?;
        vcpus.push(vcpu);
    }
    Ok(vcpus)
}

fn create_vmm_and_vcpus(
    guest_memory: memory::GuestMemoryMmap,
    track_dirty_pages: bool,
    vcpu_count: u8,
    vcpu_exit_evt: &EventFd,
) -> Result<(Vmm, Vec<Vcpu>), StartVmError> {
    let mut vm = Vm::new()
        .map_err(VmmError::Vm)
        .map_err(StartVmError::Internal)?;
    vm.memory_init(&guest_memory, track_dirty_pages)
        .map_err(VmmError::Vm)
        .map_err(StartVmError::Internal)?;
    setup_interrupt_controller(&mut vm)?;

    let vcpu = create_vcpus(&vm, vcpu_count, vcpu_exit_evt).map_err(StartVmError::Internal)?;

    // MMIO Device Manager
    let mmio_device_manager = MmioDeviceManager::new(
        guest_memory.clone(),
        0x1000,
        arch::x86_64::MMIO_MEM_START,
        5,
    );

    // Legacy Device Manager
    let mut pio_device_manager = PortIoDeviceManager::new(setup_stdio_serial_device())
        .map_err(VmmError::LegacyIoBus)
        .map_err(StartVmError::Internal)?;
    pio_device_manager
        .register_devices(vm.fd())
        .map_err(VmmError::LegacyIoBus)
        .map_err(StartVmError::Internal)?;

    Ok((
        Vmm {
            vm,
            guest_memory,
            mmio_device_manager,
            pio_device_manager,
        },
        vcpu,
    ))
}

fn attach_block_devices(
    vm_resources: &mut resources::VmResources,
    epoll_ctx: &mut epoll::EpollContext,
    mmio_device_manager: &mut MmioDeviceManager,
) -> Result<(), StartVmError> {
    let drives = vm_resources.block.devices.clone();
    let boot_cmdline = vm_resources.cmdline_mut();
    for drive in drives {
        // TODO: multiple root device validation is finished in vmresources and expected to be
        // sorted.
        let drive_file = File::options()
            .read(true)
            .write(true)
            .open(&drive.path_on_host)
            .map_err(StartVmError::OpenBlockDevice)?;
        // blocks.push(drive_file);
        if drive.is_root_device {
            boot_cmdline
                .insert_str(" root=/dev/vda")
                .map_err(StartVmError::InsertCommandline)?;
        }
        let epoll_config = epoll_ctx.allocate_virtio_blk_token();
        let block = Box::new(
            Block::new(drive_file, epoll_config).map_err(StartVmError::CreateBlockDevice)?,
        );
        mmio_device_manager
            .register_mmio(block, boot_cmdline)
            .map_err(StartVmError::RegisterMmioDevice)?;
    }
    Ok(())
}

fn attach_net_devices(
    vm_resources: &mut resources::VmResources,
    epoll_ctx: &mut epoll::EpollContext,
    mmio_device_manager: &mut MmioDeviceManager,
) -> Result<(), StartVmError> {
    let epoll_config = epoll_ctx.allocate_virtio_net_tokens();
    let net = Box::new(Net::new(epoll_config).map_err(StartVmError::CreateNetDevice)?);
    let boot_cmdline = vm_resources.cmdline_mut();
    mmio_device_manager
        .register_mmio(net, boot_cmdline)
        .map_err(StartVmError::RegisterMmioDevice)?;
    Ok(())
}

fn configure_system_for_boot(
    vmm: &Vmm,
    vcpus: &mut [Vcpu],
    vm_resources: &resources::VmResources,
    entry_addr: GuestAddress,
    initrd: &Option<InitrdConfig>,
) -> Result<(), StartVmError> {
    let mut cpuid = cpu::Cpuid::try_from(vmm.vm.supported_cpuid().clone()).unwrap();

    let num_cpus = vcpus.len() as u8;
    for vcpu in vcpus.iter_mut() {
        vcpu.configure(&vmm.guest_memory, entry_addr, &mut cpuid, num_cpus)
            .map_err(VmmError::VcpuConfigure)
            .map_err(StartVmError::Internal)?;
    }

    let boot_cmdline = vm_resources.cmdline();
    // Load cmdline
    load_cmdline::<memory::GuestMemoryMmap>(
        &vmm.guest_memory,
        GuestAddress(arch::x86_64::CMDLINE_START),
        boot_cmdline,
    )
    .map_err(StartVmError::LoadCommandline)?;

    let cmdline_cstr = boot_cmdline.as_cstring().unwrap();
    let cmdline_size = cmdline_cstr.to_str().unwrap().len() + 1;
    arch::x86_64::configure_system(
        &vmm.guest_memory,
        GuestAddress(arch::x86_64::CMDLINE_START),
        cmdline_size,
        initrd,
        num_cpus as u8,
    )
    .map_err(StartVmError::ConfigureSystem)?;
    Ok(())
}

fn run_vcpus(
    vcpus: &mut Vec<Vcpu>,
    vmm: &Vmm,
    vcpu_handles: &mut Vec<std::thread::JoinHandle<()>>,
    vcpu_thread_barrier: &mut Arc<Barrier>,
) -> Result<(), StartVmError> {
    let kill_signaled = Arc::new(AtomicBool::new(false));

    for (vcpu_id, vcpu) in vcpus.drain(..).enumerate() {
        let pio_bus = vmm.pio_device_manager.io_bus.clone();
        let mmio_bus = vmm.mmio_device_manager.bus.clone();
        let kill_signaled = kill_signaled.clone();
        let vcpu_thread_barrier = vcpu_thread_barrier.clone();
        let vcpu_exit_evt = vcpu
            .exit_evt
            .try_clone()
            .map_err(VmmError::EventFd)
            .map_err(StartVmError::Internal)?;
        vcpu_handles.push(
            std::thread::Builder::new()
                .name(format!("toyvmm_vcpu{}", vcpu_id))
                .spawn(move || {
                    vcpu_thread_barrier.wait();
                    loop {
                        match vcpu.run() {
                            Ok(run) => match run {
                                VcpuExit::IoIn(addr, data) => {
                                    pio_bus.read(addr as u64, data);
                                }
                                VcpuExit::IoOut(addr, data) => {
                                    pio_bus.write(addr as u64, data);
                                }
                                VcpuExit::MmioRead(addr, data) => {
                                    mmio_bus.read(addr, data);
                                }
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
                            },
                            Err(e) => match e {
                                VcpuError::VcpuRun(err) => {
                                    if err.errno() == libc::EAGAIN {
                                        // Skip EAGAIN
                                        continue;
                                    }
                                    println!("vcpu run unhandled errno: {:?}", err);
                                    break;
                                }
                                _ => {
                                    println!("vcpu hit unknown error: {:?}", e);
                                    break;
                                }
                            },
                        }
                        if kill_signaled.load(Ordering::SeqCst) {
                            break;
                        }
                    }
                    vcpu_exit_evt
                        .write(1)
                        .expect("failed to signal vcpu exit eventfd");
                })
                .unwrap(),
        );
    }
    vcpu_thread_barrier.wait();
    Ok(())
}

#[allow(clippy::uninit_vec)]
#[allow(clippy::needless_range_loop)]
fn run_epoll_thread(
    pio_device_manager: &PortIoDeviceManager,
    epoll_ctx: &mut epoll::EpollContext,
) -> Result<(), StartVmError> {
    use utils::{poll::PollToken, terminal::Terminal};
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
    stdin_lock
        .set_raw_mode()
        .expect("failed to set terminal raw mode");
    defer! {{
        if let Err(e) = stdin_lock.set_canon_mode() {
            println!("cannot set canon mode for stdin: {:?}", e);
        }
    }};

    const EPOLL_EVENT_LEN: usize = 100;
    let mut events = Vec::<ep::Event>::with_capacity(EPOLL_EVENT_LEN);
    // Safe as we pass to set_len the value passed to with_capacity
    unsafe { events.set_len(EPOLL_EVENT_LEN) };
    let epoll_raw_fd = epoll_ctx.epoll_raw_fd;
    'poll: loop {
        let num_events = ep::wait(epoll_raw_fd, -1, &mut events[..]).unwrap();
        for i in 0..num_events {
            // for event in events.iter() {
            let dispatch_idx = events[i].data() as usize;
            let dispatch_type = epoll_ctx.dispatch_table[dispatch_idx];
            match dispatch_type {
                epoll::EpollDispatch::Exit => break 'poll,
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
                            )
                            .unwrap();
                        }
                        Ok(count) => {
                            pio_device_manager
                                .stdio_serial
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
                    let handler = epoll_ctx.get_device_handler(device_idx);
                    handler.handle_event(device_token, events[i].events().bits());
                }
            }
        }
    }
    Ok(())
}

pub fn build_and_boot_vm(mut vm_resources: resources::VmResources) -> Result<(), StartVmError> {
    use StartVmError::*;

    let guest_memory = create_guest_memory(
        vm_resources.vm_config.mem_size_mib,
        vm_resources.vm_config.track_dirty_page,
    )?;
    let entry_addr = load_kernel(&mut vm_resources, &guest_memory)?;
    let initrd = load_initrd_from_resource(&mut vm_resources, &guest_memory)?;

    let vcpu_exit_evt = EventFd::new(libc::EFD_NONBLOCK)
        .map_err(VmmError::EventFd)
        .map_err(StartVmError::Internal)?;
    let (mut vmm, mut vcpus) = create_vmm_and_vcpus(
        guest_memory,
        vm_resources.vm_config.track_dirty_page,
        vm_resources.vm_config.vcpu_count,
        &vcpu_exit_evt,
    )?;

    let mut epoll_context =
        epoll::EpollContext::new(vcpu_exit_evt.as_raw_fd()).map_err(EpollCtx)?;
    attach_block_devices(
        &mut vm_resources,
        &mut epoll_context,
        &mut vmm.mmio_device_manager,
    )?;
    attach_net_devices(
        &mut vm_resources,
        &mut epoll_context,
        &mut vmm.mmio_device_manager,
    )?;
    vmm.mmio_device_manager
        .setup_event_notifier(&vmm.vm)
        .map_err(VmmError::MmioNotifier)
        .map_err(StartVmError::Internal)?;

    configure_system_for_boot(&vmm, &mut vcpus, &vm_resources, entry_addr, &initrd)?;

    // Run vCpu / Stdio Thread
    let vcpu_count = vcpus.len();
    let mut vcpu_handles = Vec::with_capacity(vcpu_count);
    let mut vcpu_thread_barrier = Arc::new(Barrier::new(vcpu_count + 1));
    run_vcpus(
        &mut vcpus,
        &vmm,
        &mut vcpu_handles,
        &mut vcpu_thread_barrier,
    )?;
    run_epoll_thread(&vmm.pio_device_manager, &mut epoll_context)?;

    // wait for stopping all threads
    for handle in vcpu_handles {
        if let Err(e) = handle.join() {
            println!("Failed to join vcpu thread: {:?}", e);
        }
    }

    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        arch,
        vmm_config::{boot_source, drive, machine_config},
    };
    use ::utils::tempfile::TempFile;
    use std::io::Write;

    fn make_bin(size: usize) -> Vec<u8> {
        let mut fake_bin = Vec::new();
        fake_bin.resize(size, 0xAA);
        fake_bin
    }

    fn make_test_bin() -> Vec<u8> {
        make_bin(1_000_000)
    }

    fn make_test_large_bin() -> Vec<u8> {
        make_bin(5 << 20)
    }

    fn default_kernel_cmdline() -> linux_loader::cmdline::Cmdline {
        linux_loader::cmdline::Cmdline::try_from(
            boot_source::DEFAULT_KERNEL_CMDLINE,
            arch::x86_64::CMDLINE_MAX_SIZE,
        )
        .unwrap()
    }

    fn make_test_vm_resources(
        vm_config: machine_config::VmConfig,
        boot_source: boot_source::BootSource,
        block: drive::BlockDeviceBuilder,
    ) -> resources::VmResources {
        resources::VmResources {
            vm_config,
            boot_source,
            block,
        }
    }

    fn default_vm_resources_from_block(block: drive::BlockDeviceBuilder) -> resources::VmResources {
        let vm_config = machine_config::VmConfig {
            vcpu_count: 1,
            mem_size_mib: 128,
            track_dirty_page: false,
        };
        let boot_source_config = boot_source::BootSourceConfig {
            kernel_path: String::new(),
            initrd_path: None,
            boot_args: None,
        };
        let boot_config = boot_source::BootConfig {
            cmdline: default_kernel_cmdline(),
            kernel_file: TempFile::new().unwrap().into_file(),
            initrd_file: None,
        };
        let boot_source = boot_source::BootSource {
            config: boot_source_config,
            builder: Some(boot_config),
        };
        make_test_vm_resources(vm_config, boot_source, block)
    }

    fn default_vm_resources() -> resources::VmResources {
        let block = drive::BlockDeviceBuilder {
            devices: Vec::new(),
        };
        default_vm_resources_from_block(block)
    }

    fn default_mmio_device_manager() -> MmioDeviceManager {
        MmioDeviceManager::new(
            create_guest_memory(128, false).unwrap(),
            0x1000,
            arch::x86_64::MMIO_MEM_START,
            5,
        )
    }

    pub fn cmdline_contains(cmdline: &linux_loader::cmdline::Cmdline, slug: &str) -> bool {
        cmdline
            .as_cstring()
            .unwrap()
            .into_string()
            .unwrap()
            .contains(slug)
    }

    #[test]
    fn test_load_initrd() {
        let image = make_test_bin();
        let mem_size = image.len() * 2 + arch::x86_64::PAGE_SIZE;
        let tempfile = TempFile::new().unwrap();
        let mut tempfile = tempfile.into_file();
        tempfile.write_all(&image).unwrap();

        let gm = create_guest_memory(mem_size, false).unwrap();
        let res = load_initrd(&gm, &mut tempfile);
        assert!(res.is_ok());
        let initrd = res.unwrap();
        assert_eq!(initrd.size, image.len())
    }

    #[test]
    fn test_load_initrd_no_memory() {
        let image = make_test_large_bin();
        let gm = create_guest_memory(1, false).unwrap();
        let tempfile = TempFile::new().unwrap();
        let mut tempfile = tempfile.into_file();
        tempfile.write_all(&image).unwrap();
        let res = load_initrd(&gm, &mut tempfile);
        assert!(res.is_err());
        assert_eq!(
            StartVmError::InitrdLoad.to_string(),
            res.err().unwrap().to_string(),
        );
    }

    #[test]
    fn test_create_vcpus() {
        // TODO: Now only support single vCPU, but will be support multi vCPU
        let vcpu_count = 1;
        let guest_memory = create_guest_memory(128, false).unwrap();
        let mut vm = Vm::new().unwrap();
        vm.memory_init(&guest_memory, false).unwrap();
        let exit_evt = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        setup_interrupt_controller(&mut vm).unwrap();
        assert!(create_vcpus(&vm, vcpu_count, &exit_evt).is_ok())
    }

    #[test]
    fn test_attach_block_device() {
        let mut epoll_context =
            epoll::EpollContext::new(EventFd::new(libc::EFD_NONBLOCK).unwrap().as_raw_fd())
                .unwrap();
        // Non root block devices are added.
        {
            let mut mmio_device_manager = default_mmio_device_manager();
            let tempfile = TempFile::new().unwrap();
            let block_device_config = drive::BlockDeviceConfig {
                path_on_host: tempfile.as_path().to_str().unwrap().to_string(),
                is_root_device: false,
            };
            let block = drive::BlockDeviceBuilder {
                devices: vec![block_device_config],
            };
            let mut vm_resources = default_vm_resources_from_block(block);
            assert!(attach_block_devices(
                &mut vm_resources,
                &mut epoll_context,
                &mut mmio_device_manager,
            )
            .is_ok());
            assert!(!cmdline_contains(vm_resources.cmdline(), "root=/dev/vda"));
            assert!(cmdline_contains(
                vm_resources.cmdline(),
                "virtio_mmio.device=4K@0xd0000000:5"
            ));
        }

        // Root block device is aded.
        {
            let mut mmio_device_manager = default_mmio_device_manager();
            let tempfile = TempFile::new().unwrap();
            let block_device_config = drive::BlockDeviceConfig {
                path_on_host: tempfile.as_path().to_str().unwrap().to_string(),
                is_root_device: true,
            };
            let block = drive::BlockDeviceBuilder {
                devices: vec![block_device_config],
            };
            let mut vm_resources = default_vm_resources_from_block(block);
            assert!(attach_block_devices(
                &mut vm_resources,
                &mut epoll_context,
                &mut mmio_device_manager,
            )
            .is_ok());
            assert!(cmdline_contains(vm_resources.cmdline(), "root=/dev/vda"));
            assert!(cmdline_contains(
                vm_resources.cmdline(),
                "virtio_mmio.device=4K@0xd0000000:5"
            ));
        }

        // Multiple block devices are added.
        {
            let mut mmio_device_manager = default_mmio_device_manager();
            let root = TempFile::new().unwrap();
            let vdb = TempFile::new().unwrap();
            let root_blk_device_config = drive::BlockDeviceConfig {
                path_on_host: root.as_path().to_str().unwrap().to_string(),
                is_root_device: true,
            };
            let secondary_blk_device_config = drive::BlockDeviceConfig {
                path_on_host: vdb.as_path().to_str().unwrap().to_string(),
                is_root_device: false,
            };
            let block = drive::BlockDeviceBuilder {
                devices: vec![root_blk_device_config, secondary_blk_device_config],
            };
            let mut vm_resources = default_vm_resources_from_block(block);
            assert!(attach_block_devices(
                &mut vm_resources,
                &mut epoll_context,
                &mut mmio_device_manager,
            )
            .is_ok());
            assert!(cmdline_contains(vm_resources.cmdline(), "root=/dev/vda"));
            assert!(cmdline_contains(
                vm_resources.cmdline(),
                "virtio_mmio.device=4K@0xd0000000:5 virtio_mmio.device=4K@0xd0001000:6"
            ));
        }
    }

    #[test]
    fn test_attach_net_device() {
        let mut vm_resources = default_vm_resources();
        let mut epoll_context =
            epoll::EpollContext::new(EventFd::new(libc::EFD_NONBLOCK).unwrap().as_raw_fd())
                .unwrap();
        let mut mmio_device_manager = MmioDeviceManager::new(
            create_guest_memory(128, false).unwrap(),
            0x1000,
            arch::x86_64::MMIO_MEM_START,
            5,
        );
        assert!(attach_block_devices(
            &mut vm_resources,
            &mut epoll_context,
            &mut mmio_device_manager,
        )
        .is_ok());
    }
}
