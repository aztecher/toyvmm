use crate::{
    arch,
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
    vstate::{memory, vcpu::Vcpu, vm::Vm},
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
fn setup_stdio_serial_device() -> Arc<Mutex<SerialDevice>> {
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

fn setup_interrupt_controller(vm: &mut Vm) -> Result<(), StartVmError> {
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

fn create_guest_memory(
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
    )
    .map_err(StartVmError::GuestMemoryMmap)
}

fn create_vcpus(vm: &Vm, _vcpu_count: u8, exit_evt: &EventFd) -> Result<Vcpu, VmmError> {
    // TODO: Now only support single vCPU, but will be support multi vCPU.
    let cpu_idx = 0;
    let exit_evt = exit_evt.try_clone().map_err(VmmError::EventFd)?;
    let vcpu = Vcpu::new(cpu_idx, vm, exit_evt).map_err(VmmError::VcpuCreate)?;
    Ok(vcpu)
}

fn attach_block_devices(
    vm_resources: &mut resources::VmResources,
    epoll_ctx: &mut epoll::EpollContext,
    mmio_device_manager: &mut MmioDeviceManager,
) -> Result<(), StartVmError> {
    let mut blocks = Vec::new();
    for drive in vm_resources.block.devices.iter() {
        // TODO: multiple root device validation is finished in vmresources and expected to be
        // sorted.
        let drive_file = File::options()
            .read(true)
            .write(true)
            .open(&drive.path_on_host)
            .map_err(StartVmError::OpenBlockDevice)?;
        blocks.push(drive_file);
    }
    let boot_cmdline = vm_resources.cmdline_mut();
    for (index, block) in blocks.into_iter().enumerate() {
        if index == 0 {
            boot_cmdline
                .insert_str(" root=/dev/vda")
                .map_err(StartVmError::InsertCommandline)?;
        }
        let epoll_config = epoll_ctx.allocate_virtio_blk_token();
        let block =
            Box::new(Block::new(block, epoll_config).map_err(StartVmError::CreateBlockDevice)?);
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
    vcpu: &mut Vcpu,
    vm_resources: &resources::VmResources,
    // vm_config: &machine_config::VmConfig,
    entry_addr: GuestAddress,
    initrd: &Option<InitrdConfig>,
    // boot_cmdline: &Cmdline,
) -> Result<(), StartVmError> {
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
    let num_cpus = 1;
    arch::x86_64::configure_system(
        &vmm.guest_memory,
        GuestAddress(arch::x86_64::CMDLINE_START),
        cmdline_size,
        initrd,
        num_cpus,
    )
    .unwrap();

    let cpu_id = 0;
    let num_cpus = 1;
    let mut kvm_cpuid = vmm.vm.supported_cpuid().clone();
    vcpu.configure(
        &vmm.guest_memory,
        entry_addr,
        cpu_id as u64,
        num_cpus as u64,
        &mut kvm_cpuid,
    )
    .map_err(VmmError::VcpuConfigure)
    .map_err(StartVmError::Internal)?;
    Ok(())
}

fn run_vcpus(
    vcpu: Vcpu,
    vmm: &Vmm,
    vcpu_handles: &mut Vec<std::thread::JoinHandle<()>>,
    vcpu_thread_barrier: &mut Arc<Barrier>,
) -> Result<(), StartVmError> {
    let pio_bus = vmm.pio_device_manager.io_bus.clone();
    let mmio_bus = vmm.mmio_device_manager.bus.clone();

    let kill_signaled = Arc::new(AtomicBool::new(false));
    let barrier = vcpu_thread_barrier.clone();
    let vcpu_exit_evt = vcpu
        .exit_evt
        .try_clone()
        .map_err(VmmError::EventFd)
        .map_err(StartVmError::Internal)?;
    vcpu_handles.push(
        std::thread::Builder::new()
            .name(String::from("vcpu_0"))
            .spawn(move || {
                barrier.wait();
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
                        Err(e) => {
                            println!("vcpu hit unknown error: {:?}", e);
                            break;
                        }
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
    // run vcpu threads!
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
    let (mut vmm, mut vcpu) = create_vmm_and_vcpus(
        guest_memory,
        vm_resources.vm_config.track_dirty_page,
        vm_resources.vm_config.vcpu_count,
    )?;

    let mut epoll_context =
        epoll::EpollContext::new(vcpu.exit_evt.as_raw_fd()).map_err(EpollCtx)?;
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

    configure_system_for_boot(
        &vmm,
        &mut vcpu,
        &vm_resources,
        entry_addr,
        &initrd,
        // &mut vm_resources.cmdline_mut(),
    )?;

    // Run vCpu / Stdio Thread
    let num_cpus = 1;
    let mut vcpu_handles = Vec::with_capacity(num_cpus as usize);
    let mut vcpu_thread_barrier = Arc::new(Barrier::new(num_cpus + 1));
    run_vcpus(vcpu, &vmm, &mut vcpu_handles, &mut vcpu_thread_barrier)?;
    run_epoll_thread(&vmm.pio_device_manager, &mut epoll_context)?;

    // wait for stopping all threads
    for handle in vcpu_handles {
        if let Err(e) = handle.join() {
            println!("Failed to join vcpu thread: {:?}", e);
        }
    }

    Ok(())
}

fn create_vmm_and_vcpus(
    guest_memory: memory::GuestMemoryMmap,
    track_dirty_pages: bool,
    vcpu_count: u8,
) -> Result<(Vmm, Vcpu), StartVmError> {
    let mut vm = Vm::new()
        .map_err(VmmError::Vm)
        .map_err(StartVmError::Internal)?;
    vm.memory_init(&guest_memory, track_dirty_pages)
        .map_err(VmmError::Vm)
        .map_err(StartVmError::Internal)?;
    setup_interrupt_controller(&mut vm)?;

    let vcpu_exit_evt = EventFd::new(libc::EFD_NONBLOCK)
        .map_err(VmmError::EventFd)
        .map_err(StartVmError::Internal)?;
    let vcpu = create_vcpus(&vm, vcpu_count, &vcpu_exit_evt).map_err(StartVmError::Internal)?;

    // MMIO Device Manager
    let mmio_device_manager =
        MmioDeviceManager::new(guest_memory.clone(), 0x1000, arch::MMIO_MEM_START, 5);

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
    let address = arch::initrd_load_addr(vm_memory, size).map_err(|_| StartVmError::InitrdLoad)?;

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

// #[cfg(test)]
// mod tests {}
