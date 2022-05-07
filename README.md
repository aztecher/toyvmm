# ToyVMM (Toy Virtual Machine Monitor)

[![Build Status](https://app.travis-ci.com/aztecher/toyvmm.svg?branch=main)](https://app.travis-ci.com/aztecher/toyvmm)

## Overview

[Japanese README](./README_ja.md)

ToyVMM is a project being developed for the purpose of learning virtualization technology.  
ToyVMM aims to accomplish the following

- Code-based understanding of KVM-based virtualization technologies
- Learn about the modern virtualization technology stack by using libraries managed by [rust-vmm](https://github.com/rust-vmm)
  - The rust-vmm libraries are also used as a base for well-known OSS such as [firecracker](https://github.com/firecracker-microvm/firecracker) and provides the functionality needed to create custom VMMs.

## Prerequisites

Since this project is based on KVM, it's desiable to have KVM setup in the development environment.  
In addition, Docker installation is required since the code testing and execution is basically intended to be performed inside a Docker container.

## Book

[Book](https://aztecher.github.io/) is now available!

As we expand the implementation of ToyVMM, we plan to enhance the contents of the book as well.
If you find any mistakes or my misunderstandings in the documentation, please feel free to submit an issue to the [toyvmm-book](https://github.com/aztecher/toyvmm-book) repository.

## Development

### Run LWN article example

`
Running `make run_lwn` executes `cargo run` on the development environment, and running `make run_lwn_container` executes it inside the container.
Currently running code equivalent to [kvm_ioctls' example](https://docs.rs/kvm-ioctls/latest/kvm_ioctls/#example---running-a-vm-on-x86_64)

```bash
# Execute on development environment
$ make run_lwn
sudo -E cargo run
   Compiling bitflags v1.3.2
   Compiling libc v0.2.121
   Compiling vmm-sys-util v0.9.0
   Compiling vm-memory v0.7.0
   Compiling kvm-bindings v0.5.0
   Compiling kvm-ioctls v0.11.0
   Compiling toyvmm v0.1.0 (/home/mmichish/Documents/rust/toyvmm)
    Finished dev [unoptimized + debuginfo] target(s) in 5.43s
     Running `target/debug/toyvmm`
Recieved I/O out exit. Address: 0x3f8, Data(hex): 0x34
Recieved I/O out exit. Address: 0x3f8, Data(hex): 0xa
sudo rm -rf target

# Execute inside container
$ make run_lwn_container
```


## Run linux kernel with initrd (no rootfs)

First, you have to prepair `vmlinux.bin` and `initrd.img` in toyvmm working directory.

```bash
# Download vmlinux.bin
wget https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/x86_64/kernels/vmlinux.bin
cp vmlinux.bin <TOYVMM WORKING DIRECTORY>

# Create initrd.img
# Using marcov/firecracker-initrd (https://github.com/marcov/firecracker-initrd)
git clone https://github.com/marcov/firecracker-initrd.git
cd firecracker-initrd
bash ./build.sh
# After above commands, initrd.img file wil be located on build/initrd.img
cp build/initrd.img <TOYVMM WORKING DIRECTORY>
```

and then, hit the `make run_linux` command to launch Linux kernel! (Nothing more can be done now).  

```bash
$ make run_linux
sudo -E cargo run -- boot_kernel -k vmlinux.bin -i initrd.img
...
[    0.000000] Linux version 4.14.174 (@57edebb99db7) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #2 SMP Wed Jul 14 11:47:24 UTC 2021
[    0.000000] Command line: console=ttyS0 noapic noacpi reboot=k panic=1 pci=off nomodule
[    0.000000] CPU: vendor_id 'TOYVMMTOYVMM' unknown, using generic init.
[    0.000000] CPU: Your system may be unstable.
[    0.000000] x86/fpu: Supporting XSAVE feature 0x001: 'x87 floating point registers'
[    0.000000] x86/fpu: Supporting XSAVE feature 0x002: 'SSE registers'
[    0.000000] x86/fpu: Supporting XSAVE feature 0x004: 'AVX registers'
[    0.000000] x86/fpu: xstate_offset[2]:  576, xstate_sizes[2]:  256
[    0.000000] x86/fpu: Enabled xstate features 0x7, context size is 832 bytes, using 'standard' format.
[    0.000000] e820: BIOS-provided physical RAM map:
[    0.000000] BIOS-e820: [mem 0x0000000000000000-0x000000000009fbff] usable
[    0.000000] BIOS-e820: [mem 0x0000000000100000-0x0000000007ffffff] usable
[    0.000000] NX (Execute Disable) protection: active
[    0.000000] DMI not present or invalid.
[    0.000000] Hypervisor detected: KVM
[    0.000000] tsc: Fast TSC calibration failed
[    0.000000] tsc: Unable to calibrate against PIT
[    0.000000] tsc: No reference (HPET/PMTIMER) available
[    0.000000] e820: last_pfn = 0x8000 max_arch_pfn = 0x400000000
[    0.000000] MTRR: Disabled
[    0.000000] x86/PAT: MTRRs disabled, skipping PAT initialization too.
[    0.000000] CPU MTRRs all blank - virtualized system.
[    0.000000] x86/PAT: Configuration [0-7]: WB  WT  UC- UC  WB  WT  UC- UC
[    0.000000] Scanning 1 areas for low memory corruption
[    0.000000] Using GB pages for direct mapping
[    0.000000] RAMDISK: [mem 0x06612000-0x07ffffff]
[    0.000000] No NUMA configuration found
[    0.000000] Faking a node at [mem 0x0000000000000000-0x0000000007ffffff]
[    0.000000] NODE_DATA(0) allocated [mem 0x065f0000-0x06611fff]
[    0.000000] kvm-clock: Using msrs 4b564d01 and 4b564d00
[    0.000000] kvm-clock: cpu 0, msr 0:65ee001, primary cpu clock
[    0.000000] clocksource: kvm-clock: mask: 0xffffffffffffffff max_cycles: 0x1cd42e4dffb, max_idle_ns: 881590591483 ns
[    0.000000] Zone ranges:
[    0.000000]   DMA      [mem 0x0000000000001000-0x0000000000ffffff]
[    0.000000]   DMA32    [mem 0x0000000001000000-0x0000000007ffffff]
[    0.000000]   Normal   empty
[    0.000000] Movable zone start for each node
[    0.000000] Early memory node ranges
[    0.000000]   node   0: [mem 0x0000000000001000-0x000000000009efff]
[    0.000000]   node   0: [mem 0x0000000000100000-0x0000000007ffffff]
[    0.000000] Initmem setup node 0 [mem 0x0000000000001000-0x0000000007ffffff]
[    0.000000] smpboot: Boot CPU (id 0) not listed by BIOS
[    0.000000] smpboot: Allowing 1 CPUs, 0 hotplug CPUs
[    0.000000] PM: Registered nosave memory: [mem 0x00000000-0x00000fff]
[    0.000000] PM: Registered nosave memory: [mem 0x0009f000-0x000fffff]
[    0.000000] e820: [mem 0x08000000-0xffffffff] available for PCI devices
[    0.000000] Booting paravirtualized kernel on KVM
[    0.000000] clocksource: refined-jiffies: mask: 0xffffffff max_cycles: 0xffffffff, max_idle_ns: 7645519600211568 ns
[    0.000000] random: get_random_bytes called from start_kernel+0x94/0x486 with crng_init=0
[    0.000000] setup_percpu: NR_CPUS:128 nr_cpumask_bits:128 nr_cpu_ids:1 nr_node_ids:1
[    0.000000] percpu: Embedded 41 pages/cpu s128600 r8192 d31144 u2097152
[    0.000000] KVM setup async PF for cpu 0
[    0.000000] kvm-stealtime: cpu 0, msr 6215040
[    0.000000] PV qspinlock hash table entries: 256 (order: 0, 4096 bytes)
[    0.000000] Built 1 zonelists, mobility grouping on.  Total pages: 32137
[    0.000000] Policy zone: DMA32
[    0.000000] Kernel command line: console=ttyS0 noapic noacpi reboot=k panic=1 pci=off nomodule
[    0.000000] PID hash table entries: 512 (order: 0, 4096 bytes)
[    0.000000] Memory: 84464K/130680K available (8204K kernel code, 645K rwdata, 1480K rodata, 1324K init, 2792K bss, 46216K reserved, 0K cma-reserved)
[    0.000000] SLUB: HWalign=64, Order=0-3, MinObjects=0, CPUs=1, Nodes=1
[    0.000000] Kernel/User page tables isolation: enabled
[    0.004000] Hierarchical RCU implementation.
[    0.004000]  RCU restricting CPUs from NR_CPUS=128 to nr_cpu_ids=1.
[    0.004000] RCU: Adjusting geometry for rcu_fanout_leaf=16, nr_cpu_ids=1
[    0.004000] NR_IRQS: 4352, nr_irqs: 24, preallocated irqs: 16
[    0.004000] Console: colour dummy device 80x25
[    0.004000] console [ttyS0] enabled
[    0.004000] tsc: Detected 1797.917 MHz processor
[    0.012160] Calibrating delay loop (skipped) preset value.. 3595.83 BogoMIPS (lpj=7191668)
[    0.020071] pid_max: default: 32768 minimum: 301
[    0.028913] Security Framework initialized
[    0.036369] SELinux:  Initializing.
[    0.049804] Dentry cache hash table entries: 16384 (order: 5, 131072 bytes)
[    0.058110] Inode-cache hash table entries: 8192 (order: 4, 65536 bytes)
[    0.064245] Mount-cache hash table entries: 512 (order: 0, 4096 bytes)
[    0.072207] Mountpoint-cache hash table entries: 512 (order: 0, 4096 bytes)
[    0.097996] Last level iTLB entries: 4KB 0, 2MB 0, 4MB 0
[    0.104069] Last level dTLB entries: 4KB 0, 2MB 0, 4MB 0, 1GB 0
[    0.112200] Spectre V1 : Mitigation: usercopy/swapgs barriers and __user pointer sanitization
[    0.120071] Spectre V2 : Mitigation: Full generic retpoline
[    0.128068] Spectre V2 : Spectre v2 / SpectreRSB mitigation: Filling RSB on context switch
[    0.136068] Spectre V2 : Enabling Restricted Speculation for firmware calls
[    0.144094] Spectre V2 : mitigation: Enabling conditional Indirect Branch Prediction Barrier
[    0.152070] Speculative Store Bypass: Mitigation: Speculative Store Bypass disabled via prctl and seccomp
[    0.160193] MDS: Mitigation: Clear CPU buffers
[    0.264757] Freeing SMP alternatives memory: 28K
[    0.291047] smpboot: Max logical packages: 1
[    0.296075] smpboot: SMP motherboard not detected
[    0.304069] smpboot: SMP disabled
[    0.312087] Not enabling interrupt remapping due to skipped IO-APIC setup
[    0.543466] Performance Events: no PMU driver, software events only.
[    0.549031] Hierarchical SRCU implementation.
[    0.562622] smp: Bringing up secondary CPUs ...
[    0.564009] smp: Brought up 1 node, 1 CPU
[    0.568009] smpboot: Total of 1 processors activated (3595.83 BogoMIPS)
[    0.577419] devtmpfs: initialized
[    0.580508] x86/mm: Memory block size: 128MB
[    0.589934] clocksource: jiffies: mask: 0xffffffff max_cycles: 0xffffffff, max_idle_ns: 7645041785100000 ns
[    0.592030] futex hash table entries: 256 (order: 2, 16384 bytes)
[    0.609081] NET: Registered protocol family 16
[    0.618664] cpuidle: using governor ladder
[    0.620010] cpuidle: using governor menu
[    0.712976] HugeTLB registered 1.00 GiB page size, pre-allocated 0 pages
[    0.716019] HugeTLB registered 2.00 MiB page size, pre-allocated 0 pages
[    0.724573] SCSI subsystem initialized
[    0.728074] pps_core: LinuxPPS API ver. 1 registered
[    0.732008] pps_core: Software ver. 5.3.6 - Copyright 2005-2007 Rodolfo Giometti <giometti@linux.it>
[    0.736021] PTP clock support registered
[    0.740022] dmi: Firmware registration failed.
[    0.744273] NetLabel: Initializing
[    0.748007] NetLabel:  domain hash size = 128
[    0.752006] NetLabel:  protocols = UNLABELED CIPSOv4 CALIPSO
[    0.756287] NetLabel:  unlabeled traffic allowed by default
[    0.760582] clocksource: Switched to clocksource kvm-clock
[    0.778344] VFS: Disk quotas dquot_6.6.0
[    0.790769] VFS: Dquot-cache hash table entries: 512 (order 0, 4096 bytes)
[    0.822841] NET: Registered protocol family 2
[    0.837069] TCP established hash table entries: 1024 (order: 1, 8192 bytes)
[    0.859342] TCP bind hash table entries: 1024 (order: 2, 16384 bytes)
[    0.879465] TCP: Hash tables configured (established 1024 bind 1024)
[    0.902117] UDP hash table entries: 256 (order: 1, 8192 bytes)
[    0.920399] UDP-Lite hash table entries: 256 (order: 1, 8192 bytes)
[    0.940404] NET: Registered protocol family 1
[    0.955256] Unpacking initramfs...
[    3.052249] Freeing initrd memory: 26552K
[    3.065617] clocksource: tsc: mask: 0xffffffffffffffff max_cycles: 0x19ea79d464e, max_idle_ns: 440795215514 ns
[    3.096416] platform rtc_cmos: registered platform RTC device (no PNP device found)
[    3.120848] Scanning for low memory corruption every 60 seconds
[    3.140348] audit: initializing netlink subsys (disabled)
[    3.160735] Initialise system trusted keyrings
[    3.174717] Key type blacklist registered
[    3.187779] audit: type=2000 audit(1651886382.899:1): state=initialized audit_enabled=0 res=1
[    3.214358] workingset: timestamp_bits=36 max_order=15 bucket_order=0
[    3.241777] squashfs: version 4.0 (2009/01/31) Phillip Lougher
[    3.264886] Key type asymmetric registered
[    3.277843] Asymmetric key parser 'x509' registered
[    3.293150] Block layer SCSI generic (bsg) driver version 0.4 loaded (major 252)
[    3.316612] io scheduler noop registered (default)
[    3.331830] io scheduler cfq registered
[    3.344407] Serial: 8250/16550 driver, 1 ports, IRQ sharing disabled
[    3.436907] serial8250: ttyS0 at I/O 0x3f8 (irq = 4, base_baud = 115200) is a U6_16550A
[    3.472688] loop: module loaded
[    3.482762] Loading iSCSI transport class v2.0-870.
[    3.499158] iscsi: registered transport (tcp)
[    3.513021] tun: Universal TUN/TAP device driver, 1.6
[    5.182788] i8042: Can't read CTR while initializing i8042
[    5.200323] i8042: probe of i8042 failed with error -5
[    5.216681] hidraw: raw HID events driver (C) Jiri Kosina
[    5.234068] nf_conntrack version 0.5.0 (1024 buckets, 4096 max)
[    5.252947] ip_tables: (C) 2000-2006 Netfilter Core Team
[    5.269699] Initializing XFRM netlink socket
[    5.284294] NET: Registered protocol family 10
[    5.302930] Segment Routing with IPv6
[    5.314933] NET: Registered protocol family 17
[    5.328924] Bridge firewalling registered
[    5.341851] NET: Registered protocol family 40
[    5.357171] registered taskstats version 1
[    5.370211] Loading compiled-in X.509 certificates
[    5.388792] Loaded X.509 cert 'Build time autogenerated kernel key: e98e9d271da5d0a322cc4d7bfaa8c2c4c3e46010'
[    5.421131] Key type encrypted registered
[    5.460265] Freeing unused kernel memory: 1324K
[    5.476248] Write protecting the kernel read-only data: 12288k
[    5.574072] Freeing unused kernel memory: 2016K
[    5.614686] Freeing unused kernel memory: 568K

   OpenRC 0.44.7.10dab8bfb7 is starting up Linux 4.14.174 (x86_64)

 * Mounting /proc ... [ ok ]
 * Mounting /run ... * /run/openrc: creating directory
 * /run/lock: creating directory
 * /run/lock: correcting owner
 * Caching service dependencies ... [ ok ]
 * Mounting devtmpfs on /dev ... [ ok ]
 * Mounting /dev/mqueue ... [ ok ]
 * Mounting /dev/pts ... [ ok ]
 * Mounting /dev/shm ... [ ok ]
 * Loading modules ...modprobe: can't change directory to '/lib/modules': No such file or directory
modprobe: can't change directory to '/lib/modules': No such file or directory
 [ ok ]
 * Mounting misc binary format filesystem ... [ ok ]
 * Mounting /sys ... [ ok ]
 * Mounting security filesystem ... [ ok ]
 * Mounting debug filesystem ... [ ok ]
 * Mounting SELinux filesystem ... [ ok ]
 * Mounting persistent storage (pstore) filesystem ... [ ok ]
 * Starting fcnet ... [ ok ]
 * Checking local filesystems  ... [ ok ]
 * Remounting filesystems ... [ ok ]
 * Mounting local filesystems ... [ ok ]
 * Starting networking ... *   eth0 ...Cannot find device "eth0"
Device "eth0" does not exist.
 [ ok ]
 * Starting networking ... *   lo ... [ ok ]
 *   eth0 ... [ ok ]

Welcome to Alpine Linux 3.15
Kernel 4.14.174 on an x86_64 (ttyS0)

(none) login:
```

### Test

Running `make test` will run `cargo test` on the development environment, and running `make test_container` will run the test inside the container.
Since this test assumes that `/dev/kvm` is used, `make test` requires the existence of `/dev/kvm` and sudo privileges. Also, when testing on containers, `/dev/kvm` is mounted and the test is executed.

```bash
# Execute on development environment
$ make test

# Execute inside container
make test_container
```
