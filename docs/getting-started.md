# Getting Started with ToyVMM

## Supportred architecture & OS

ToyVMM only supports **x86_64** Linux for Guest OS.  
ToyVMM has been confirmed to work with Rocky Linux 8.6, 9.1 and Ubuntu 18.04, 22.04, 24.04 as the Hypervisor OS.  

## Prerequisites

ToyVMM requires [the KVM Linux kernel module.](https://www.linux-kvm.org/page/Main_Page)

## Run Virtual Machine using ToyVMM

Following command builds toyvmm from source, downloads the kernel binary and rootfs needed to start the VM, and starts the VM.

```bash
# download and build toyvmm from source.
git clone https://github.com/aztecher/toyvmm.git
cd toyvmm
mkdir build
CARGO_TARGET_DIR=./build cargo build --release

# Download a linux kernel binary.
wget https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/x86_64/kernels/vmlinux.bin

# Download a rootfs.
wget https://s3.amazonaws.com/spec.ccfc.min/ci-artifacts/disks/x86_64/ubuntu-18.04.ext4

# Run virtual machine based on ToyVMM!
sudo ./build/release/toyvmm vm run --config examples/vm_config.json
```

After the guest OS startup sequence is output, the login screen is displayed, so enter both username and password as 'root' to login.

## Disk I/O in Virtual Machine.

Since we have implemented virtio-blk, the virtual machine is capable of operating block devices.  
Now it recognizes the ubuntu18.04.ext4 disk image as a block device and mounts it as the root filesystem.

```bash
lsblk
> NAME MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
> vda  254:0    0  384M  0 disk /
```

Therefore, if you create a file in the VM and then recreate the VM using the same image, the file you created will be found.
This behavior is significantly different from a initramfs (rootfs that is extracted on RAM).

```bash
# Create 'hello.txt' in VM.
echo "hello virtual machine" > hello.txt
cat hello.txt
> hello virtual machine

# Rebooting will cause the ToyVMM process to terminate.
reboot -f

# In the host, please restart VM and login again.
# Afterward, you can found the file you created in the VM during its previous run.
cat hello.txt
> hello virtual machine
```

## Network I/O in Virtual Mahcine.

Since we have implemented virtio-net, the virtual machine is capable of operating network device.  
Now, it recognizes the `eth0` network interface.

```bash
ip link show eth0
> 2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000
>     link/ether 52:5f:7f:b3:f8:81 brd ff:ff:ff:ff:ff:ff
```

And toyvmm creates the host-side tap device named `vmtap0` that connect to the virtual machine interface.

```bash
ip link show vmtap0
> 334: vmtap0: <BROADCAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN mode DEFAULT group default qlen 1000
>     link/ether 26:e9:5c:02:3c:19 brd ff:ff:ff:ff:ff:ff
```

Therefore, by assigning appropriate IP addresses to the interfaces on both the VM side and the Host side, communication can be established between the HV and the VM.

```bash
# Assign ip address 192.168.0.10/24 to 'eth0' in vm.
ip addr add 192.168.0.10/24 dev eth0

# Assign ip address 192.168.0.1/24 to 'vmtap0' in host.
sudo ip addr add 192.168.0.1/24 dev vmtap0

# Host -> VM. ping to VM interface ip from host.
ping -c 1 192.168.0.10

# VM -> Host. Ping to Host interface ip from vm.
ping -c 1 192.168.0.1
```

Additionally, by setting the default route on the VM side, and configuring iptables and enabling IP forwarding on the host side, you can also allow the VM to access the Internet.  
However, this will not be covered in detail here.

