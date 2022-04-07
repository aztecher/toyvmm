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

### Run

Running `make run` executes `cargo run` on the development environment, and running `make run_container` executes it inside the container.
Currently running code equivalent to the example of LVM article 「[Using the KVM API](https://lwn.net/Articles/658511/)」and similar to [kvm_ioctls' example](https://docs.rs/kvm-ioctls/latest/kvm_ioctls/#example---running-a-vm-on-x86_64)

```bash
# Execute on development environment
$ make run
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
$ make run_container
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
