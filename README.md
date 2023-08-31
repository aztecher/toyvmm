# ToyVMM (Toy Virtual Machine Monitor)

[![Build Status](https://app.travis-ci.com/aztecher/toyvmm.svg?branch=main)](https://app.travis-ci.com/aztecher/toyvmm)

## Overview

ToyVMM is a project being developed for the purpose of learning virtualization technology.  
ToyVMM aims to accomplish the following

- Code-based understanding of KVM-based virtualization technologies
- Learn about the modern virtualization technology stack by using libraries managed by [rust-vmm](https://github.com/rust-vmm)
  - The rust-vmm libraries are also used as a base for well-known OSS such as [firecracker](https://github.com/firecracker-microvm/firecracker) and provides the functionality needed to create custom VMMs.

## Book

[Book](https://aztecher.github.io/) is now available!

As we expand the implementation of ToyVMM, we plan to enhance the contents of the book as well.
If you find any mistakes or my misunderstandings in the documentation, please feel free to submit an issue to the [toyvmm-book](https://github.com/aztecher/toyvmm-book) repository.

**CHANGE LOG**

* Jan 5, 2023 : Add contents (Load Linux Kernel, and its subcontents)
  * Now it's currently available only in ja, but will soon be translated into en.
* Apr 7, 2022 : First publish (Introduction, QuickStart, Running Tiny Code in VM)

## Getting Started

Please see the [quickstart guide](./docs/getting-started.md) to launch your VM using ToyVMM!

## Features and Capabilities

* Can run a virtual machine!
* Customizing the memory size of your virtual machine is available.
  * Currently only one vCPU is supported, but support for multiple vCPUs is planned for implementation.
* Support virtio-blk and virtio-net to execute disk and network I/O in virtual machine.
  * Thanks to the virtio-blk, toyvmm can launch the guest OS from rootfs images like ubuntu-18.04.ext4, not only initramfs.
  * Thanks to the virtio-net, the virtual machine can reach out of the host (requires the host-side iptables setting).
