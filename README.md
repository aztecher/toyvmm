# ToyVMM (Toy Virtual Machine Monitor)

<p>
  <a alia-label="Build" href="https://app.travis-ci.com/aztecher/toyvmm">
    <img alt="" src="https://img.shields.io/travis/com/aztecher/toyvmm.svg?style=for-the-badge&logo=travisci">
  </a>
  <!-- <a alia-label="License" href=""> -->
  <!--   <img alt="" src="https://img.shields.io/badge/license-MIT-blue?style=for-the-badge"> -->
  <!-- </a> -->
  <a alia-label="Book" href="https://aztecher.github.io/en/">
    <img alt="" src="https://img.shields.io/badge/read%20the-book-9cf.svg?style=for-the-badge&logo=mdbook">
  </a>
</p>


## Overview

ToyVMM is a project being developed for the purpose of learning virtualization technology.  
ToyVMM aims to accomplish the following

- Code-based understanding of KVM-based virtualization technologies
- Learn about the modern virtualization technology stack by using libraries managed by [rust-vmm](https://github.com/rust-vmm)
  - The rust-vmm libraries are also used as a base for well-known OSS such as [firecracker](https://github.com/firecracker-microvm/firecracker) and provides the functionality needed to create custom VMMs.

## Book

Book ([en](https://aztecher.github.io/en/) / [ja](https://aztecher.github.io/ja/)) is now available!

As we expand the implementation of ToyVMM, we plan to enhance the contents of the book as well.
If you find any mistakes or my misunderstandings in the documentation, please feel free to submit an issue to the [toyvmm-book](https://github.com/aztecher/toyvmm-book) repository.

**BOOK CHANGE LOG**

* Dec 27, 2023 : Add contents about SMP only in ja.
* Sep 24, 2023 : Add 'Virtio' contents and translate all existing contents into ja / en.
* Jan  5, 2023 : Add contents (Load Linux Kernel, and its subcontents)
* Apr  7, 2022 : First publish (Introduction, QuickStart, Running Tiny Code in VM)

## Getting Started

Please see the [quickstart guide](./docs/getting-started.md) to launch your VM using ToyVMM!

## Features and Capabilities

* Can run a virtual machine!
* Customizing the number of vCPU and memory size of your virtual machine is available.
* Support virtio-blk and virtio-net to execute disk and network I/O in virtual machine.
  * Thanks to the virtio-blk, toyvmm can launch the guest OS from rootfs images like ubuntu-18.04.ext4, not only initramfs.
  * Thanks to the virtio-net, the virtual machine can reach out of the host (requires the host-side iptables setting).
