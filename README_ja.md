# ToyVMM (Toy Virtual Machine Monitor)

[English README](./README.md)

ToyVMMは仮想化技術の学習目的で開発されているプロジェクトになります。
ToyVMMは以下を達成することを目的としています

- KVMをベースとした仮想化技術についてコードベースで理解する
- [rust-vmm](https://github.com/rust-vmm)によって管理される各種ライブラリを題材として取り上げ、モダンな仮想化技術スタックについて学ぶ
  - rust-vmmのライブラリは[firecracker](https://github.com/firecracker-microvm/firecracker)などの有名なOSSのベースにも利用されており、  カスタムVMMを作成するのに必要な機能が提供されています

## Prerequisites

本プロジェクトはKVMをベースとしているため、開発環境にKVMがセットアップされている必要があります。
また、基本的にコードのテストや実行はDockerコンテナ内部で実施することを想定ているため、Dockerのインストールが必要です。


## Book

[Book](https://aztecher.github.io/)を作成しました。

ToyVMMの実装拡張とともに、bookの内容も拡充していく予定です
もし内容に間違いを含んでいる場合は、気軽に[toyvmm-book](https://github.com/aztecher/toyvmm-book)にissueを起票してください

## Development

### Run

`make run`を実行すると開発環境上で`cargo run`を実施し、`make run_container`を実行することでコンテナ内部で実行します。
現在は、LWNの「[Using the KVM API](https://lwn.net/Articles/658511/)」と同等のコードを実行しており、[kvm_ioctlsのExample](https://docs.rs/kvm-ioctls/latest/kvm_ioctls/#example---running-a-vm-on-x86_64)とも類似のコードになっています

```bash
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
```

### Test

`make test`を実行すると開発環境上で`cargo test`を実施し、`make test_container`を実行するとコンテナ内部でテストを実行します。
`/dev/kvm`を利用することが前提のテストを記載しているため、`make test`を実行する場合`/dev/kvm`が存在することとsudo権限を要求します。また 、コンテナ上でのテストでは`/dev/kvm`をマウントしテストを実行します。

```bash
# 開発マシン上で実行
$ make test

# コンテナを起動し、コンテナ内部でテスト実行
$ make test_container
```
