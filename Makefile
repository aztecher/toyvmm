#!/usr/bin/make -f

CARGO := cargo

IMAGE_TAG := 0.0.1
DOCKER_IMAGE := aztecher/toyvmm:${IMAGE_TAG}
KERNEL_FILE := vmlinux.bin
INITRD_FILE := initrd.img
ROOT_DISK := disk

DEFAULT_TARGET := help

# list up all targets
ALL_TARGET := filename

target: $(DEFAULT_TARGET) ## help

all: $(ALL_TARGET) ## Make all files

docker-image: ## Build docker image
	docker build -t ${DOCKER_IMAGE} .

run_lwn: ## Execute LWN sample
	sudo -E cargo run -- lwn_sample
	sudo rm -rf target

run_lwn_container: docker-image
	docker run --rm --device=/dev/kvm \
		--security-opt seccomp=unconfined \
		--volume `pwd`:/toyvmm -it ${DOCKER_IMAGE} \
		sh -c 'cd toyvmm; cargo run -- lwn_sample; rm -rf target'

run_linux: ## Execute Linux kernel (Require vmlinux.bin, initrd.img in this directory)
	sudo -E cargo run -- boot_kernel -k ${KERNEL_FILE} -i ${INITRD_FILE} -r ${ROOT_DISK}

run_linux_debug:
	sudo -E strace -y -e epoll_create,epoll_ctl,epoll_wait cargo run -- \
		boot_kernel -k ${KERNEL_FILE} -i ${INITRD_FILE} -r ${ROOT_DISK}

# run_linux_virt:
# 	sudo -E cargo run -- boot_kernel -k ${KERNEL_FILE} -i initrd.img-5.4.0-139-generic

test: ## Execute cargo test
	sudo -E cargo test -- --nocapture
	sudo rm -rf target

test_container: docker-image ## Execute cargo test in container
	docker run --rm --device=/dev/kvm \
		--security-opt seccomp=unconfined \
		--volume `pwd`:/toyvmm -it ${DOCKER_IMAGE} \
		sh -c 'cd toyvmm; cargo test; rm -rf target'

.PHONT: help
help:
	@grep -E '^[a-zA-Z_-]+:.*##.*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*##"}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

