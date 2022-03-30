#!/usr/bin/make -f

CARGO := cargo

IMAGE_TAG := 0.0.1
DOCKER_IMAGE := aztecher/toyvmm:${IMAGE_TAG}

DEFAULT_TARGET := help

# list up all targets
ALL_TARGET := filename

target: $(DEFAULT_TARGET) ## help

all: $(ALL_TARGET) ## Make all files

docker-image: ## Build docker image
	docker build -t ${DOCKER_IMAGE} .

run: ## Execute cargo run
	sudo -E cargo run
	sudo rm -rf target

run_container: docker-image
	docker run --rm --device=/dev/kvm \
		--security-opt seccomp=unconfined \
		--volume `pwd`:/toyvmm -it ${DOCKER_IMAGE} \
		sh -c 'cd toyvmm; cargo run; rm -rf target'

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

