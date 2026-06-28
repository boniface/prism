SHELL := /bin/sh

CARGO ?= cargo
STABLE ?= stable
BPF_TARGET ?= bpfel-unknown-none
HOST_TARGET ?= $(shell rustc +$(STABLE) -vV | sed -n 's/^host: //p')
USER_TARGET ?= $(HOST_TARGET)
DIST_TARGET ?= x86_64-unknown-linux-musl
VERSION ?= 0.1.0-alpha.0
DEB_VERSION ?= $(shell ./scripts/package-versions.sh "$(VERSION)" | sed -n 's/^deb_version=//p')
RPM_VERSION ?= $(shell ./scripts/package-versions.sh "$(VERSION)" | sed -n 's/^rpm_version=//p')
RPM_RELEASE ?= $(shell ./scripts/package-versions.sh "$(VERSION)" | sed -n 's/^rpm_release=//p')
NIGHTLY ?= nightly
LLVM_PREFIX ?= $(shell brew --prefix llvm 2>/dev/null || true)

ifneq ($(LLVM_PREFIX),)
EBPF_ENV := LLVM_PREFIX=$(LLVM_PREFIX) DYLD_FALLBACK_LIBRARY_PATH=$(LLVM_PREFIX)/lib:$(DYLD_FALLBACK_LIBRARY_PATH)
endif

ifeq ($(USER_TARGET),$(HOST_TARGET))
USER_BUILD_ARGS :=
else
USER_BUILD_ARGS := --target $(USER_TARGET)
endif

.PHONY: audit build ci dev dist docker-smoke ebpf fmt lint package package-build package-deb package-helm package-rpm package-tar perf setup test

setup:
	./scripts/setup-dev.sh

dev:
	$(CARGO) +$(STABLE) build --workspace --exclude prism-ebpf

fmt:
	$(CARGO) +$(STABLE) fmt --all --check

lint:
	$(CARGO) +$(STABLE) clippy --workspace --all-targets --all-features --exclude prism-ebpf -- -D warnings -W clippy::pedantic
	$(EBPF_ENV) $(CARGO) +$(NIGHTLY) clippy -Z build-std=core -p prism-ebpf --target $(BPF_TARGET) -- -D warnings -W clippy::pedantic

test:
	$(CARGO) +$(STABLE) test --workspace --exclude prism-ebpf

perf:
	$(CARGO) +$(STABLE) bench -p prism-agent

ebpf:
	$(EBPF_ENV) $(CARGO) +$(NIGHTLY) build -Z build-std=core -p prism-ebpf --release --target $(BPF_TARGET)

build: ebpf
	$(CARGO) +$(STABLE) build -p prism-agent --release $(USER_BUILD_ARGS)

audit:
	if [ -d target/advisory-db/.git ]; then \
		$(CARGO) +$(STABLE) audit --db target/advisory-db --no-fetch --stale; \
	else \
		$(CARGO) +$(STABLE) audit --db target/advisory-db; \
	fi
	$(CARGO) +$(STABLE) deny check bans licenses sources

ci: fmt lint test ebpf audit

docker-smoke:
	./scripts/docker-compose-smoke.sh

package: package-tar

package-build: ebpf
	$(CARGO) +$(STABLE) build -p prism-agent --release --target $(DIST_TARGET)

package-tar: package-build
	./scripts/package-tar.sh "$(VERSION)" "$(DIST_TARGET)"

package-deb: package-build
	$(CARGO) +$(STABLE) deb -p prism-agent --target "$(DIST_TARGET)" --no-build --deb-version "$(DEB_VERSION)" --output "target/dist/prism-agent_$(VERSION)_amd64.deb"

package-rpm: package-build
	$(CARGO) +$(STABLE) generate-rpm -p prism-agent --target "$(DIST_TARGET)" --set-metadata 'version = "$(RPM_VERSION)"' --set-metadata 'release = "$(RPM_RELEASE)"' --output "target/dist/prism-agent-$(VERSION).x86_64.rpm"

package-helm:
	helm lint deploy/helm/prism-agent
	helm package deploy/helm/prism-agent --version "$(VERSION)" --app-version "$(VERSION)" --destination target/dist

dist: package-tar package-deb package-rpm package-helm
