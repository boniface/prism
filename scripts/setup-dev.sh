#!/usr/bin/env bash
set -euo pipefail

missing=0

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "missing command: $1"
        missing=1
    fi
}

require_rust_component() {
    if ! rustup component list --installed | grep -Eq "^$1($|-)"; then
        echo "missing rust component: $1"
        echo "install with: rustup component add $1"
        missing=1
    fi
}

require_rust_target() {
    if ! rustup target list --installed | grep -qx "$1"; then
        echo "missing rust target: $1"
        echo "install with: rustup target add $1"
        missing=1
    fi
}

require_command cargo
require_command rustup
require_command make
require_command clang
require_command bpftool
require_command bpf-linker

require_rust_component clippy
require_rust_component rustfmt
require_rust_component rust-src

require_rust_target x86_64-unknown-linux-musl

if ! rustup toolchain list | grep -q '^nightly'; then
    echo "missing nightly Rust toolchain"
    echo "install with: rustup toolchain install nightly --component rust-src,clippy,rustfmt"
    missing=1
fi

if ! rustup +nightly component list --installed | grep -qx "rust-src"; then
    echo "missing nightly rust-src component"
    echo "install with: rustup +nightly component add rust-src"
    missing=1
fi

if ! rustup +nightly component list --installed | grep -Eq "^clippy($|-)"; then
    echo "missing nightly clippy component"
    echo "install with: rustup +nightly component add clippy"
    missing=1
fi

if [ "$(uname -s)" = "Darwin" ]; then
    if ! command -v brew >/dev/null 2>&1 || ! brew --prefix llvm >/dev/null 2>&1; then
        echo "missing Homebrew LLVM"
        echo "install with: brew install llvm"
        missing=1
    fi
fi

if [ ! -f /sys/kernel/btf/vmlinux ]; then
    echo "missing BTF file: /sys/kernel/btf/vmlinux"
    echo "use a Linux host or VM with BTF-enabled kernel support"
    missing=1
fi

if ! mount | grep -q " on /sys/fs/bpf "; then
    echo "bpffs is not mounted at /sys/fs/bpf"
    echo "mount with: sudo mount -t bpf bpf /sys/fs/bpf"
    missing=1
fi

if [ "$missing" -ne 0 ]; then
    echo "development environment check failed"
    exit 1
fi

echo "development environment check passed"
