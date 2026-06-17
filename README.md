# Prism

Prism is a Rust and eBPF observability agent for Linux hosts. The repository is a multi-crate workspace, but the product is distributed as one executable: `prism-agent`.

## Status

This project is at the v0.1 development baseline. The first milestone proves the eBPF lifecycle: start the agent, load a tiny eBPF program, create a map, attach to a tracepoint, detach on shutdown, and reconcile stale Prism-owned pins on restart.

## Repository Layout

- `prism-core`: shared `no_std` event and ID types.
- `prism-ebpf`: kernel-space eBPF programs.
- `prism-agent`: user-space daemon and the shipped binary.
- `docs/spec.md`: technical specification and architecture decisions.
- `docs/implementation-plan.md`: phased implementation plan and tickets.
- `docs/`: architecture diagrams.

## Development

Use the Makefile targets. Raw Cargo command sequences are not the supported workflow for standard checks.

```bash
./scripts/setup-dev.sh
make dev
make lint
make test
make ebpf
make perf
make build
```

The eBPF lifecycle proof requires Linux with cgroup v2, BTF, bpffs mounted at `/sys/fs/bpf`, `bpf-linker`, nightly Rust with `rust-src`, and permission to load eBPF programs.

## Running The Lifecycle Proof

```bash
make ebpf
PRISM_EBPF_OBJECT=target/bpfel-unknown-none/release/prism-ebpf \
  sudo -E ./target/release/prism-agent
```

Press `Ctrl-C` to detach and exit cleanly.

## License

Prism is licensed under the Apache License, Version 2.0.
