# Contributing To Prism

Prism runs eBPF programs on Linux hosts, so safety and reproducibility matter more than speed of feature delivery.

## Required Workflow

Use the Makefile gates before opening a pull request:

```bash
make fmt
make lint
make test
make ebpf
make audit
```

`make lint` runs clippy with `-D warnings` and `-W clippy::pedantic`. Fix pedantic findings directly. Do not add `#[allow(clippy::...)]`, relax lint flags, hide code behind feature gates, or create alternate targets that bypass lint failures.

## Rust Standards

- Keep `main.rs` minimal and place logic in libraries.
- Use the `mod` plus `pub use` re-export pattern.
- Keep every `mod.rs` file limited to module declarations and re-exports.
- Prefer borrowing over cloning.
- Return `Result` for fallible operations.
- Never use `.unwrap()` in production code.
- Use `.expect()` only for invariant violations with descriptive messages.
- Add unit tests for new functions and types.
- Add `// SAFETY:` comments for every unsafe block.

## Architecture Changes

`docs/spec.md` is the v0.1 development baseline. Material scope, safety, deployment, or release changes must be added as architecture decisions in that document rather than silently rewriting requirements.

## Security

Do not commit secrets, tokens, credentials, customer data, or host-specific private configuration. Sensitive runtime configuration must come from environment variables or secret files.
