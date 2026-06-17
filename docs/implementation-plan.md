# Prism Production Implementation Plan

This plan turns `docs/spec.md` into the full set of phases and tickets required to call Prism production-grade. It is intentionally broader than the first usable agent milestone. If a capability is required for the production product, it is represented here as a phase or ticket.

## Definition Of Done

Prism is production-grade when:

- The agent safely loads, attaches, detaches, and reconciles eBPF resources across normal shutdowns and crash restarts.
- Infrastructure metrics, security audit events, metadata resolution, application telemetry, and encrypted-traffic visibility work across the supported platforms.
- Docker, Kubernetes, Uncloud/systemd, and bare metal deployments are documented, packaged, tested, and releasable.
- Manual GitHub releases produce signed binaries, packages, container images, SBOMs, checksums, and release notes.
- Kernel verifier tests, integration tests, performance tests, security tests, and platform smoke tests pass.
- Production operations are documented, including upgrades, rollback, troubleshooting, capacity guidance, and security posture.

Every ticket must pass:

- `make fmt`
- `make lint`
- `make test`
- `make ebpf`
- `make audit`

Performance-sensitive tickets must also pass `make perf`.

## Phase 0: Foundation And Lifecycle

Status: in progress. The workspace, Makefile, setup gate, CI, shared types, cgroup detection skeleton, metadata traits, Docker provider skeleton, performance benchmark target, and minimal eBPF lifecycle proof exist.

### P0-01: Verify Lifecycle Proof On Linux

Goal: prove the current lifecycle implementation on a Linux host or VM.

Tasks:

- Run `scripts/setup-dev.sh` on Ubuntu 22.04+ or equivalent Linux VM.
- Run `make ci`.
- Run `make build`.
- Run `prism-agent` with `PRISM_EBPF_OBJECT=target/bpfel-unknown-none/release/prism-ebpf`.
- Confirm the lifecycle tracepoint attaches.
- Stop with `SIGINT` and confirm clean detach.

Acceptance criteria:

- Agent starts on Linux with required capabilities.
- eBPF object loads successfully.
- Tracepoint attaches successfully.
- Agent exits cleanly on `Ctrl-C`.
- No Prism-owned stale pins remain after normal shutdown.

### P0-02: Add Linux Lifecycle Integration Test

Goal: automate lifecycle proof on Linux.

Tasks:

- Add a capability-gated integration test for eBPF load, attach, and detach.
- Test the missing-object path without root privileges.
- Test the real eBPF path only when Linux, BTF, bpffs, and capabilities are available.
- Document how to run the privileged test locally.

Acceptance criteria:

- Normal `make test` remains unprivileged.
- Linux privileged lifecycle test can be run explicitly.
- Test verifies attach and detach without leaving stale pins.

### P0-03: Harden Pin Reconciliation

Goal: make stale pin cleanup safe enough for production.

Tasks:

- Add an agent instance ID format.
- Add boot ID detection.
- Add versioned pin name helper.
- Restrict cleanup to Prism-owned paths.
- Add tests proving unrelated files outside the pin root are untouched.

Acceptance criteria:

- Reconciliation never traverses outside configured Prism pin root.
- Stale Prism-owned resources are removed before new attach.
- Unit tests cover nested directories, files, missing roots, and unrelated paths.

## Phase 1: Configuration And Runtime Foundation

### P1-01: Implement Config File Loading

Goal: support `/etc/prism/config.yaml` and environment overrides.

Tasks:

- Add typed config structs.
- Parse YAML config.
- Add environment variable overrides.
- Validate required fields.
- Add example config at `config/example.yaml`.

Acceptance criteria:

- Invalid config returns structured errors.
- Sensitive values are never logged.
- Unit tests cover defaults, env overrides, and validation errors.

### P1-02: Implement Cgroup v2 Identity Resolution

Goal: map processes and events to cgroup v2 paths and IDs.

Tasks:

- Read process cgroup data from `/proc/<pid>/cgroup`.
- Parse cgroup v2 paths.
- Add cgroup ID newtype usage across agent APIs.
- Add bounded cache for PID to cgroup lookup.

Acceptance criteria:

- cgroup v1 produces a clear unsupported error.
- cgroup v2 paths parse deterministically.
- Tests cover systemd, Docker, containerd, and Kubernetes-style paths.

### P1-03: Add Metadata Cache

Goal: provide a bounded cache for runtime metadata.

Tasks:

- Implement cache with TTL or event-driven invalidation hooks.
- Add cache hit, miss, stale, and eviction counters.
- Ensure locks are not held across async I/O.

Acceptance criteria:

- Cache size is bounded.
- Tests cover hit, miss, update, eviction, and expiry behavior.
- No async lock is held across external I/O.

### P1-04: Implement Agent Task Runtime

Goal: give all processors and exporters a structured lifecycle.

Tasks:

- Add `CancellationToken`-based task orchestration.
- Add bounded channels for kernel events.
- Add graceful shutdown ordering.
- Add task error propagation and health state.

Acceptance criteria:

- All long-running tasks stop on cancellation.
- Shutdown drains bounded queues within configured timeout.
- Task failures are visible through health/self-metrics.

## Phase 2: Metadata Providers

### P2-01: Implement Docker Provider

Goal: resolve Docker containers from cgroup IDs.

Tasks:

- Connect to Docker socket read-only.
- List existing containers on startup.
- Watch container start/stop events.
- Map container IDs and names to cgroup paths.

Acceptance criteria:

- Docker metadata includes container ID and name.
- Provider handles Docker socket unavailability gracefully.
- Unit tests use mocked Docker responses.
- Docker Compose smoke test resolves container metadata.

### P2-02: Implement CRI Provider

Goal: resolve Kubernetes/containerd/CRI-O containers through CRI.

Tasks:

- Connect to configured CRI socket.
- List pods and containers.
- Watch runtime changes where supported.
- Map container metadata to cgroup paths.

Acceptance criteria:

- Metadata includes container ID, pod name, namespace, and container name when available.
- Provider works with containerd.
- Provider fails soft when CRI socket is unavailable.
- `kind` smoke test resolves pod metadata.

### P2-03: Implement Kubernetes API Enrichment

Goal: enrich CRI metadata with safe Kubernetes API data.

Tasks:

- Add read-only Kubernetes client.
- Watch pods, namespaces, and nodes.
- Add allowlist for labels and annotations.
- Add RBAC manifests to Helm chart.

Acceptance criteria:

- Agent continues working when Kubernetes API is unavailable.
- RBAC grants only `get`, `list`, and `watch` on required resources.
- Labels and annotations are allowlisted by default.

### P2-04: Implement Systemd And Uncloud Provider

Goal: resolve bare metal and Uncloud process metadata.

Tasks:

- Parse systemd cgroup v2 slice paths.
- Resolve service/unit names.
- Add optional Uncloud API enrichment.
- Keep Uncloud credentials out of logs.

Acceptance criteria:

- Bare metal processes are labeled with systemd unit or slice where available.
- Uncloud metadata is optional.
- Tests cover common systemd slice path formats.

## Phase 3: Metrics Pipeline

### P3-01: Add Kernel Metric Event Maps

Goal: introduce eBPF maps for per-cgroup metrics.

Tasks:

- Add per-cgroup metric map definitions.
- Add shared metric event layout tests.
- Add ring buffer drop counters.

Acceptance criteria:

- eBPF verifier accepts maps.
- User-space can read metric values.
- Layout tests protect shared ABI.

### P3-02: Implement CPU Scheduling Counters

Goal: collect per-cgroup CPU runtime counters.

Tasks:

- Attach scheduler tracepoints.
- Attribute runtime to cgroup ID.
- Export monotonic counters to user-space.

Acceptance criteria:

- CPU metrics are visible per cgroup.
- Load test shows counters increasing under CPU load.
- No verifier rejection on supported kernels.

### P3-03: Implement Memory Metrics

Goal: collect memory usage and pressure metrics.

Tasks:

- Read cgroup v2 memory counters from user-space.
- Correlate memory metrics with runtime metadata.
- Add memory pressure and limit metrics where available.

Acceptance criteria:

- Per-cgroup memory metrics are exposed.
- Missing memory files degrade gracefully.
- Tests cover cgroup v2 memory file parsing.

### P3-04: Implement Disk And Block I/O Metrics

Goal: collect per-cgroup disk I/O metrics.

Tasks:

- Read cgroup v2 I/O counters.
- Add optional block tracepoint enrichment where safe.
- Export read/write bytes and operations.

Acceptance criteria:

- Per-cgroup disk metrics are exposed.
- Disk metrics work without elevated capabilities beyond the standard profile where possible.
- Tests cover cgroup v2 I/O parsing.

### P3-05: Implement Network Counters

Goal: collect per-cgroup network counters.

Tasks:

- Attach TC hooks only when enabled.
- Count packets and bytes.
- Add drop counters.

Acceptance criteria:

- Network counters are visible per cgroup.
- `NET_ADMIN` is required only when TC hooks are enabled.
- Agent can run with network hooks disabled.

### P3-06: Implement Prometheus Exporter

Goal: expose metrics at `/metrics`.

Tasks:

- Add HTTP server.
- Export agent self-metrics.
- Export infrastructure metrics.
- Add bounded/sanitized labels.

Acceptance criteria:

- `curl http://127.0.0.1:9090/metrics` returns Prometheus text format.
- High-cardinality labels are disabled by default.
- Docker Compose smoke test scrapes metrics.

### P3-07: Add Metrics Cardinality Controls

Goal: prevent telemetry cost and backend overload.

Tasks:

- Add allowlist for labels.
- Add label length limits.
- Add series cardinality counters.
- Add config to disable expensive dimensions.

Acceptance criteria:

- Default labels are bounded and stable.
- High-cardinality labels require explicit opt-in.
- Cardinality counters are exported.

## Phase 4: Security Audit Pipeline

### P4-01: Implement `execve` eBPF Event

Goal: capture process execution audit events.

Tasks:

- Attach to `execve` tracepoint.
- Capture PID, PPID, UID, GID, cgroup ID, comm, timestamp.
- Use bounded field lengths.
- Submit event through ring buffer.

Acceptance criteria:

- Event layout is POD and covered by tests.
- Running a process emits a `ProcessExec` event.
- No command-line arguments are captured by default.

### P4-02: Implement File Access Audit Events

Goal: audit sensitive file reads without flooding logs.

Tasks:

- Add file access hooks for approved sensitive path monitoring.
- Add allowlist/denylist policy.
- Capture bounded path metadata.
- Avoid capturing file contents.

Acceptance criteria:

- Reading configured sensitive paths emits security events.
- File contents are never captured.
- Path capture is bounded and redacted where configured.

### P4-03: Implement Network Security Events

Goal: audit suspicious connection activity.

Tasks:

- Emit connection open/close events.
- Add process and cgroup attribution.
- Add optional destination allowlist policy.

Acceptance criteria:

- Connection events include process/runtime metadata.
- Policy violations are labeled with severity.
- Event volume is bounded by sampling or policy.

### P4-04: Implement Security Processor

Goal: consume kernel security events in user-space.

Tasks:

- Decode ring buffer events.
- Enrich with metadata.
- Apply redaction and field policy.
- Add event size limits.

Acceptance criteria:

- Processor handles malformed or partial events safely.
- Sensitive fields are redacted before export.
- Tests cover field caps and redaction.

### P4-05: Implement OTLP Logs Exporter

Goal: export security audit events through OTLP logs.

Tasks:

- Add OpenTelemetry crates from the approved family.
- Implement OTLP gRPC logs export.
- Add retry/backoff behavior.
- Add local collector integration test.

Acceptance criteria:

- Local OpenTelemetry Collector receives security logs.
- Export failures do not crash the agent.
- No sensitive values are logged by exporter internals.

## Phase 5: Application And Network Telemetry

### P5-01: Implement Connection-Level Telemetry For All Traffic

Goal: observe encrypted and plaintext traffic without requiring payload visibility.

Tasks:

- Track TCP connection lifecycle.
- Attribute flows to process and cgroup.
- Export connection metrics and spans.
- Avoid payload capture.

Acceptance criteria:

- Encrypted traffic produces connection-level telemetry.
- Plaintext traffic produces connection-level telemetry.
- No decrypted payload is captured by default.

### P5-02: Implement Plaintext HTTP/1.1 Parser

Goal: safely parse visible HTTP metadata.

Tasks:

- Add bounded packet parser.
- Extract method, status, and protocol where visible.
- Add fuzz target.
- Add packet bounds tests.

Acceptance criteria:

- Parser never reads beyond packet bounds.
- Fuzz target runs without panic.
- HTTP metrics are emitted only when metadata is visible.

### P5-03: Implement SQL And Cache Protocol Metrics

Goal: add production-safe semantic metrics for common protocols.

Tasks:

- Add Postgres parser for bounded metadata.
- Add Redis parser for bounded metadata.
- Add fuzz targets.
- Add opt-in config per protocol.

Acceptance criteria:

- Parsers do not capture raw sensitive query payloads by default.
- Fuzz targets run without panic.
- Protocol metrics are opt-in until validated.

### P5-04: Implement Trace Context Extraction

Goal: correlate visible request metadata into traces.

Tasks:

- Parse W3C `traceparent` where visible.
- Generate server/client spans where safe.
- Add span queue and exporter integration.

Acceptance criteria:

- Visible trace context creates correlated spans.
- Missing trace context creates valid root spans when configured.
- Span queues are bounded.

### P5-05: Implement TLS Uprobe Support

Goal: support encrypted request metadata for approved libraries.

Tasks:

- Add architecture decision for supported TLS libraries.
- Implement OpenSSL uprobes if approved.
- Evaluate BoringSSL and rustls.
- Add privacy controls and opt-in config.

Acceptance criteria:

- TLS tracing is disabled by default.
- Supported libraries are allowlisted.
- No TLS keys, secrets, cookies, authorization headers, or bodies are exported.
- Unsupported TLS libraries fall back to connection-level telemetry.

### P5-06: Implement OTLP Traces Exporter

Goal: export traces to an OpenTelemetry Collector.

Tasks:

- Add OTLP gRPC trace exporter.
- Add batching and retry policy.
- Add local collector integration test.

Acceptance criteria:

- Local collector receives spans.
- Export failures do not block kernel event processing.
- Trace exporter obeys shutdown drain timeout.

## Phase 6: Policy, Detection, And Controls

### P6-01: Implement Security Policy Configuration

Goal: define user-configurable audit and alert policy.

Tasks:

- Add policy config schema.
- Add file path rules.
- Add process execution rules.
- Add network destination rules.

Acceptance criteria:

- Invalid policy fails config validation.
- Policy can be reloaded on restart.
- Tests cover rule matching and precedence.

### P6-02: Implement Severity And Alert Enrichment

Goal: produce actionable security events.

Tasks:

- Add severity model.
- Add event categories.
- Add policy match context.
- Add stable event IDs.

Acceptance criteria:

- Security events include severity and category.
- Policy match context avoids sensitive payloads.
- Event IDs are stable and documented.

### P6-03: Implement High-Cardinality Field Controls

Goal: enforce safe defaults for expensive or sensitive fields.

Tasks:

- Add per-event field allowlists.
- Add global length and event-size caps.
- Add redaction rules.
- Add tests for command lines, paths, labels, annotations, and SQL text.

Acceptance criteria:

- High-cardinality fields are opt-in per event type.
- Defaults are safe for production.
- Redaction occurs before export.

## Phase 7: Deployment And Packaging

### P7-01: Add Docker Image And Compose Manifest

Goal: run Prism through Docker.

Tasks:

- Add minimal production Dockerfile.
- Add Compose manifest.
- Mount required host paths.
- Add Docker provider configuration.

Acceptance criteria:

- `docker compose up -d` starts agent.
- `/metrics` is scrapeable.
- Docker metadata resolves.
- Compose teardown leaves no stale Prism-owned pins after restart reconciliation.

### P7-02: Add Helm Chart

Goal: deploy Prism as a Kubernetes DaemonSet.

Tasks:

- Add DaemonSet, ServiceAccount, RBAC, ConfigMap, and Service.
- Add default and production values.
- Add CRI socket configuration.
- Add optional Kubernetes API enrichment RBAC.

Acceptance criteria:

- `helm template` succeeds.
- `kind` smoke test rolls out DaemonSet.
- `/metrics` can be scraped or port-forwarded.
- Pod metadata resolves.

### P7-03: Add Systemd Packaging

Goal: support bare metal and Uncloud installs.

Tasks:

- Add systemd service.
- Add example `/etc/prism/config.yaml`.
- Add Debian package build.
- Add RPM package build.
- Preserve existing config on upgrade.

Acceptance criteria:

- Debian package installs and starts service.
- RPM package installs and starts service.
- Upgrades preserve `/etc/prism/config.yaml`.
- `systemctl stop prism-agent` exits cleanly.

### P7-04: Add Release Artifacts And Signing

Goal: produce release artifacts through CI.

Tasks:

- Generate static tarball.
- Generate SBOM.
- Generate checksums.
- Sign artifacts and container images.
- Upload to draft GitHub Release.

Acceptance criteria:

- Manual GitHub release workflow creates all artifacts.
- Stable release requires maintainer approval before publish.
- GHCR image is pushed only through release workflow.

## Phase 8: Integration, Reliability, And Hardening

### P8-01: Add Linux Kernel Matrix Verifier Tests

Goal: prevent verifier regressions.

Tasks:

- Add CI or scripted tests for supported kernel versions.
- Test eBPF load on 5.10, 5.15, 6.1, and latest LTS where practical.
- Store verifier logs on failure.

Acceptance criteria:

- Verifier tests pass on supported kernel matrix.
- Failure logs are attached to CI artifacts.

### P8-02: Add Crash Recovery Test

Goal: prove forced kill and restart does not accumulate stale Prism resources.

Tasks:

- Start agent on Linux.
- Kill with `SIGKILL`.
- Restart agent.
- Repeat loop.
- Check Prism-owned map/link counts.

Acceptance criteria:

- Forced kill-and-restart loop does not increase Prism-owned pinned map or link count after startup reconciliation.
- Test documents required privileges.

### P8-03: Add End-To-End Platform Smoke Tests

Goal: validate the four supported environments.

Tasks:

- Docker smoke test.
- Kubernetes `kind` smoke test.
- Bare metal/systemd smoke test.
- Uncloud/systemd smoke test or documented manual test path.

Acceptance criteria:

- Each platform guide includes install, validate, logs, upgrade, and uninstall.
- Each smoke test verifies `/metrics`.
- Metadata resolution is validated per platform.

### P8-04: Add Chaos And Soak Tests

Goal: test stability under long-running and failure conditions.

Tasks:

- Add 24-hour soak profile.
- Add forced collector outage test.
- Add runtime socket outage test.
- Add high event-rate test.

Acceptance criteria:

- Agent memory remains bounded.
- Exporter outages do not block kernel event processing.
- Ring buffer drops are counted and exported.
- Agent recovers when dependencies return.

## Phase 9: Performance And Capacity

### P9-01: Expand Performance Benchmark Suite

Goal: make `make perf` representative of production hot paths.

Tasks:

- Benchmark event decode.
- Benchmark metadata cache lookup.
- Benchmark ring buffer batch processing.
- Benchmark exporter serialization.
- Benchmark label sanitization.

Acceptance criteria:

- Benchmarks have stable names.
- Results are stored under Criterion output.
- Performance-sensitive PRs include benchmark comparison.

### P9-02: Add Load Test Profiles

Goal: measure host overhead under realistic load.

Tasks:

- Add CPU load profile.
- Add network load profile.
- Add process-exec storm profile.
- Add mixed workload profile.

Acceptance criteria:

- CPU overhead target is measured.
- RSS target is measured.
- Ring buffer drops are measured.
- Results are documented.

### P9-03: Add Capacity Guidance

Goal: document sizing and tuning for production operators.

Tasks:

- Document queue sizing.
- Document map sizing.
- Document exporter batching.
- Document high-cardinality controls.

Acceptance criteria:

- Operators can tune Prism for small, medium, and large nodes.
- Unsafe defaults are avoided.
- Docs include failure modes and symptoms.

## Phase 10: Agent Self-Observability

### P10-01: Add Agent Health Endpoint

Goal: expose agent health for operators.

Tasks:

- Add `/healthz`.
- Add `/readyz`.
- Include exporter, metadata, and eBPF health states.

Acceptance criteria:

- Health endpoint does not require backend availability.
- Readiness fails when critical pipelines are unavailable.
- Kubernetes probes are wired to endpoints.

### P10-02: Add Agent Self-Metrics

Goal: expose internal operational metrics.

Tasks:

- Export queue depth.
- Export dropped events.
- Export metadata cache stats.
- Export exporter retry counts.
- Export eBPF attach state.

Acceptance criteria:

- Self-metrics are visible in Prometheus.
- Metrics have bounded labels.
- Metrics are documented.

### P10-03: Add Structured Logging

Goal: make debugging safe and predictable.

Tasks:

- Add JSON log option.
- Add log levels per subsystem.
- Add redaction for sensitive fields.

Acceptance criteria:

- Logs never include secrets.
- Logs include agent instance ID and node name.
- Debug logging is opt-in.

## Phase 11: Security Review And Compliance

### P11-01: Add Security Review Checklist

Goal: make production readiness review repeatable.

Tasks:

- Add checklist for capabilities.
- Add checklist for RBAC.
- Add checklist for sensitive field policy.
- Add checklist for release signing and SBOM.

Acceptance criteria:

- Security checklist is stored in `docs/`.
- Release cannot be marked stable until checklist is completed.

### P11-02: Add Threat Model

Goal: document Prism's attack surface.

Tasks:

- Model eBPF loading risks.
- Model runtime socket access risks.
- Model telemetry exfiltration risks.
- Model Kubernetes RBAC risks.
- Model supply chain risks.

Acceptance criteria:

- Threat model is stored in `docs/`.
- Mitigations map to tickets or implementation.
- Stable release requires threat model review.

### P11-03: Add Supply Chain Policy

Goal: formalize dependency and release security.

Tasks:

- Document dependency approval.
- Document license policy.
- Document vulnerability response.
- Document signing and provenance.

Acceptance criteria:

- `cargo audit` and `cargo deny` policies match docs.
- Release artifacts include SBOM and signatures.
- Vulnerability response path is documented.

## Phase 12: Production Documentation

### P12-01: Add Operator Guide

Goal: provide end-to-end production operating docs.

Tasks:

- Document Docker operation.
- Document Kubernetes operation.
- Document bare metal/systemd operation.
- Document Uncloud operation.
- Document config reference.

Acceptance criteria:

- Each platform has install, validate, logs, upgrade, rollback, and uninstall steps.
- Config reference covers every setting.
- Troubleshooting section covers common failures.

### P12-02: Add Developer Guide

Goal: make development onboarding repeatable.

Tasks:

- Document Linux VM setup.
- Document macOS editing limitations.
- Document eBPF build flow.
- Document privileged tests.
- Document Makefile targets.

Acceptance criteria:

- New developer can reach `make ci`.
- Linux runtime requirements are clear.
- eBPF troubleshooting steps are documented.

### P12-03: Add Architecture Guide

Goal: explain the system beyond the spec.

Tasks:

- Document data flow.
- Document module boundaries.
- Document event schemas.
- Document lifecycle and shutdown.
- Document pin reconciliation.

Acceptance criteria:

- Guide references diagrams in `docs/`.
- Guide reflects current implementation.
- Public concepts align with code names.

## Phase 13: Release Automation

### P13-01: Implement Manual GitHub Release Workflow

Goal: release only through approved manual process.

Tasks:

- Add `workflow_dispatch` release workflow.
- Validate semver tag.
- Build all artifacts.
- Generate release notes.
- Create draft GitHub Release.

Acceptance criteria:

- Release is never published automatically from merge.
- Draft release requires maintainer approval.
- Workflow refuses duplicate version tags.

### P13-02: Implement Artifact Provenance

Goal: make artifacts verifiable.

Tasks:

- Generate provenance attestations.
- Sign artifacts with Cosign.
- Sign container image.
- Attach checksums.

Acceptance criteria:

- Users can verify binary, package, and image integrity.
- Provenance is attached to GitHub Release.
- Stable release fails if signing fails.

### P13-03: Implement Rollback Procedure

Goal: make production rollback safe.

Tasks:

- Document rollback for Docker.
- Document rollback for Helm.
- Document rollback for systemd packages.
- Document `latest` tag policy.

Acceptance criteria:

- Broken releases are deprecated, not deleted.
- Patch release procedure is documented.
- `latest` moves only after stable validation.

## Phase 14: Production Readiness Validation

### P14-01: Run Full Platform Certification

Goal: certify supported environments.

Tasks:

- Certify Docker deployment.
- Certify Kubernetes deployment.
- Certify Uncloud/systemd deployment.
- Certify bare metal deployment.

Acceptance criteria:

- All platform smoke tests pass.
- Install, upgrade, rollback, and uninstall are validated.
- Metadata resolution works on every platform.

### P14-02: Run Full Performance Certification

Goal: validate production overhead targets.

Tasks:

- Run load profiles.
- Run 24-hour soak.
- Record CPU overhead.
- Record RSS.
- Record ring buffer drops.

Acceptance criteria:

- CPU overhead target is met.
- RSS target is met.
- Drops are zero in the standard benchmark profile.
- Results are attached to release notes.

### P14-03: Run Full Security Certification

Goal: validate production security posture.

Tasks:

- Complete security checklist.
- Review threat model.
- Validate least privilege capabilities.
- Validate Kubernetes RBAC.
- Validate no secret logging.

Acceptance criteria:

- Security review is signed off.
- No critical/high unignored vulnerabilities remain.
- Release artifacts are signed.

## Completion Checklist

Prism can be called production-grade when:

- All Phase 0 through Phase 14 tickets are complete.
- `make ci` passes.
- `make perf` passes and production load targets are met.
- Linux lifecycle integration test passes.
- Kernel verifier matrix passes.
- Docker, Kubernetes, Uncloud/systemd, and bare metal certification passes.
- Application telemetry supports plaintext HTTP, connection-level encrypted traffic, and approved TLS uprobe integrations.
- Metrics, traces, security logs, and self-observability are exported with bounded cardinality.
- Manual GitHub release workflow produces all required artifacts.
- Security review, threat model, and supply chain policy are complete.
- `docs/spec.md` acceptance criteria are satisfied or superseded by explicit architecture decisions.
