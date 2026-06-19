#!/usr/bin/env bash
# =============================================================================
# Prism – GitHub Issue Creation Script
# Creates all tickets from docs/implementation-plan.md across Phases 0–14
#
# Usage:
#   chmod +x create_prism_issues.sh
#   gh auth login          # only needed once
#   ./create_prism_issues.sh
#
# Requirements:
#   - GitHub CLI (gh) installed and authenticated
#   - You must be a collaborator on miketyo/prism
#
# The script will:
#   1. Create labels for each phase
#   2. Create all issues with title, body, and phase label
#   3. Print a summary at the end
# =============================================================================

set -euo pipefail

REPO="boniface/prism"
CREATED=0
FAILED=0

echo "============================================="
echo " Prism Issue Creation Script"
echo " Target repo: $REPO"
echo "============================================="
echo ""

# -----------------------------------------------------------------------------
# Helper: create a single issue, with basic retry on failure
# -----------------------------------------------------------------------------
create_issue() {
  local title="$1"
  local body="$2"
  local label="$3"

  echo "Creating: [$label] $title"
  if gh issue create \
      --title "$title" \
      --body "$body" \
      --label "$label" \
      --repo "$REPO" > /dev/null 2>&1; then
    CREATED=$((CREATED + 1))
    echo "  ✓ Created"
  else
    FAILED=$((FAILED + 1))
    echo "  ✗ Failed – check permissions or duplicate title"
  fi
  # Small delay to avoid GitHub API rate limiting
  sleep 1
}

# -----------------------------------------------------------------------------
# Step 1: Create phase labels (ignore errors if they already exist)
# -----------------------------------------------------------------------------
echo "--- Creating phase labels ---"
LABELS=(
  "phase-0:Foundation And Lifecycle:0075ca"
  "phase-1:Configuration And Runtime:e4e669"
  "phase-2:Metadata Providers:d93f0b"
  "phase-3:Metrics Pipeline:0e8a16"
  "phase-4:Security Audit Pipeline:b60205"
  "phase-5:Application Telemetry:5319e7"
  "phase-6:Policy And Detection:f9d0c4"
  "phase-7:Deployment And Packaging:c2e0c6"
  "phase-8:Integration And Hardening:fef2c0"
  "phase-9:Performance And Capacity:bfd4f2"
  "phase-10:Agent Self-Observability:d4c5f9"
  "phase-11:Security Review:ee0701"
  "phase-12:Production Docs:0052cc"
  "phase-13:Release Automation:e4e669"
  "phase-14:Production Readiness:0e8a16"
)

for entry in "${LABELS[@]}"; do
  IFS=':' read -r name desc color <<< "$entry"
  gh label create "$name" --description "$desc" --color "$color" --repo "$REPO" 2>/dev/null || true
  echo "  Label: $name"
done
echo ""

# =============================================================================
# PHASE 0: Foundation And Lifecycle
# =============================================================================
echo "--- Phase 0: Foundation And Lifecycle ---"

create_issue \
  "P0-01: Verify Lifecycle Proof On Linux" \
  "## Goal
Prove the current lifecycle implementation on a Linux host or VM.

## Tasks
- [ ] Run \`scripts/setup-dev.sh\` on Ubuntu 22.04+ or equivalent Linux VM
- [ ] Run \`make ci\`
- [ ] Run \`make build\`
- [ ] Run \`prism-agent\` with \`PRISM_EBPF_OBJECT=target/bpfel-unknown-none/release/prism-ebpf\`
- [ ] Confirm the lifecycle tracepoint attaches
- [ ] Stop with \`SIGINT\` and confirm clean detach

## Acceptance Criteria
- Agent starts on Linux with required capabilities
- eBPF object loads successfully
- Tracepoint attaches successfully
- Agent exits cleanly on Ctrl-C
- No Prism-owned stale pins remain after normal shutdown

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-0"

create_issue \
  "P0-02: Add Linux Lifecycle Integration Test" \
  "## Goal
Automate lifecycle proof on Linux.

## Tasks
- [ ] Add a capability-gated integration test for eBPF load, attach, and detach
- [ ] Test the missing-object path without root privileges
- [ ] Test the real eBPF path only when Linux, BTF, bpffs, and capabilities are available
- [ ] Document how to run the privileged test locally

## Acceptance Criteria
- Normal \`make test\` remains unprivileged
- Linux privileged lifecycle test can be run explicitly
- Test verifies attach and detach without leaving stale pins

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-0"

create_issue \
  "P0-03: Harden Pin Reconciliation" \
  "## Goal
Make stale pin cleanup safe enough for production.

## Tasks
- [ ] Add an agent instance ID format
- [ ] Add boot ID detection
- [ ] Add versioned pin name helper
- [ ] Restrict cleanup to Prism-owned paths
- [ ] Add tests proving unrelated files outside the pin root are untouched

## Acceptance Criteria
- Reconciliation never traverses outside configured Prism pin root
- Stale Prism-owned resources are removed before new attach
- Unit tests cover nested directories, files, missing roots, and unrelated paths

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-0"

# =============================================================================
# PHASE 1: Configuration And Runtime Foundation
# =============================================================================
echo ""
echo "--- Phase 1: Configuration And Runtime Foundation ---"

create_issue \
  "P1-01: Implement Config File Loading" \
  "## Goal
Support \`/etc/prism/config.yaml\` and environment overrides.

## Tasks
- [ ] Add typed config structs
- [ ] Parse YAML config
- [ ] Add environment variable overrides
- [ ] Validate required fields
- [ ] Add example config at \`config/example.yaml\`

## Acceptance Criteria
- Invalid config returns structured errors
- Sensitive values are never logged
- Unit tests cover defaults, env overrides, and validation errors

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-1"

create_issue \
  "P1-02: Implement Cgroup v2 Identity Resolution" \
  "## Goal
Map processes and events to cgroup v2 paths and IDs.

## Tasks
- [ ] Read process cgroup data from \`/proc/<pid>/cgroup\`
- [ ] Parse cgroup v2 paths
- [ ] Add cgroup ID newtype usage across agent APIs
- [ ] Add bounded cache for PID to cgroup lookup

## Acceptance Criteria
- cgroup v1 produces a clear unsupported error
- cgroup v2 paths parse deterministically
- Tests cover systemd, Docker, containerd, and Kubernetes-style paths

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-1"

create_issue \
  "P1-03: Add Metadata Cache" \
  "## Goal
Provide a bounded cache for runtime metadata.

## Tasks
- [ ] Implement cache with TTL or event-driven invalidation hooks
- [ ] Add cache hit, miss, stale, and eviction counters
- [ ] Ensure locks are not held across async I/O

## Acceptance Criteria
- Cache size is bounded
- Tests cover hit, miss, update, eviction, and expiry behavior
- No async lock is held across external I/O

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-1"

create_issue \
  "P1-04: Implement Agent Task Runtime" \
  "## Goal
Give all processors and exporters a structured lifecycle.

## Tasks
- [ ] Add \`CancellationToken\`-based task orchestration
- [ ] Add bounded channels for kernel events
- [ ] Add graceful shutdown ordering
- [ ] Add task error propagation and health state

## Acceptance Criteria
- All long-running tasks stop on cancellation
- Shutdown drains bounded queues within configured timeout
- Task failures are visible through health/self-metrics

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-1"

# =============================================================================
# PHASE 2: Metadata Providers
# =============================================================================
echo ""
echo "--- Phase 2: Metadata Providers ---"

create_issue \
  "P2-01: Implement Docker Provider" \
  "## Goal
Resolve Docker containers from cgroup IDs.

## Tasks
- [ ] Connect to Docker socket read-only
- [ ] List existing containers on startup
- [ ] Watch container start/stop events
- [ ] Map container IDs and names to cgroup paths

## Acceptance Criteria
- Docker metadata includes container ID and name
- Provider handles Docker socket unavailability gracefully
- Unit tests use mocked Docker responses
- Docker Compose smoke test resolves container metadata

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-2"

create_issue \
  "P2-02: Implement CRI Provider" \
  "## Goal
Resolve Kubernetes/containerd/CRI-O containers through CRI.

## Tasks
- [ ] Connect to configured CRI socket
- [ ] List pods and containers
- [ ] Watch runtime changes where supported
- [ ] Map container metadata to cgroup paths

## Acceptance Criteria
- Metadata includes container ID, pod name, namespace, and container name when available
- Provider works with containerd
- Provider fails soft when CRI socket is unavailable
- \`kind\` smoke test resolves pod metadata

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-2"

create_issue \
  "P2-03: Implement Kubernetes API Enrichment" \
  "## Goal
Enrich CRI metadata with safe Kubernetes API data.

## Tasks
- [ ] Add read-only Kubernetes client
- [ ] Watch pods, namespaces, and nodes
- [ ] Add allowlist for labels and annotations
- [ ] Add RBAC manifests to Helm chart

## Acceptance Criteria
- Agent continues working when Kubernetes API is unavailable
- RBAC grants only \`get\`, \`list\`, and \`watch\` on required resources
- Labels and annotations are allowlisted by default

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-2"

create_issue \
  "P2-04: Implement Systemd And Uncloud Provider" \
  "## Goal
Resolve bare metal and Uncloud process metadata.

## Tasks
- [ ] Parse systemd cgroup v2 slice paths
- [ ] Resolve service/unit names
- [ ] Add optional Uncloud API enrichment
- [ ] Keep Uncloud credentials out of logs

## Acceptance Criteria
- Bare metal processes are labeled with systemd unit or slice where available
- Uncloud metadata is optional
- Tests cover common systemd slice path formats

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-2"

# =============================================================================
# PHASE 3: Metrics Pipeline
# =============================================================================
echo ""
echo "--- Phase 3: Metrics Pipeline ---"

create_issue \
  "P3-01: Add Kernel Metric Event Maps" \
  "## Goal
Introduce eBPF maps for per-cgroup metrics.

## Tasks
- [ ] Add per-cgroup metric map definitions
- [ ] Add shared metric event layout tests
- [ ] Add ring buffer drop counters

## Acceptance Criteria
- eBPF verifier accepts maps
- User-space can read metric values
- Layout tests protect shared ABI

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-3"

create_issue \
  "P3-02: Implement CPU Scheduling Counters" \
  "## Goal
Collect per-cgroup CPU runtime counters.

## Tasks
- [ ] Attach scheduler tracepoints
- [ ] Attribute runtime to cgroup ID
- [ ] Export monotonic counters to user-space

## Acceptance Criteria
- CPU metrics are visible per cgroup
- Load test shows counters increasing under CPU load
- No verifier rejection on supported kernels

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓
- \`make perf\` ✓" \
  "phase-3"

create_issue \
  "P3-03: Implement Memory Metrics" \
  "## Goal
Collect memory usage and pressure metrics.

## Tasks
- [ ] Read cgroup v2 memory counters from user-space
- [ ] Correlate memory metrics with runtime metadata
- [ ] Add memory pressure and limit metrics where available

## Acceptance Criteria
- Per-cgroup memory metrics are exposed
- Missing memory files degrade gracefully
- Tests cover cgroup v2 memory file parsing

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-3"

create_issue \
  "P3-04: Implement Disk And Block I/O Metrics" \
  "## Goal
Collect per-cgroup disk I/O metrics.

## Tasks
- [ ] Read cgroup v2 I/O counters
- [ ] Add optional block tracepoint enrichment where safe
- [ ] Export read/write bytes and operations

## Acceptance Criteria
- Per-cgroup disk metrics are exposed
- Disk metrics work without elevated capabilities beyond the standard profile where possible
- Tests cover cgroup v2 I/O parsing

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-3"

create_issue \
  "P3-05: Implement Network Counters" \
  "## Goal
Collect per-cgroup network counters.

## Tasks
- [ ] Attach TC hooks only when enabled
- [ ] Count packets and bytes
- [ ] Add drop counters

## Acceptance Criteria
- Network counters are visible per cgroup
- \`NET_ADMIN\` is required only when TC hooks are enabled
- Agent can run with network hooks disabled

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-3"

create_issue \
  "P3-06: Implement Prometheus Exporter" \
  "## Goal
Expose metrics at \`/metrics\`.

## Tasks
- [ ] Add HTTP server
- [ ] Export agent self-metrics
- [ ] Export infrastructure metrics
- [ ] Add bounded/sanitized labels

## Acceptance Criteria
- \`curl http://127.0.0.1:9090/metrics\` returns Prometheus text format
- High-cardinality labels are disabled by default
- Docker Compose smoke test scrapes metrics

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-3"

create_issue \
  "P3-07: Add Metrics Cardinality Controls" \
  "## Goal
Prevent telemetry cost and backend overload.

## Tasks
- [ ] Add allowlist for labels
- [ ] Add label length limits
- [ ] Add series cardinality counters
- [ ] Add config to disable expensive dimensions

## Acceptance Criteria
- Default labels are bounded and stable
- High-cardinality labels require explicit opt-in
- Cardinality counters are exported

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-3"

# =============================================================================
# PHASE 4: Security Audit Pipeline
# =============================================================================
echo ""
echo "--- Phase 4: Security Audit Pipeline ---"

create_issue \
  "P4-01: Implement execve eBPF Event" \
  "## Goal
Capture process execution audit events.

## Tasks
- [ ] Attach to \`execve\` tracepoint
- [ ] Capture PID, PPID, UID, GID, cgroup ID, comm, timestamp
- [ ] Use bounded field lengths
- [ ] Submit event through ring buffer

## Acceptance Criteria
- Event layout is POD and covered by tests
- Running a process emits a \`ProcessExec\` event
- No command-line arguments are captured by default

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-4"

create_issue \
  "P4-02: Implement File Access Audit Events" \
  "## Goal
Audit sensitive file reads without flooding logs.

## Tasks
- [ ] Add file access hooks for approved sensitive path monitoring
- [ ] Add allowlist/denylist policy
- [ ] Capture bounded path metadata
- [ ] Avoid capturing file contents

## Acceptance Criteria
- Reading configured sensitive paths emits security events
- File contents are never captured
- Path capture is bounded and redacted where configured

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-4"

create_issue \
  "P4-03: Implement Network Security Events" \
  "## Goal
Audit suspicious connection activity.

## Tasks
- [ ] Emit connection open/close events
- [ ] Add process and cgroup attribution
- [ ] Add optional destination allowlist policy

## Acceptance Criteria
- Connection events include process/runtime metadata
- Policy violations are labeled with severity
- Event volume is bounded by sampling or policy

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-4"

create_issue \
  "P4-04: Implement Security Processor" \
  "## Goal
Consume kernel security events in user-space.

## Tasks
- [ ] Decode ring buffer events
- [ ] Enrich with metadata
- [ ] Apply redaction and field policy
- [ ] Add event size limits

## Acceptance Criteria
- Processor handles malformed or partial events safely
- Sensitive fields are redacted before export
- Tests cover field caps and redaction

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-4"

create_issue \
  "P4-05: Implement OTLP Logs Exporter" \
  "## Goal
Export security audit events through OTLP logs.

## Tasks
- [ ] Add OpenTelemetry crates from the approved family (opentelemetry 0.32)
- [ ] Implement OTLP gRPC logs export
- [ ] Add retry/backoff behavior
- [ ] Add local collector integration test

## Acceptance Criteria
- Local OpenTelemetry Collector receives security logs
- Export failures do not crash the agent
- No sensitive values are logged by exporter internals

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-4"

# =============================================================================
# PHASE 5: Application And Network Telemetry
# =============================================================================
echo ""
echo "--- Phase 5: Application And Network Telemetry ---"

create_issue \
  "P5-01: Implement Connection-Level Telemetry For All Traffic" \
  "## Goal
Observe encrypted and plaintext traffic without requiring payload visibility.

## Tasks
- [ ] Track TCP connection lifecycle
- [ ] Attribute flows to process and cgroup
- [ ] Export connection metrics and spans
- [ ] Avoid payload capture

## Acceptance Criteria
- Encrypted traffic produces connection-level telemetry
- Plaintext traffic produces connection-level telemetry
- No decrypted payload is captured by default

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-5"

create_issue \
  "P5-02: Implement Plaintext HTTP/1.1 Parser" \
  "## Goal
Safely parse visible HTTP metadata.

## Tasks
- [ ] Add bounded packet parser
- [ ] Extract method, status, and protocol where visible
- [ ] Add fuzz target
- [ ] Add packet bounds tests

## Acceptance Criteria
- Parser never reads beyond packet bounds
- Fuzz target runs without panic
- HTTP metrics are emitted only when metadata is visible

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-5"

create_issue \
  "P5-03: Implement SQL And Cache Protocol Metrics" \
  "## Goal
Add production-safe semantic metrics for common protocols.

## Tasks
- [ ] Add Postgres parser for bounded metadata
- [ ] Add Redis parser for bounded metadata
- [ ] Add fuzz targets
- [ ] Add opt-in config per protocol

## Acceptance Criteria
- Parsers do not capture raw sensitive query payloads by default
- Fuzz targets run without panic
- Protocol metrics are opt-in until validated

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-5"

create_issue \
  "P5-04: Implement Trace Context Extraction" \
  "## Goal
Correlate visible request metadata into traces.

## Tasks
- [ ] Parse W3C \`traceparent\` where visible
- [ ] Generate server/client spans where safe
- [ ] Add span queue and exporter integration

## Acceptance Criteria
- Visible trace context creates correlated spans
- Missing trace context creates valid root spans when configured
- Span queues are bounded

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-5"

create_issue \
  "P5-05: Implement TLS Uprobe Support" \
  "## Goal
Support encrypted request metadata for approved libraries.

## Tasks
- [ ] Add architecture decision for supported TLS libraries
- [ ] Implement OpenSSL uprobes if approved
- [ ] Evaluate BoringSSL and rustls
- [ ] Add privacy controls and opt-in config

## Acceptance Criteria
- TLS tracing is disabled by default
- Supported libraries are allowlisted
- No TLS keys, secrets, cookies, authorization headers, or bodies are exported
- Unsupported TLS libraries fall back to connection-level telemetry

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-5"

create_issue \
  "P5-06: Implement OTLP Traces Exporter" \
  "## Goal
Export traces to an OpenTelemetry Collector.

## Tasks
- [ ] Add OTLP gRPC trace exporter
- [ ] Add batching and retry policy
- [ ] Add local collector integration test

## Acceptance Criteria
- Local collector receives spans
- Export failures do not block kernel event processing
- Trace exporter obeys shutdown drain timeout

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-5"

# =============================================================================
# PHASE 6: Policy, Detection, And Controls
# =============================================================================
echo ""
echo "--- Phase 6: Policy, Detection, And Controls ---"

create_issue \
  "P6-01: Implement Security Policy Configuration" \
  "## Goal
Define user-configurable audit and alert policy.

## Tasks
- [ ] Add policy config schema
- [ ] Add file path rules
- [ ] Add process execution rules
- [ ] Add network destination rules

## Acceptance Criteria
- Invalid policy fails config validation
- Policy can be reloaded on restart
- Tests cover rule matching and precedence

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-6"

create_issue \
  "P6-02: Implement Severity And Alert Enrichment" \
  "## Goal
Produce actionable security events.

## Tasks
- [ ] Add severity model
- [ ] Add event categories
- [ ] Add policy match context
- [ ] Add stable event IDs

## Acceptance Criteria
- Security events include severity and category
- Policy match context avoids sensitive payloads
- Event IDs are stable and documented

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-6"

create_issue \
  "P6-03: Implement High-Cardinality Field Controls" \
  "## Goal
Enforce safe defaults for expensive or sensitive fields.

## Tasks
- [ ] Add per-event field allowlists
- [ ] Add global length and event-size caps
- [ ] Add redaction rules
- [ ] Add tests for command lines, paths, labels, annotations, and SQL text

## Acceptance Criteria
- High-cardinality fields are opt-in per event type
- Defaults are safe for production
- Redaction occurs before export

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-6"

# =============================================================================
# PHASE 7: Deployment And Packaging
# =============================================================================
echo ""
echo "--- Phase 7: Deployment And Packaging ---"

create_issue \
  "P7-01: Add Docker Image And Compose Manifest" \
  "## Goal
Run Prism through Docker.

## Tasks
- [ ] Add minimal production Dockerfile
- [ ] Add Compose manifest
- [ ] Mount required host paths
- [ ] Add Docker provider configuration

## Acceptance Criteria
- \`docker compose up -d\` starts agent
- \`/metrics\` is scrapeable
- Docker metadata resolves
- Compose teardown leaves no stale Prism-owned pins after restart reconciliation

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-7"

create_issue \
  "P7-02: Add Helm Chart" \
  "## Goal
Deploy Prism as a Kubernetes DaemonSet.

## Tasks
- [ ] Add DaemonSet, ServiceAccount, RBAC, ConfigMap, and Service
- [ ] Add default and production values
- [ ] Add CRI socket configuration
- [ ] Add optional Kubernetes API enrichment RBAC

## Acceptance Criteria
- \`helm template\` succeeds
- \`kind\` smoke test rolls out DaemonSet
- \`/metrics\` can be scraped or port-forwarded
- Pod metadata resolves

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-7"

create_issue \
  "P7-03: Add Systemd Packaging" \
  "## Goal
Support bare metal and Uncloud installs.

## Tasks
- [ ] Add systemd service
- [ ] Add example \`/etc/prism/config.yaml\`
- [ ] Add Debian package build
- [ ] Add RPM package build
- [ ] Preserve existing config on upgrade

## Acceptance Criteria
- Debian package installs and starts service
- RPM package installs and starts service
- Upgrades preserve \`/etc/prism/config.yaml\`
- \`systemctl stop prism-agent\` exits cleanly

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-7"

create_issue \
  "P7-04: Add Release Artifacts And Signing" \
  "## Goal
Produce release artifacts through CI.

## Tasks
- [ ] Generate static tarball
- [ ] Generate SBOM
- [ ] Generate checksums
- [ ] Sign artifacts and container images
- [ ] Upload to draft GitHub Release

## Acceptance Criteria
- Manual GitHub release workflow creates all artifacts
- Stable release requires maintainer approval before publish
- GHCR image is pushed only through release workflow

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-7"

# =============================================================================
# PHASE 8: Integration, Reliability, And Hardening
# =============================================================================
echo ""
echo "--- Phase 8: Integration, Reliability, And Hardening ---"

create_issue \
  "P8-01: Add Linux Kernel Matrix Verifier Tests" \
  "## Goal
Prevent verifier regressions across kernel versions.

## Tasks
- [ ] Add CI or scripted tests for supported kernel versions
- [ ] Test eBPF load on 5.10, 5.15, 6.1, and latest LTS where practical
- [ ] Store verifier logs on failure

## Acceptance Criteria
- Verifier tests pass on supported kernel matrix
- Failure logs are attached to CI artifacts

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-8"

create_issue \
  "P8-02: Add Crash Recovery Test" \
  "## Goal
Prove forced kill and restart does not accumulate stale Prism resources.

## Tasks
- [ ] Start agent on Linux
- [ ] Kill with \`SIGKILL\`
- [ ] Restart agent
- [ ] Repeat loop
- [ ] Check Prism-owned map/link counts

## Acceptance Criteria
- Forced kill-and-restart loop does not increase Prism-owned pinned map or link count after startup reconciliation
- Test documents required privileges

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-8"

create_issue \
  "P8-03: Add End-To-End Platform Smoke Tests" \
  "## Goal
Validate the four supported environments.

## Tasks
- [ ] Docker smoke test
- [ ] Kubernetes \`kind\` smoke test
- [ ] Bare metal/systemd smoke test
- [ ] Uncloud/systemd smoke test or documented manual test path

## Acceptance Criteria
- Each platform guide includes install, validate, logs, upgrade, and uninstall
- Each smoke test verifies \`/metrics\`
- Metadata resolution is validated per platform

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-8"

create_issue \
  "P8-04: Add Chaos And Soak Tests" \
  "## Goal
Test stability under long-running and failure conditions.

## Tasks
- [ ] Add 24-hour soak profile
- [ ] Add forced collector outage test
- [ ] Add runtime socket outage test
- [ ] Add high event-rate test

## Acceptance Criteria
- Agent memory remains bounded
- Exporter outages do not block kernel event processing
- Ring buffer drops are counted and exported
- Agent recovers when dependencies return

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓
- \`make perf\` ✓" \
  "phase-8"

# =============================================================================
# PHASE 9: Performance And Capacity
# =============================================================================
echo ""
echo "--- Phase 9: Performance And Capacity ---"

create_issue \
  "P9-01: Expand Performance Benchmark Suite" \
  "## Goal
Make \`make perf\` representative of production hot paths.

## Tasks
- [ ] Benchmark event decode
- [ ] Benchmark metadata cache lookup
- [ ] Benchmark ring buffer batch processing
- [ ] Benchmark exporter serialization
- [ ] Benchmark label sanitization

## Acceptance Criteria
- Benchmarks have stable names
- Results are stored under Criterion output
- Performance-sensitive PRs include benchmark comparison

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓
- \`make perf\` ✓" \
  "phase-9"

create_issue \
  "P9-02: Add Load Test Profiles" \
  "## Goal
Measure host overhead under realistic load.

## Tasks
- [ ] Add CPU load profile
- [ ] Add network load profile
- [ ] Add process-exec storm profile
- [ ] Add mixed workload profile

## Acceptance Criteria
- CPU overhead target is measured (target: below 3% per core)
- RSS target is measured (target: below 256 MiB)
- Ring buffer drops are measured
- Results are documented

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓
- \`make perf\` ✓" \
  "phase-9"

create_issue \
  "P9-03: Add Capacity Guidance" \
  "## Goal
Document sizing and tuning for production operators.

## Tasks
- [ ] Document queue sizing
- [ ] Document map sizing
- [ ] Document exporter batching
- [ ] Document high-cardinality controls

## Acceptance Criteria
- Operators can tune Prism for small, medium, and large nodes
- Unsafe defaults are avoided
- Docs include failure modes and symptoms

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-9"

# =============================================================================
# PHASE 10: Agent Self-Observability
# =============================================================================
echo ""
echo "--- Phase 10: Agent Self-Observability ---"

create_issue \
  "P10-01: Add Agent Health Endpoint" \
  "## Goal
Expose agent health for operators.

## Tasks
- [ ] Add \`/healthz\`
- [ ] Add \`/readyz\`
- [ ] Include exporter, metadata, and eBPF health states

## Acceptance Criteria
- Health endpoint does not require backend availability
- Readiness fails when critical pipelines are unavailable
- Kubernetes probes are wired to endpoints

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-10"

create_issue \
  "P10-02: Add Agent Self-Metrics" \
  "## Goal
Expose internal operational metrics.

## Tasks
- [ ] Export queue depth
- [ ] Export dropped events
- [ ] Export metadata cache stats
- [ ] Export exporter retry counts
- [ ] Export eBPF attach state

## Acceptance Criteria
- Self-metrics are visible in Prometheus
- Metrics have bounded labels
- Metrics are documented

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-10"

create_issue \
  "P10-03: Add Structured Logging" \
  "## Goal
Make debugging safe and predictable.

## Tasks
- [ ] Add JSON log option
- [ ] Add log levels per subsystem
- [ ] Add redaction for sensitive fields

## Acceptance Criteria
- Logs never include secrets
- Logs include agent instance ID and node name
- Debug logging is opt-in

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-10"

# =============================================================================
# PHASE 11: Security Review And Compliance
# =============================================================================
echo ""
echo "--- Phase 11: Security Review And Compliance ---"

create_issue \
  "P11-01: Add Security Review Checklist" \
  "## Goal
Make production readiness review repeatable.

## Tasks
- [ ] Add checklist for capabilities
- [ ] Add checklist for RBAC
- [ ] Add checklist for sensitive field policy
- [ ] Add checklist for release signing and SBOM

## Acceptance Criteria
- Security checklist is stored in \`docs/\`
- Release cannot be marked stable until checklist is completed

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-11"

create_issue \
  "P11-02: Add Threat Model" \
  "## Goal
Document Prism's attack surface.

## Tasks
- [ ] Model eBPF loading risks
- [ ] Model runtime socket access risks
- [ ] Model telemetry exfiltration risks
- [ ] Model Kubernetes RBAC risks
- [ ] Model supply chain risks

## Acceptance Criteria
- Threat model is stored in \`docs/\`
- Mitigations map to tickets or implementation
- Stable release requires threat model review

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-11"

create_issue \
  "P11-03: Add Supply Chain Policy" \
  "## Goal
Formalize dependency and release security.

## Tasks
- [ ] Document dependency approval
- [ ] Document license policy
- [ ] Document vulnerability response
- [ ] Document signing and provenance

## Acceptance Criteria
- \`cargo audit\` and \`cargo deny\` policies match docs
- Release artifacts include SBOM and signatures
- Vulnerability response path is documented

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-11"

# =============================================================================
# PHASE 12: Production Documentation
# =============================================================================
echo ""
echo "--- Phase 12: Production Documentation ---"

create_issue \
  "P12-01: Add Operator Guide" \
  "## Goal
Provide end-to-end production operating docs.

## Tasks
- [ ] Document Docker operation
- [ ] Document Kubernetes operation
- [ ] Document bare metal/systemd operation
- [ ] Document Uncloud operation
- [ ] Document config reference

## Acceptance Criteria
- Each platform has install, validate, logs, upgrade, rollback, and uninstall steps
- Config reference covers every setting
- Troubleshooting section covers common failures

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-12"

create_issue \
  "P12-02: Add Developer Guide" \
  "## Goal
Make development onboarding repeatable.

## Tasks
- [ ] Document Linux VM setup
- [ ] Document macOS editing limitations
- [ ] Document eBPF build flow
- [ ] Document privileged tests
- [ ] Document Makefile targets

## Acceptance Criteria
- New developer can reach \`make ci\`
- Linux runtime requirements are clear
- eBPF troubleshooting steps are documented

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-12"

create_issue \
  "P12-03: Add Architecture Guide" \
  "## Goal
Explain the system beyond the spec.

## Tasks
- [ ] Document data flow
- [ ] Document module boundaries
- [ ] Document event schemas
- [ ] Document lifecycle and shutdown
- [ ] Document pin reconciliation

## Acceptance Criteria
- Guide references diagrams in \`docs/\`
- Guide reflects current implementation
- Public concepts align with code names

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-12"

# =============================================================================
# PHASE 13: Release Automation
# =============================================================================
echo ""
echo "--- Phase 13: Release Automation ---"

create_issue \
  "P13-01: Implement Manual GitHub Release Workflow" \
  "## Goal
Release only through approved manual process.

## Tasks
- [ ] Add \`workflow_dispatch\` release workflow
- [ ] Validate semver tag
- [ ] Build all artifacts
- [ ] Generate release notes
- [ ] Create draft GitHub Release

## Acceptance Criteria
- Release is never published automatically from merge
- Draft release requires maintainer approval
- Workflow refuses duplicate version tags

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-13"

create_issue \
  "P13-02: Implement Artifact Provenance" \
  "## Goal
Make artifacts verifiable.

## Tasks
- [ ] Generate provenance attestations
- [ ] Sign artifacts with Cosign
- [ ] Sign container image
- [ ] Attach checksums

## Acceptance Criteria
- Users can verify binary, package, and image integrity
- Provenance is attached to GitHub Release
- Stable release fails if signing fails

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-13"

create_issue \
  "P13-03: Implement Rollback Procedure" \
  "## Goal
Make production rollback safe.

## Tasks
- [ ] Document rollback for Docker
- [ ] Document rollback for Helm
- [ ] Document rollback for systemd packages
- [ ] Document \`latest\` tag policy

## Acceptance Criteria
- Broken releases are deprecated, not deleted
- Patch release procedure is documented
- \`latest\` moves only after stable validation

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-13"

# =============================================================================
# PHASE 14: Production Readiness Validation
# =============================================================================
echo ""
echo "--- Phase 14: Production Readiness Validation ---"

create_issue \
  "P14-01: Run Full Platform Certification" \
  "## Goal
Certify supported environments.

## Tasks
- [ ] Certify Docker deployment
- [ ] Certify Kubernetes deployment
- [ ] Certify Uncloud/systemd deployment
- [ ] Certify bare metal deployment

## Acceptance Criteria
- All platform smoke tests pass
- Install, upgrade, rollback, and uninstall are validated
- Metadata resolution works on every platform

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-14"

create_issue \
  "P14-02: Run Full Performance Certification" \
  "## Goal
Validate production overhead targets.

## Tasks
- [ ] Run load profiles
- [ ] Run 24-hour soak
- [ ] Record CPU overhead (target: below 3% per core)
- [ ] Record RSS (target: below 256 MiB)
- [ ] Record ring buffer drops

## Acceptance Criteria
- CPU overhead target is met
- RSS target is met
- Drops are zero in the standard benchmark profile
- Results are attached to release notes

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓
- \`make perf\` ✓" \
  "phase-14"

create_issue \
  "P14-03: Run Full Security Certification" \
  "## Goal
Validate production security posture.

## Tasks
- [ ] Complete security checklist
- [ ] Review threat model
- [ ] Validate least privilege capabilities
- [ ] Validate Kubernetes RBAC
- [ ] Validate no secret logging

## Acceptance Criteria
- Security review is signed off
- No critical/high unignored vulnerabilities remain
- Release artifacts are signed

## Quality Gates
- \`make fmt\` ✓
- \`make lint\` ✓
- \`make test\` ✓
- \`make ebpf\` ✓
- \`make audit\` ✓" \
  "phase-14"

# =============================================================================
# Summary
# =============================================================================
echo ""
echo "============================================="
echo " Done!"
echo " Issues created : $CREATED"
echo " Issues failed  : $FAILED"
echo " View all issues: https://github.com/$REPO/issues"
echo "============================================="
