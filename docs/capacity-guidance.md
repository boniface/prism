# Capacity Guidance

This document covers queue sizing, map sizing, exporter batching, and
high-cardinality controls so operators can tune Prism for small, medium,
and large nodes without hitting unsafe defaults.

## Node Size Reference

| Size   | vCPUs | RAM    | Cgroups | Events/s |
|--------|-------|--------|---------|----------|
| Small  | 1–2   | 1–4 GiB  | < 100   | < 1 000  |
| Medium | 4–8   | 8–32 GiB | 100–500 | 1 000–10 000 |
| Large  | 16+   | 64+ GiB  | 500+    | 10 000+  |

## Queue Sizing

Prism uses bounded channels between the eBPF ring buffer consumer and the
export pipeline. The defaults are conservative and safe for small nodes.

| Setting | Default | Notes |
|---------|---------|-------|
| `PRISM_TRACE_QUEUE_CAPACITY` | 1 000 | Span queue depth before back-pressure |
| `PRISM_OTLP_BATCH_SIZE` | 512 | Spans per OTLP export batch |

For medium nodes increase the trace queue to 5 000 and the batch size to
1 024. For large nodes use 20 000 and 4 096 respectively.

If `prism_trace_queue_depth` stays near the capacity ceiling the queue is
too small. If `prism_otlp_export_retry_total` climbs the collector is
falling behind; increase batch size or collector resources first before
growing the queue.

### Failure mode

A full trace queue drops new spans and increments
`prism_trace_queue_dropped_total`. This counter is the primary signal that
queue capacity needs to increase.

## Map Sizing

eBPF hash maps are sized at compile time. The defaults accommodate medium
nodes. Large nodes with many ephemeral containers may need recompilation
with higher limits.

| Map | Default entries | Environment |
|-----|----------------|-------------|
| `CGROUP_METRICS` | 4 096 | All platforms |
| `CPU_LAST_RUN_NS` | 4 096 | All platforms |

Signs the map is full: `prism_cgroup_drops_total` climbs even when the
ring buffer has headroom, and new cgroups stop appearing in `/metrics`.

For large nodes set `MAX_CGROUP_METRICS` to 16 384 or higher and rebuild
with `make ebpf`.

### Failure mode

When a map is full the eBPF program silently drops new entries. The agent
continues running but metrics for new cgroups are missing. Rebuild with a
larger map limit and redeploy.

## Ring Buffer Sizing

Each ring buffer is 256 KiB by default. Under very high event rates the
producer may outpace the consumer and drop events.

| Buffer | Default | Constant |
|--------|---------|----------|
| `SECURITY_EVENTS` | 256 KiB | `prism-ebpf/src/lib.rs` |
| `FILE_ACCESS_EVENTS` | 256 KiB | `prism-ebpf/src/lib.rs` |
| `NETWORK_SECURITY_EVENTS` | 256 KiB | `prism-ebpf/src/lib.rs` |
| `METRIC_EVENTS` | 256 KiB | `prism-ebpf/src/lib.rs` |

Monitor `prism_cgroup_drops_total` and the `METRIC_RING_DROPS` counter. If
drops appear under normal load double the ring buffer size and rebuild.

### Failure mode

Ring buffer drops are counted and exported but are not fatal. The agent
continues collecting future events. Drops in the standard benchmark profile
are a release blocker; drops under extreme load are documented and expected.

## Exporter Batching

OTLP export batches reduce network round-trips and collector load.

| Setting | Default | Tuning |
|---------|---------|--------|
| `PRISM_OTLP_BATCH_SIZE` | 512 | Increase for large nodes with high span rates |
| `PRISM_OTLP_ENDPOINT` | `http://127.0.0.1:4317` | Point at a local or remote collector |

If the collector is remote increase batch size to reduce connection
overhead. If the collector is on the same host keep the default.

Export failures are retried with backoff and do not block kernel event
processing. Monitor `prism_otlp_export_retry_total` to detect persistent
collector unavailability.

### Failure mode

If the collector is unreachable for an extended period the export queue
fills and new spans are dropped. The agent logs export errors at WARN
level. Restart the collector or point `PRISM_OTLP_ENDPOINT` at a healthy
replica.

## High-Cardinality Controls

High-cardinality labels drive up storage costs and can overload backends.
Prism applies safe defaults and requires explicit opt-in for expensive
dimensions.

| Setting | Default | Risk |
|---------|---------|------|
| `prometheus.expensive_dimensions_enabled` | `false` | Enables full path and command line labels |
| `prometheus.max_label_value_len` | 64 | Caps label value length |
| `prometheus.series_limit` | 10 000 | Drops series above this count |
| `security.max_field_len` | 256 | Caps security event field length |

Monitor `prism_metric_series_dropped_total`. If it is non-zero either
raise `series_limit` or disable expensive dimensions.

### Unsafe defaults to avoid

Do not set `expensive_dimensions_enabled: true` on large nodes without
also setting a `label_allowlist`. Full command lines and file paths can
produce millions of unique series within minutes on busy hosts.

Do not disable `series_limit`. Without it a cardinality spike can exhaust
backend storage.

### Failure mode

When `series_limit` is reached new series are dropped and
`prism_metric_series_dropped_total` increments. Existing series continue
to be exported. Raise the limit or reduce label cardinality to recover.

## Load Test Reference

Run the load test profiles to validate sizing before production deployment:

```sh
# Quick 30-second mixed profile
sudo PRISM_LOAD_DURATION_SECONDS=30 make load-test

# Specific profile
sudo PRISM_LOAD_PROFILE=exec-storm PRISM_LOAD_DURATION_SECONDS=60 make load-test
```

Results are written to `target/load-test-logs/results-<profile>.txt` and
include `peak_rss_kb`, `peak_cpu_percent`, and `ring_buffer_drops`.

Production targets:

- RSS below 256 MiB (`262144` KiB) during the standard benchmark profile.
- CPU overhead below 3% per core during the standard benchmark profile.
- Zero ring buffer drops during the standard benchmark profile.
