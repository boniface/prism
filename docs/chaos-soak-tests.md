# Chaos And Soak Tests

`make chaos-smoke` runs `scripts/chaos-soak.sh`. The runner is designed for Linux hosts with the same eBPF privileges as production and skips elsewhere unless `PRISM_CHAOS_REQUIRED=1`.

## Profiles

- `PRISM_SOAK_PROFILE=smoke`: 60 second default run for PR and pre-merge checks.
- `PRISM_SOAK_PROFILE=24h`: 86,400 second soak for release candidates and dedicated runners.

Override either profile with `PRISM_SOAK_DURATION_SECONDS`.

## Faults Covered

- Collector outage: the agent starts with `PRISM_CHAOS_OTLP_ENDPOINT`, defaulting to an unavailable local collector endpoint, and must keep serving `/metrics`.
- Runtime socket outage: run the profile on hosts where Docker or CRI sockets are intentionally absent or blocked; metadata failure must remain non-fatal and logs must show recovery or soft misses.
- High event rate: the runner creates repeated process and procfs activity while the agent is live.
- Memory bound: RSS is sampled through `/proc/<pid>/status` and must stay below `PRISM_SOAK_MAX_RSS_KB`, default `262144`.

## Required Signals

The final scrape is stored in `target/chaos-soak-logs/metrics-final.prom`. The smoke checks that `/metrics` remains scrapeable, self-metrics are exported, cardinality drop metrics are present, and `prism_cgroup_drops_total` is present whenever cgroup snapshots are present.

## Release Command

```sh
sudo PRISM_SOAK_PROFILE=24h PRISM_CHAOS_REQUIRED=1 make chaos-smoke
```

The release run passes only if memory remains bounded, exporter or metadata dependency outages do not stop kernel processing, drops are counted and exported, and the agent remains scrapeable after dependencies return.
