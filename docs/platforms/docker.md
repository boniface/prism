# Docker Platform Guide

## Install

Use `deploy/docker-compose.yaml` from the repository root:

```sh
docker compose -f deploy/docker-compose.yaml up -d --build prism-agent
```

The compose file runs with host PID and network namespaces, mounts bpffs and cgroupfs, and mounts the Docker socket read-only for Docker metadata resolution.

## Validate

Run the automated smoke test:

```sh
make docker-smoke
```

The smoke test starts the Compose service, scrapes `http://127.0.0.1:9090/metrics`, checks for Prism metrics, inspects logs for Docker metadata activity, and tears the service down.

## Logs

```sh
docker compose -f deploy/docker-compose.yaml logs --no-color prism-agent
```

## Upgrade

Build or pull the new image, then recreate the service:

```sh
docker compose -f deploy/docker-compose.yaml up -d --build prism-agent
```

## Uninstall

```sh
docker compose -f deploy/docker-compose.yaml down --remove-orphans
```

After uninstall, verify no stale Prism-owned pins remain under `/sys/fs/bpf/prism`.
