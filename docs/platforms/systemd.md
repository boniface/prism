# Bare Metal systemd Platform Guide

## Install

Install a generated package or tarball, then enable the service:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now prism-agent.service
```

The service uses `/etc/prism/config.yaml`, writes Prism-owned BPF state below the configured pin path, and exposes Prometheus on the configured listen address.

## Validate

Run static package and unit validation:

```sh
make package-smoke
make platform-smoke
```

Run the live systemd smoke on a Linux host with the package already installed:

```sh
sudo PRISM_SYSTEMD_SMOKE_INSTALL=1 ./scripts/systemd-smoke.sh
```

The live smoke starts the service, verifies `http://127.0.0.1:9090/metrics`, checks service logs for systemd metadata or agent activity, restarts the service, checks `/metrics` again, and stops the service.

## Logs

```sh
journalctl -u prism-agent.service -n 200 --no-pager
```

## Upgrade

Install the new package, reload systemd, and restart:

```sh
sudo systemctl daemon-reload
sudo systemctl restart prism-agent.service
curl http://127.0.0.1:9090/metrics
```

## Uninstall

```sh
sudo systemctl disable --now prism-agent.service
```

Then remove the package and confirm no stale Prism-owned pins remain under the configured BPF pin root.
