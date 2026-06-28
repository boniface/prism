# Uncloud Platform Guide

## Install

Use the same package and `prism-agent.service` unit as bare metal systemd. Configure metadata providers in `/etc/prism/config.yaml` for systemd and, when available, Uncloud API enrichment.

```yaml
metadata:
  providers:
    - systemd
```

## Validate

Run the documented smoke path:

```sh
make platform-smoke
```

On an Uncloud Linux host with the package installed, run:

```sh
sudo PRISM_UNCLOUD_SMOKE_LIVE=1 ./scripts/uncloud-smoke.sh
```

The live path delegates to the systemd smoke test, verifies `http://127.0.0.1:9090/metrics`, and validates metadata through systemd slice or Uncloud enrichment logs.

## Logs

```sh
journalctl -u prism-agent.service -n 200 --no-pager
```

## Upgrade

Install the new package, reload systemd, restart the service, and scrape `/metrics`:

```sh
sudo systemctl daemon-reload
sudo systemctl restart prism-agent.service
curl http://127.0.0.1:9090/metrics
```

## Uninstall

```sh
sudo systemctl disable --now prism-agent.service
```

Remove the package and verify the configured Prism BPF pin path is empty of Prism-owned entries.
