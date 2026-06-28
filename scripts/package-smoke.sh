#!/usr/bin/env bash
set -euo pipefail

grep -q 'conf-files = \["/etc/prism/config.yaml"\]' prism-agent/Cargo.toml
grep -q 'maintainer-scripts = "../deploy/packaging/deb"' prism-agent/Cargo.toml
grep -q 'config = "noreplace"' prism-agent/Cargo.toml
grep -q '%config(noreplace) /etc/prism/config.yaml' deploy/packaging/rpm/prism-agent.spec

for script in postinst prerm postrm; do
    test -x "deploy/packaging/deb/${script}"
    sh -n "deploy/packaging/deb/${script}"
done

systemd-analyze verify deploy/systemd/prism-agent.service >/dev/null 2>&1 || {
    if command -v systemd-analyze >/dev/null 2>&1; then
        systemd-analyze verify deploy/systemd/prism-agent.service
        exit 1
    fi
    echo "systemd-analyze is not installed; skipped systemd unit verification"
}
