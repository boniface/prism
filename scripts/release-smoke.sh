#!/usr/bin/env bash
set -euo pipefail

workflow=".github/workflows/release.yml"

grep -q "workflow_dispatch:" "${workflow}"
grep -q "environment:" "${workflow}"
grep -q "stable-release" "${workflow}"
grep -q "make dist" "${workflow}"
grep -q "syft dir:." "${workflow}"
grep -q "sha256sum \\*" "${workflow}"
grep -q "./scripts/sign-release-artifacts.sh" "${workflow}"
grep -q "cosign sign --yes" "${workflow}"
grep -q "softprops/action-gh-release" "${workflow}"
grep -q "docker push" "${workflow}"

sh -n scripts/package-tar.sh
sh -n scripts/package-versions.sh
sh -n scripts/sign-release-artifacts.sh
