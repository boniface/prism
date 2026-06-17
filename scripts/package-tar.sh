#!/usr/bin/env bash
set -euo pipefail

version="${1:?version is required}"
target="${2:?target triple is required}"

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dist_dir="${root_dir}/target/dist"
stage_dir="${dist_dir}/prism-agent-${version}-${target}"
agent_bin="${root_dir}/target/${target}/release/prism-agent"
ebpf_obj="${root_dir}/target/bpfel-unknown-none/release/prism-ebpf"

rm -rf "${stage_dir}"
mkdir -p "${stage_dir}/bin" "${stage_dir}/ebpf" "${stage_dir}/config" "${stage_dir}/docs"

install -m 0755 "${agent_bin}" "${stage_dir}/bin/prism-agent"
install -m 0644 "${ebpf_obj}" "${stage_dir}/ebpf/prism-ebpf"
install -m 0644 "${root_dir}/config/example.yaml" "${stage_dir}/config/example.yaml"
install -m 0644 "${root_dir}/README.md" "${stage_dir}/README.md"
install -m 0644 "${root_dir}/LICENSE" "${stage_dir}/LICENSE"
install -m 0644 "${root_dir}/docs/spec.md" "${stage_dir}/docs/spec.md"
install -m 0644 "${root_dir}/docs/implementation-plan.md" "${stage_dir}/docs/implementation-plan.md"

tarball="${dist_dir}/prism-agent-${version}-${target}.tar.gz"
tar -C "${dist_dir}" -czf "${tarball}" "prism-agent-${version}-${target}"

if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${tarball}" > "${tarball}.sha256"
else
    sha256sum "${tarball}" > "${tarball}.sha256"
fi

echo "created ${tarball}"
