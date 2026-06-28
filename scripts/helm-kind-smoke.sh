#!/usr/bin/env bash
set -euo pipefail

release="prism-agent"
namespace="prism-system"
chart="deploy/helm/prism-agent"
production_values="${chart}/values-production.yaml"

if ! command -v helm >/dev/null 2>&1; then
    echo "helm is not installed; skipping Helm smoke test"
    exit 0
fi

helm template "${release}" "${chart}" --namespace "${namespace}" >/dev/null
helm template "${release}" "${chart}" --namespace "${namespace}" -f "${production_values}" >/dev/null
helm lint "${chart}"

if [ "${PRISM_KIND_SMOKE:-0}" != "1" ]; then
    echo "PRISM_KIND_SMOKE is not 1; skipping kind rollout smoke test"
    exit 0
fi

for tool in kind kubectl; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        echo "${tool} is not installed; skipping kind rollout smoke test"
        exit 0
    fi
done

cluster="${PRISM_KIND_CLUSTER:-prism-smoke}"

if ! kind get clusters | grep -qx "${cluster}"; then
    kind create cluster --name "${cluster}"
fi

kubectl create namespace "${namespace}" --dry-run=client -o yaml | kubectl apply -f -
helm upgrade --install "${release}" "${chart}" \
    --namespace "${namespace}" \
    --set image.pullPolicy=IfNotPresent

kubectl -n "${namespace}" rollout status daemonset/"${release}" --timeout=120s
kubectl -n "${namespace}" get endpoints "${release}" -o yaml
