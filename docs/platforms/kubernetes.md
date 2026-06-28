# Kubernetes Platform Guide

## Install

Install the Helm chart into a node-observability namespace:

```sh
kubectl create namespace prism-system --dry-run=client -o yaml | kubectl apply -f -
helm upgrade --install prism-agent deploy/helm/prism-agent --namespace prism-system
```

The chart deploys a DaemonSet with host PID access, bpffs and cgroupfs mounts, a CRI socket mount, and a Service exposing the metrics port.

## Validate

Run static chart validation:

```sh
make helm-smoke
```

For a live kind rollout smoke, set `PRISM_KIND_SMOKE=1`:

```sh
PRISM_KIND_SMOKE=1 make helm-smoke
```

The live smoke installs the chart, waits for the DaemonSet rollout, verifies the metrics Service exists, port-forwards the Service, and scrapes `/metrics`. You can run the same validation manually:

```sh
kubectl -n prism-system port-forward svc/prism-agent 9090:9090
curl http://127.0.0.1:9090/metrics
```

Pod metadata resolution is validated by CRI and Kubernetes provider logs and by metrics labelled with resolved pod metadata when workload events are present.

## Logs

```sh
kubectl -n prism-system logs daemonset/prism-agent --all-containers --tail=200
```

## Upgrade

```sh
helm upgrade prism-agent deploy/helm/prism-agent --namespace prism-system
kubectl -n prism-system rollout status daemonset/prism-agent
```

## Uninstall

```sh
helm uninstall prism-agent --namespace prism-system
kubectl delete namespace prism-system
```
