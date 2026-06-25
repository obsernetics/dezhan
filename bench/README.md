# dezhan benchmarks

Reproducible S3 throughput/latency comparison harness and captured results.

- `s3bench.py` - endpoint-agnostic boto3 benchmark (PUT/GET/LIST/DELETE at
  1KiB/256KiB/4MiB), emits one JSON result.
- `make-vm.sh` - provision an Ubuntu KVM guest (cloud-init) for a test env.
- `results/` - captured runs: dezhan in k8s, dezhan on a Longhorn PV, MinIO in
  k8s (reference), and dezhan on-prem (docker), plus `/metrics` snapshots.
- `results/COMPARISON.md` - generated comparison tables.

Environment: 3-node k3s (2 vCPU / 4 GB nodes, nested KVM) + a separate on-prem
VM. Veeam was out of scope (proprietary, Windows-only). Run:
`python3 s3bench.py <label> <endpoint> <access> <secret> out.json`.
