# bench

S3 throughput/latency comparison of dezhan vs MinIO and Longhorn.

- `s3bench.py <label> <endpoint> <key> <secret> out.json` - run the benchmark.
- `graph.py` - render `dezhan-vs-others.svg` from the result JSONs.
- `make-vm.sh` - provision a test VM (cloud-init).
- `results/` - captured runs (+ `/metrics`) and `COMPARISON.md`.

Setup: 3-node k3s + on-prem VM (nested KVM). Veeam excluded (proprietary).
