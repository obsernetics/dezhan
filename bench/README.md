# bench

S3 throughput/latency comparison of dezhan vs MinIO.

- `s3bench.py <label> <endpoint> <key> <secret> out.json` - run the benchmark.
- `graph.py` - render `dezhan-vs-others.svg` from the result JSONs.
- `gen_comparison.py` - render `results/COMPARISON.md` from the result JSONs.
- `make-vm.sh` - provision a test VM (cloud-init).
- `results/` - captured runs and `COMPARISON.md`.

Setup: dezhan and MinIO on one VM (4 vCPU, nested KVM), same harness.
