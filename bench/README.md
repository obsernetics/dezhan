# bench

dezhan's measured S3 throughput, plus a dezhan-vs-Veeam immutability comparison.

- `s3bench.py <label> <endpoint> <key> <secret> out.json` - run the benchmark.
- `graph.py` - render `dezhan-vs-others.svg` from the result JSON.
- `gen_comparison.py` - render `results/COMPARISON.md` (throughput + Veeam table).
- `make-vm.sh` - provision a test VM (cloud-init).
- `results/` - captured runs and `COMPARISON.md`.

Setup: dezhan on one VM (4 vCPU, nested KVM). Veeam is compared on immutability
guarantees, not obj/s: it is not an S3 server, so it is not driven by the harness.
