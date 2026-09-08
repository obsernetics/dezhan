#!/usr/bin/env python3
# Regenerate results/COMPARISON.md from the measured result JSONs. Single-node:
# dezhan and MinIO benchmarked on the same VM with the same harness (s3bench.py).
import json, datetime

ENVS = [("dezhan-vm", "dezhan"), ("minio-vm", "MinIO")]
SIZES = ["1KiB", "256KiB", "4MiB"]
data = {e: json.load(open(f"results/{e}.json")) for e, _ in ENVS}

def table(title, key, fmt="{}"):
    hdr = "| size | " + " | ".join(lbl for _, lbl in ENVS) + " |"
    sep = "|---|" + "|".join(["---"] * len(ENVS)) + "|"
    rows = [f"## {title}", hdr, sep]
    for sz in SIZES:
        cells = [fmt.format(data[e]["sizes"][sz][key]) for e, _ in ENVS]
        rows.append(f"| {sz} | " + " | ".join(cells) + " |")
    return "\n".join(rows)

ts = datetime.datetime.fromtimestamp(data["dezhan-vm"]["ts"], datetime.timezone.utc).strftime("%Y-%m-%d")
out = []
out.append("# dezhan benchmark comparison")
out.append("")
out.append(f"Measured {ts} on a single VM (4 vCPU, nested KVM), both servers on the")
out.append("same host, same harness (`bench/s3bench.py`, boto3, path-style S3v4).")
out.append("Workload: sequential PUT/GET/LIST/DELETE at 3 object sizes. Numbers are")
out.append("objects/s and MB/s (higher = better); p95 latency in ms (lower = better).")
out.append("dezhan is single-writer with per-write fsync, per-object ChaCha20 encryption,")
out.append("and Reed-Solomon erasure coding; MinIO (single-node, erasure set of one) is the")
out.append("S3 throughput reference. Re-run with `s3bench.py` then `graph.py`.")
out.append("")
out.append(table("PUT obj/s", "put_objs_per_s"))
out.append("")
out.append(table("PUT MB/s", "put_MBps"))
out.append("")
out.append(table("PUT p95 ms", "put_p95_ms"))
out.append("")
out.append(table("GET obj/s", "get_objs_per_s"))
out.append("")
out.append(table("GET MB/s", "get_MBps"))
out.append("")
out.append(table("GET p95 ms", "get_p95_ms"))
out.append("")
out.append(table("DELETE obj/s", "delete_objs_per_s"))
out.append("")
open("results/COMPARISON.md", "w").write("\n".join(out))
print("wrote results/COMPARISON.md")
