#!/usr/bin/env python3
# Regenerate results/COMPARISON.md: dezhan's own measured throughput (from the
# result JSON) plus a dezhan-vs-Veeam immutability/backup capability comparison.
# Veeam cannot be driven through an S3 throughput harness (it is not an S3
# server), so it is compared on guarantees, not obj/s. The Veeam column is
# sourced from Veeam's public documentation (cited at the foot of the file); no
# Veeam performance numbers are invented.
import json, datetime

SIZES = ["1KiB", "256KiB", "4MiB"]
d = json.load(open("results/dezhan-vm.json"))

def table(title, key):
    rows = [f"## {title}", "| size | dezhan |", "|---|---|"]
    for sz in SIZES:
        rows.append(f"| {sz} | {d['sizes'][sz][key]} |")
    return "\n".join(rows)

ts = datetime.datetime.fromtimestamp(d["ts"], datetime.timezone.utc).strftime("%Y-%m-%d")

CAP = """## dezhan vs Veeam: immutable backup guarantees

Both keep backups that cannot be deleted before their retention expires. The
difference is *how that is guaranteed*. Veeam is a full backup platform; dezhan
is a focused immutable backup vault with an S3 API that backup tools write to.

| | dezhan | Veeam |
|---|---|---|
| How immutability is guaranteed | Machine-proved: the delete-before-expiry path is verified unreachable in the trusted core by `gnatprove` on every commit | Enforced by the storage layer: the Linux immutable flag on an XFS hardened repository, or S3 Object Lock on an object store |
| Where it is enforced | Inside the vault's own trusted core | Delegated to the filesystem (`chattr +i` via `veeamimmureposvc`) or to the object store's Object Lock |
| Can a privileged operator shorten or lift retention? | No: retention may be extended, never shortened (a proved invariant) | Governance-mode Object Lock: yes, with permissions. Compliance mode / hardened repo: no, until expiry |
| Clock tampering | The vault seals instead of releasing objects early | Depends on accurate system time |
| Retention metadata | Part of the sealed, hash-chained audit log | Backup metadata (e.g. the `.vbm`) is kept mutable so it can be updated |
| Runtime footprint | Single Ada/SPARK binary, air-gapped, no external dependency | Windows management server plus repository/object-store infrastructure |
| Integrity evidence | 325 SPARK proof checks, 0 unproved, re-checked in CI | Feature-tested |
| API | S3-compatible target for any backup client | Proprietary agents writing to file or object repositories |
| Scope | Immutable backup vault / S3 target | Comprehensive backup, replication and orchestration platform |
| License | Open source, Apache-2.0 | Commercial, proprietary |

dezhan does not replace Veeam's breadth; it is an immutable target whose core
retention guarantee is a proved theorem rather than a storage-layer policy.

Sources (Veeam public docs / community):
- Hardened repository (XFS immutable flag): https://helpcenter.veeam.com/docs/backup/vsphere/hardened_repository.html
- Object storage immutability and S3 Object Lock modes: https://helpcenter.veeam.com/docs/vbaws/guide/immutability.html
"""

out = []
out.append("# dezhan benchmark and comparison")
out.append("")
out.append(f"Throughput measured {ts} on a single VM (4 vCPU, nested KVM) with")
out.append("`bench/s3bench.py` (boto3, path-style S3v4). Workload: sequential")
out.append("PUT/GET/LIST/DELETE at 3 object sizes; numbers are objects/s and MB/s")
out.append("(higher = better), p95 latency in ms (lower = better). dezhan is")
out.append("single-writer with per-write fsync, per-object ChaCha20 encryption, and")
out.append("Reed-Solomon erasure coding. Re-run with `s3bench.py` then `graph.py`.")
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
out.append(CAP)
open("results/COMPARISON.md", "w").write("\n".join(out))
print("wrote results/COMPARISON.md")
