# dezhan benchmark and comparison

Throughput measured 2026-09-07 on a single VM (4 vCPU, nested KVM) with
`bench/s3bench.py` (boto3, path-style S3v4). Workload: sequential
PUT/GET/LIST/DELETE at 3 object sizes; numbers are objects/s and MB/s
(higher = better), p95 latency in ms (lower = better). dezhan is
single-writer with per-write fsync, per-object ChaCha20 encryption, and
Reed-Solomon erasure coding. Re-run with `s3bench.py` then `graph.py`.

## PUT obj/s
| size | dezhan |
|---|---|
| 1KiB | 1.0 |
| 256KiB | 0.8 |
| 4MiB | 0.3 |

## PUT MB/s
| size | dezhan |
|---|---|
| 1KiB | 0.0 |
| 256KiB | 0.21 |
| 4MiB | 1.18 |

## PUT p95 ms
| size | dezhan |
|---|---|
| 1KiB | 1021.605 |
| 256KiB | 1268.625 |
| 4MiB | 3607.507 |

## GET obj/s
| size | dezhan |
|---|---|
| 1KiB | 447.6 |
| 256KiB | 121.8 |
| 4MiB | 8.7 |

## GET MB/s
| size | dezhan |
|---|---|
| 1KiB | 0.46 |
| 256KiB | 31.93 |
| 4MiB | 36.59 |

## GET p95 ms
| size | dezhan |
|---|---|
| 1KiB | 2.935 |
| 256KiB | 8.869 |
| 4MiB | 115.561 |

## DELETE obj/s
| size | dezhan |
|---|---|
| 1KiB | 237.9 |
| 256KiB | 276.7 |
| 4MiB | 255.2 |

## dezhan vs Veeam: immutable backup guarantees

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
