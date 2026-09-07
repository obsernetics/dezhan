# dezhan benchmark comparison

Measured 2026-09-07 on a single VM (4 vCPU, nested KVM), both servers on the
same host, same harness (`bench/s3bench.py`, boto3, path-style S3v4).
Workload: sequential PUT/GET/LIST/DELETE at 3 object sizes. Numbers are
objects/s and MB/s (higher = better); p95 latency in ms (lower = better).
dezhan is single-writer with per-write fsync, per-object ChaCha20 encryption,
and Reed-Solomon erasure coding; MinIO (single-node, erasure set of one) is the
S3 throughput reference. Re-run with `s3bench.py` then `graph.py`.

## PUT obj/s
| size | dezhan | MinIO |
|---|---|---|
| 1KiB | 1.0 | 227.0 |
| 256KiB | 0.8 | 111.8 |
| 4MiB | 0.3 | 31.7 |

## PUT MB/s
| size | dezhan | MinIO |
|---|---|---|
| 1KiB | 0.0 | 0.23 |
| 256KiB | 0.21 | 29.32 |
| 4MiB | 1.18 | 132.92 |

## PUT p95 ms
| size | dezhan | MinIO |
|---|---|---|
| 1KiB | 1021.605 | 8.076 |
| 256KiB | 1268.625 | 12.042 |
| 4MiB | 3607.507 | 34.094 |

## GET obj/s
| size | dezhan | MinIO |
|---|---|---|
| 1KiB | 447.6 | 669.2 |
| 256KiB | 121.8 | 651.9 |
| 4MiB | 8.7 | 186.6 |

## GET MB/s
| size | dezhan | MinIO |
|---|---|---|
| 1KiB | 0.46 | 0.69 |
| 256KiB | 31.93 | 170.9 |
| 4MiB | 36.59 | 782.63 |

## GET p95 ms
| size | dezhan | MinIO |
|---|---|---|
| 1KiB | 2.935 | 1.646 |
| 256KiB | 8.869 | 1.775 |
| 4MiB | 115.561 | 6.415 |

## DELETE obj/s
| size | dezhan | MinIO |
|---|---|---|
| 1KiB | 237.9 | 682.3 |
| 256KiB | 276.7 | 767.7 |
| 4MiB | 255.2 | 772.3 |
