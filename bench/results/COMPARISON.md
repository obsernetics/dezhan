# dezhan benchmark comparison

Measured on a 3-node k3s cluster (2 vCPU / 4 GB nodes, nested KVM) and a separate
on-prem VM. Workload: sequential PUT/GET/LIST/DELETE via boto3, 3 object sizes.
Numbers are objects/s and MB/s (higher = better); p95 latency in ms (lower = better).
dezhan is single-writer with per-write fsync + erasure coding + per-object encryption;
MinIO is included as an S3 throughput reference. Longhorn = dezhan on a Longhorn PV.

## PUT obj/s
| size | dezhan-k8s | minio-k8s | dezhan-longhorn | dezhan-onprem |
|---|---|---|---|---|
| 1KiB | 1.0 | 126.0 | 1.0 | 0.9 |
| 256KiB | 0.9 | 51.3 | 0.9 | 0.8 |
| 4MiB | 0.5 | 16.3 | 0.5 | 0.5 |

## PUT MB/s
| size | dezhan-k8s | minio-k8s | dezhan-longhorn | dezhan-onprem |
|---|---|---|---|---|
| 1KiB | 0.0 | 0.13 | 0.0 | 0.0 |
| 256KiB | 0.24 | 13.45 | 0.24 | 0.2 |
| 4MiB | 2.22 | 68.25 | 2.09 | 1.96 |

## PUT p95 ms
| size | dezhan-k8s | minio-k8s | dezhan-longhorn | dezhan-onprem |
|---|---|---|---|---|
| 1KiB | 1012.878 | 11.612 | 1133.229 | 1807.969 |
| 256KiB | 1093.689 | 26.431 | 1106.21 | 1638.447 |
| 4MiB | 1910.638 | 75.962 | 2101.264 | 2432.201 |

## GET obj/s
| size | dezhan-k8s | minio-k8s | dezhan-longhorn | dezhan-onprem |
|---|---|---|---|---|
| 1KiB | 356.8 | 473.2 | 345.2 | 420.5 |
| 256KiB | 115.6 | 367.7 | 160.0 | 164.7 |
| 4MiB | 17.1 | 76.1 | 15.9 | 17.4 |

## GET MB/s
| size | dezhan-k8s | minio-k8s | dezhan-longhorn | dezhan-onprem |
|---|---|---|---|---|
| 1KiB | 0.37 | 0.48 | 0.35 | 0.43 |
| 256KiB | 30.32 | 96.39 | 41.94 | 43.17 |
| 4MiB | 71.9 | 319.35 | 66.51 | 72.8 |

## GET p95 ms
| size | dezhan-k8s | minio-k8s | dezhan-longhorn | dezhan-onprem |
|---|---|---|---|---|
| 1KiB | 4.436 | 3.297 | 4.394 | 3.631 |
| 256KiB | 12.15 | 3.832 | 9.083 | 9.293 |
| 4MiB | 64.741 | 19.356 | 77.297 | 73.236 |

## DELETE obj/s
| size | dezhan-k8s | minio-k8s | dezhan-longhorn | dezhan-onprem |
|---|---|---|---|---|
| 1KiB | 145.5 | 515.6 | 148.2 | 6.9 |
| 256KiB | 167.6 | 623.3 | 161.8 | 7.6 |
| 4MiB | 141.3 | 697.4 | 153.3 | 9.9 |
