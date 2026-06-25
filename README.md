# dezhan

[![ci](https://github.com/obsernetics/dezhan/actions/workflows/ci.yml/badge.svg)](https://github.com/obsernetics/dezhan/actions/workflows/ci.yml)
[![operator](https://github.com/obsernetics/dezhan/actions/workflows/operator.yml/badge.svg)](https://github.com/obsernetics/dezhan/actions/workflows/operator.yml)
[![csi](https://github.com/obsernetics/dezhan/actions/workflows/csi.yml/badge.svg)](https://github.com/obsernetics/dezhan/actions/workflows/csi.yml)
[![SPARK proof: 325 checks, 0 unproved](https://img.shields.io/badge/SPARK%20proof-325%20checks%2C%200%20unproved-brightgreen)](docs/SPEC.md)
[![trusted-core coverage 95%](https://img.shields.io/badge/trusted--core%20coverage-95%25-brightgreen)](scripts/coverage.sh)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](#)

On-prem, air-gapped, immutable backup vault that speaks S3. Point any S3 client
(aws-cli, restic, Veeam, Velero, boto3) at it; data is content-addressed,
encrypted, erasure-coded, and WORM-locked so it cannot be changed or deleted
before its retention expires. The integrity core is formally verified in SPARK.
An on-prem alternative to MinIO and Veeam.

Three images are published to GHCR: `dezhan` (the vault server), `dezhan-operator`
(runs vaults from a custom resource), and `dezhan-csi` (exposes a vault as
PersistentVolumes). For a plain install you only need the server.

## Install

On-prem (pulls the image, runs it, prints generated credentials):

```sh
curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/obsernetics/dezhan/main/install.sh | sh
```

Kubernetes operator (then create a `DezhanVault`, below):

```sh
kubectl apply -f https://raw.githubusercontent.com/obsernetics/dezhan/main/deploy/dezhan.yaml
```

Or with Helm from the chart repo (set `vault.create=true` to provision a vault
too):

```sh
helm repo add dezhan https://obsernetics.github.io/dezhan
helm repo update
helm install dezhan dezhan/dezhan
```

## Use it

```sh
ALIAS="aws --endpoint-url http://localhost:8080 --region us-east-1"
$ALIAS s3 mb s3://backups
$ALIAS s3 cp ./data.tar s3://backups/      # any size; multipart handled
$ALIAS s3 ls s3://backups/

# make a bucket immutable (WORM / Object Lock)
$ALIAS s3api create-bucket --bucket vault --object-lock-enabled-for-bucket
$ALIAS s3 cp important.bak s3://vault/
$ALIAS s3 rm  s3://vault/important.bak     # denied until retention expires
```

Standard S3 validated against the AWS SDK: buckets, objects, range reads, copy,
batch delete, multipart, versioning with delete markers, user metadata,
conditional requests, presigned URLs, SigV4, and Object Lock / WORM with legal
hold. Retention is enforced by a formally verified state machine, and a tampered
system clock cannot expire a lock.

## Configuration

| Variable | Meaning | Default |
|---|---|---|
| `DEZHAN_VAULT_KEY` | passphrase the data key is wrapped under | demo key |
| `DEZHAN_REQUIRE_AUTH` | reject unsigned requests | unset (anonymous) |
| `DEZHAN_ACCESS_KEY` / `DEZHAN_SECRET` | the S3 credential | `dezhanadmin` / demo |
| `DEZHAN_CREDENTIALS` | extra `accesskey secret [default] [bucket:perm ...]` lines | `<root>/credentials` |
| `DEZHAN_TOKENS` | API token / service-account lines `token accesskey` | `<root>/tokens` |
| `DEZHAN_ADMIN_TOKEN` | token (`X-Dezhan-Admin-Token`) gating `/admin/*` | unset |
| `DEZHAN_DELETE_QUORUM` / `DEZHAN_APPROVERS` | four-eyes deletes | `0` / unset |
| `DEZHAN_APPROVAL_TTL` | seconds a staged delete approval stays valid | `3600` |
| `DEZHAN_SCRUB_INTERVAL` | seconds between integrity scrubs | `300` |

`dezhan_server [port] [data-dir]`. Operations: `GET /healthz`, `GET /metrics`
(Prometheus), `POST /admin/{seal,scrub,checkpoint}`, web UI at `/`. Run
`sh scripts/smoke.sh` for a boto3 conformance check.

Each credential has a default access level (`rw`, `ro`, or `none`) plus optional
per-bucket overrides, e.g. `auditor s3cret none logs:ro` (no access except
read-only on `logs`) or `app s3cret ro data:rw` (read everywhere, write to
`data`). A write needs `rw` on that bucket; a read needs `ro` or `rw`.

Service accounts use API tokens: a `DEZHAN_TOKENS` line `tok-abc app` lets a
client authenticate with `Authorization: Bearer tok-abc`, inheriting the `app`
principal's policy (no SigV4 signing required).

With `DEZHAN_DELETE_QUORUM` set, a delete needs approver co-signatures, either
synchronously (secrets in the `X-Dezhan-Approvals` header) or staged: approvers
pre-authorize a specific object from separate sessions with
`POST /approve?resource=/bucket/key` (header `X-Dezhan-Approval: <secret>`), and
the delete succeeds once enough approvals accrue. Staged approvals expire after
`DEZHAN_APPROVAL_TTL` and are consumed on use.

## Kubernetes operator

Declare a `DezhanVault`; the operator reconciles it into a single-replica
StatefulSet, a Service, a PVC, and a PodDisruptionBudget, and reports readiness
on the resource status.

```yaml
apiVersion: dezhan.obsernetics.io/v1alpha1
kind: DezhanVault
metadata:
  name: my-vault
spec:
  storage: 100Gi
  requireAuth: true
  deleteQuorum: 2                # deletes need 2 approver co-signatures
  secretName: my-vault-secrets   # DEZHAN_VAULT_KEY, DEZHAN_SECRET, ...
```

```sh
kubectl apply -f my-vault.yaml
kubectl get dezhanvaults          # READY, ENDPOINT, AGE
```

Reach the vault in-cluster at `http://my-vault.<namespace>.svc:8080`. A
ready-to-edit sample is in [operator/config/samples](operator/config/samples).

### Spec

| Field | Default | Meaning |
|---|---|---|
| `image` | `ghcr.io/obsernetics/dezhan:latest` | server image |
| `port` | `8080` | listen port |
| `storage` | `50Gi` | persistent volume size (raise it to expand online) |
| `storageClassName` | cluster default | PVC storage class |
| `requireAuth` | `true` | reject unsigned requests |
| `deleteQuorum` | `0` | approver co-signatures required to delete |
| `scrubIntervalSeconds` | `0` (server default 300) | recurring verify-and-self-heal interval |
| `secretName` | none | Secret whose keys become server env vars |
| `serviceType` | `ClusterIP` | `ClusterIP` (headless) / `NodePort` / `LoadBalancer` |
| `priorityClassName` | none | schedule priority so the vault is not evicted first |
| `disablePodDisruptionBudget` | `false` | turn off the PDB |
| `resources` | none | container requests/limits |

Put every secret (`DEZHAN_VAULT_KEY`, `DEZHAN_SECRET`, `DEZHAN_ADMIN_TOKEN`,
`DEZHAN_APPROVERS`) in the referenced Secret. Nothing sensitive belongs in the CR.

### Resilience

- A vault is a single writer over durable storage: one-replica StatefulSet with
  a `ReadWriteOnce` volume. Do not scale it; the immutability and audit-chain
  guarantees assume one writer. Cross-node durability and failover come from the
  underlying StorageClass (run on Ceph/cloud-disk/Longhorn so the PV reattaches).
- Pod runs non-root, read-only root filesystem, all capabilities dropped,
  `seccomp=RuntimeDefault`; only `/data` is writable.
- A PodDisruptionBudget (`minAvailable=1`) stops drains/upgrades from evicting
  the writer without a deliberate eviction. The StatefulSet retains its PVC on
  delete and scale, so data outlives the workload object. A startup probe
  tolerates slow journal replay; termination grace lets it flush.
- Online expansion: raise `spec.storage` and the operator grows the PVC in place
  (the StorageClass must allow expansion). Shrinking is never attempted.
- Reconciles are level-based and idempotent (no hot update loop); owned objects
  are watched, so a deleted Service/StatefulSet/PDB is recreated. The operator
  runs two replicas behind leader election with its own PDB.

## Use as a Kubernetes volume (CSI)

The `dezhan` CSI driver turns a vault into a StorageClass: each PVC becomes a
bucket, mounted on the node via [mountpoint-s3](https://github.com/awslabs/mountpoint-s3).
Best for write-once/append/archival workloads (it matches WORM); not for
random-write volumes such as databases. For block/RWX-database storage, run
dezhan *on* Ceph/Longhorn instead.

```sh
# edit deploy/csi/storageclass.yaml (endpoint) and secret-example.yaml (creds) first
kubectl apply -f deploy/csi/
```

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: archive
spec:
  accessModes: ["ReadWriteMany"]
  storageClassName: dezhan
  resources:
    requests:
      storage: 100Gi        # advisory; object storage is not pre-allocated
```

The controller's `CreateVolume`/`DeleteVolume` provision and remove a bucket via
the dezhan S3 API; the node plugin's `NodePublishVolume` mounts it with
`mount-s3`. Credentials come from the StorageClass-referenced Secret, never the
image.

Volume snapshots are supported (`deploy/csi/volumesnapshotclass.yaml`): a
`VolumeSnapshot` server-side-copies the bucket into an immutable snapshot
bucket, and a PVC with that snapshot as its `dataSource` restores it.

## Observability

`/metrics` is Prometheus format; the operator annotates each vault Service for
scraping. Apply the ServiceMonitor, Grafana dashboard, alerts, and an OTel
Collector bridge with `kubectl apply -f operator/config/observability/`.

## How it works

The retention state machine, clock-integrity guard, append-only audit chain, and
erasure coding are written in SPARK and machine-checked by `gnatprove` (325
checks, 0 unproved); the cryptography (SHA-256/512, ChaCha20, HMAC, Ed25519) is
in-tree with no external dependency. See [docs/SPEC.md](docs/SPEC.md) and
[docs/NOTES.md](docs/NOTES.md).

## Development

```sh
gprbuild -P dezhan.gpr           # build server, CLI, verifier
sh scripts/test.sh               # unit tests
sh scripts/prove.sh              # SPARK proof gate
sh scripts/coverage.sh           # trusted-core line coverage
( cd operator && go build ./... && go test ./... )
( cd csi && go build ./... && go test ./... )
```

Licensed under Apache-2.0.
