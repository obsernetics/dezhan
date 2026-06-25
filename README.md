# dezhan

[![ci](https://github.com/obsernetics/dezhan/actions/workflows/ci.yml/badge.svg)](https://github.com/obsernetics/dezhan/actions/workflows/ci.yml)
[![operator](https://github.com/obsernetics/dezhan/actions/workflows/operator.yml/badge.svg)](https://github.com/obsernetics/dezhan/actions/workflows/operator.yml)
[![SPARK proof: 325 checks, 0 unproved](https://img.shields.io/badge/SPARK%20proof-325%20checks%2C%200%20unproved-brightgreen)](docs/SPEC.md)
[![trusted-core coverage 95%](https://img.shields.io/badge/trusted--core%20coverage-95%25-brightgreen)](scripts/coverage.sh)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](#)

On-prem, air-gapped, immutable backup vault that speaks S3. Point any S3 client
(aws-cli, restic, Veeam, Velero, boto3) at it; data is content-addressed,
encrypted, erasure-coded, and WORM-locked so it cannot be changed or deleted
before its retention expires. The integrity core is formally verified in SPARK.
An on-prem alternative to MinIO and Veeam.

## Install

On-prem (pulls the image, runs it, prints generated credentials):

```sh
curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/obsernetics/dezhan/main/install.sh | sh
```

Kubernetes, the operator (then create a `DezhanVault`):

```sh
kubectl apply -f https://raw.githubusercontent.com/obsernetics/dezhan/main/deploy/dezhan.yaml
```

Or with Helm:

```sh
helm install dezhan ./deploy/charts/dezhan
```

For a one-command cluster install that also provisions a vault and generates
credentials, run `./install-k8s.sh`. The full `DezhanVault` spec is in
[operator/README.md](operator/README.md).

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
| `DEZHAN_CREDENTIALS` | extra `accesskey secret [ro\|rw]` lines | `<root>/credentials` |
| `DEZHAN_ADMIN_TOKEN` | token (`X-Dezhan-Admin-Token`) gating `/admin/*` | unset |
| `DEZHAN_DELETE_QUORUM` / `DEZHAN_APPROVERS` | four-eyes deletes | `0` / unset |

`dezhan_server [port] [data-dir]`. Operations: `GET /healthz`, `GET /metrics`
(Prometheus), `POST /admin/{seal,scrub,checkpoint}`, web UI at `/`. Run
`sh scripts/smoke.sh` for a boto3 conformance check.

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

Licensed under Apache-2.0.
