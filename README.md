<div align="center">

<h1>dezhan</h1>

<p><b>Write-once backups whose immutability is a machine-checked theorem, not a configuration flag.</b></p>

<p>
  <a href="https://github.com/obsernetics/dezhan/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/obsernetics/dezhan/ci.yml?branch=main&label=CI&logo=github" alt="CI" /></a>
  <a href="scripts/prove.sh"><img src="https://img.shields.io/badge/SPARK%20proof-325%20checks%2C%200%20unproved-brightgreen" alt="SPARK proof: 325 checks, 0 unproved" /></a>
  <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License: Apache 2.0" /></a>
  <a href="https://obsernetics.github.io/dezhan/"><img src="https://img.shields.io/badge/website-obsernetics.github.io%2Fdezhan-1f6feb" alt="Website" /></a>
</p>

<img src="docs/assets/demo.gif" alt="dezhanctl demo: check health, store an object under a compliance retention, show its metadata, watch a delete-before-expiry be refused, then open the live dashboard" width="900" />

</div>

## What it is

When you write an object under a retention, the vault refuses to delete it,
shorten its retention, or expire it early until the clock legitimately passes the
deadline. That refusal is not a policy flag an admin can turn off: it is a SPARK
state machine, proved by `gnatprove` to have no execution path that deletes a
retained object. It speaks S3, so `restic`, Velero, Veeam, `aws-cli` or `boto3`
write to it unchanged, and it runs on-prem and air-gapped with no external
runtime dependency.

## Control CLI and live dashboard

`dezhanctl` reads the vault's plain control plane (`/healthz`, `/metrics`, `/v`),
so it needs no AWS SDK and works air-gapped. It ships in each release.

![dezhanctl dashboard](docs/assets/dashboard.png)

```sh
export DEZHAN_ENDPOINT=http://127.0.0.1:8080
dezhanctl dashboard            # live TUI: health, seal state, objects, audit, scrub
dezhanctl put report --file ./q3-close.tar --mode compliance --retain 86400
dezhanctl stat report          # object metadata
dezhanctl get report -o ./out  # fetch to a file
dezhanctl ls --json            # machine-readable output
dezhanctl del report           # refused while the object is retained
dezhanctl admin scrub --admin-token "$DEZHAN_ADMIN_TOKEN"   # token-gated ops
```

## What it proves

Four things in the trusted core are written in SPARK and machine-checked by
`gnatprove`: **325 verification conditions, 0 unproved**, on every commit.

| Verified component | Invariant it guarantees |
|---|---|
| Retention state machine | retention may be extended, never shortened; a retained object cannot be deleted before expiry |
| Clock-integrity guard | a rewound or tampered clock cannot expire a lock; the vault seals instead of releasing |
| Append-only audit chain | every operation is hash-chained; history cannot be rewritten undetectably |
| Erasure coding | data survives drive loss and reconstructs exactly, or is quarantined, never returned wrong |

The cryptography (SHA-256/512, ChaCha20, HMAC, Ed25519) is in-tree with no
external runtime dependency. Design notes and limits: [`docs/NOTES.md`](docs/NOTES.md).

## Speaks S3

Standard S3 is validated against the AWS SDK: buckets, objects, copy, batch
delete, multipart, versioning, presigned URLs, SigV4, and Object Lock / WORM.

```sh
ALIAS="aws --endpoint-url http://localhost:8080 --region us-east-1"
$ALIAS s3 cp ./data.tar s3://backups/                 # any size, multipart handled
$ALIAS s3api create-bucket --bucket vault --object-lock-enabled-for-bucket
$ALIAS s3 rm  s3://vault/important.bak                 # refused until retention expires
```

Buckets are mutable by default; enabling Object Lock makes a bucket WORM. dezhan
trades write speed for durability (every write is encrypted, erasure-coded, and
fsync'd), so it is slower than a plain object store on `PUT` and closer on `GET`.
Numbers and the dezhan-vs-Veeam comparison: [`bench/results/COMPARISON.md`](bench/results/COMPARISON.md).

## Quick start

```sh
# on-prem: pulls the image, runs it, prints generated credentials
curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/obsernetics/dezhan/main/install.sh | sh

# kubernetes: operator + a DezhanVault CR
kubectl apply -f https://raw.githubusercontent.com/obsernetics/dezhan/main/deploy/dezhan.yaml
```

A vault is a single writer over durable storage (a one-replica StatefulSet on a
`ReadWriteOnce` volume); do not scale it. Three images ship from one code base:
`dezhan` (the server), `dezhan-operator`, and `dezhan-csi`.

## Configuration

`dezhan_server [port] [data-dir]`. Endpoints: `GET /healthz`, `GET /metrics`,
`POST /admin/{seal,scrub,checkpoint,gc}`, and a web UI at `/`.

| Variable | Meaning | Default |
|---|---|---|
| `DEZHAN_VAULT_KEY` | passphrase the data key is wrapped under | demo key |
| `DEZHAN_REQUIRE_AUTH` | reject unsigned requests | unset |
| `DEZHAN_ACCESS_KEY` / `DEZHAN_SECRET` | the S3 credential | `dezhanadmin` / demo |
| `DEZHAN_ADMIN_TOKEN` | token (`X-Dezhan-Admin-Token`) gating `/admin/*` | unset |
| `DEZHAN_DELETE_QUORUM` / `DEZHAN_APPROVERS` | four-eyes deletes | `0` / unset |
| `DEZHAN_SCRUB_INTERVAL` | seconds between integrity scrubs | `300` |

The operator and CSI samples are in [`operator/config/samples`](operator/config/samples)
and [`deploy/csi/`](deploy/csi/). Run `sh scripts/smoke.sh` for a `boto3` check.

## Development

Builds and proofs run inside the project's KVM guest; see [`CLAUDE.md`](CLAUDE.md).

```sh
gprbuild -P dezhan.gpr           # build server, CLI, verifier
sh scripts/test.sh               # unit tests
sh scripts/prove.sh              # SPARK proof gate (hard)
( cd ctl && go build ./... )     # dezhanctl
```

The landing page at <https://obsernetics.github.io/dezhan/> is generated from
these sources by [`scripts/gen-site.py`](scripts/gen-site.py), so it cannot drift.

## Status

Early software: a `v1alpha1` operator API and an MVP scope (tape, database
movers, and OIDC/LDAP are deferred). [`docs/NOTES.md`](docs/NOTES.md) records
what is deferred; nothing here describes behavior that is not in the tree.
Contributions welcome. Licensed under the [Apache License 2.0](LICENSE).
