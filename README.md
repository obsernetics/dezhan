<div align="center">

<h1>dezhan</h1>

<p><b>Write-once backups whose immutability is a machine-checked theorem, not a configuration flag.</b></p>

<p>
  <a href="https://github.com/obsernetics/dezhan/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/obsernetics/dezhan/ci.yml?branch=main&label=CI&logo=github" alt="CI" /></a>
  <a href="scripts/prove.sh"><img src="https://img.shields.io/badge/SPARK%20proof-325%20checks%2C%200%20unproved-brightgreen" alt="SPARK proof: 325 checks, 0 unproved" /></a>
  <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License: Apache 2.0" /></a>
  <a href="https://obsernetics.github.io/dezhan/"><img src="https://img.shields.io/badge/website-obsernetics.github.io%2Fdezhan-1f6feb" alt="Website" /></a>
</p>

<img src="docs/assets/demo.gif" alt="dezhanctl demo: store an object under a retention, watch a delete-before-expiry be refused, then open the live dashboard" width="900" />

</div>

## What it is

When you write an object under a retention, the vault refuses to delete it,
shorten it, or expire it early until the clock legitimately passes the deadline.
That refusal is not a flag an admin can turn off: it is a SPARK state machine,
proved by `gnatprove` to have no execution path that deletes a retained object.
It speaks S3 (point `restic`, Velero, Veeam, `aws-cli` or `boto3` at it) and runs
on-prem and air-gapped with no external runtime dependency.

## dezhanctl

The control CLI and live dashboard shown above. It ships in every release and
talks to the vault's plain HTTP control plane, so it needs no AWS SDK.

```sh
export DEZHAN_ENDPOINT=http://127.0.0.1:8080
dezhanctl dashboard            # live TUI: health, seal state, objects, audit, scrub
dezhanctl put report --file ./q3-close.tar --mode compliance --retain 86400
dezhanctl get report -o ./out  # fetch to a file
dezhanctl del report           # refused while the object is retained
dezhanctl admin scrub --admin-token "$DEZHAN_ADMIN_TOKEN"   # token-gated ops
```

## What it proves

Four things in the trusted core are machine-checked by `gnatprove` on every
commit: **325 verification conditions, 0 unproved**.

| Verified component | Invariant it guarantees |
|---|---|
| Retention state machine | retention may be extended, never shortened; a retained object cannot be deleted before expiry |
| Clock-integrity guard | a rewound clock cannot expire a lock; the vault seals instead of releasing |
| Append-only audit chain | every operation is hash-chained; history cannot be rewritten undetectably |
| Erasure coding | data survives drive loss and reconstructs exactly, or is quarantined, never returned wrong |

The cryptography (SHA-256/512, ChaCha20, HMAC, Ed25519) is in-tree. Design notes
and limits: [`docs/NOTES.md`](docs/NOTES.md).

## Using it

Standard S3 is validated against the AWS SDK (buckets, copy, multipart,
versioning, presigned URLs, SigV4, Object Lock / WORM):

```sh
ALIAS="aws --endpoint-url http://localhost:8080 --region us-east-1"
$ALIAS s3api create-bucket --bucket vault --object-lock-enabled-for-bucket
$ALIAS s3 cp important.bak s3://vault/     # any size, multipart handled
$ALIAS s3 rm  s3://vault/important.bak     # refused until retention expires
```

Install on-prem or on Kubernetes:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/obsernetics/dezhan/main/install.sh | sh
kubectl apply -f https://raw.githubusercontent.com/obsernetics/dezhan/main/deploy/dezhan.yaml
```

A vault is a single writer over durable storage; do not scale it. dezhan trades
write speed for durability, so it is slower than a plain object store on `PUT`.
Numbers and the dezhan-vs-Veeam comparison: [`bench/results/COMPARISON.md`](bench/results/COMPARISON.md).

## Configuration

`dezhan_server [port] [data-dir]`, configured by environment:

| Variable | Meaning | Default |
|---|---|---|
| `DEZHAN_VAULT_KEY` | passphrase the data key is wrapped under | demo key |
| `DEZHAN_REQUIRE_AUTH` | reject unsigned requests | unset |
| `DEZHAN_ACCESS_KEY` / `DEZHAN_SECRET` | the S3 credential | `dezhanadmin` / demo |
| `DEZHAN_ADMIN_TOKEN` | token gating `/admin/*` | unset |
| `DEZHAN_DELETE_QUORUM` / `DEZHAN_APPROVERS` | four-eyes deletes | `0` / unset |

Operator and CSI samples: [`operator/config/samples`](operator/config/samples),
[`deploy/csi/`](deploy/csi/). Builds and proofs run in the project KVM guest; see
[`CLAUDE.md`](CLAUDE.md). Early software (`v1alpha1`); [`docs/NOTES.md`](docs/NOTES.md)
records what is deferred. Licensed under the [Apache License 2.0](LICENSE).
