# dezhan

A secure, immutable backup vault that speaks S3. Point any S3 client or backup
tool at it (aws-cli, restic, Veeam, Velero, boto3) and your data is stored
content-addressed, encrypted, erasure-coded, and optionally WORM-locked so it
cannot be modified or deleted before its retention expires.

It is a drop-in replacement for the storage target of Veeam and MinIO, with the
integrity-critical core formally verified in SPARK.

## Quick start

Build (needs the Ada/SPARK toolchain, e.g. via [Alire](https://alire.ada.dev)):

```sh
gprbuild -P server/dezhan_server.gpr      # the S3 server
gprbuild -P cli/dezhan_cli.gpr            # optional CLI
```

Run the server (`<port> <data-dir>`):

```sh
export DEZHAN_VAULT_KEY="a-strong-passphrase"   # encrypts data at rest
export DEZHAN_REQUIRE_AUTH=1                     # require signed requests
server/obj/dezhan_server 8080 /var/lib/dezhan
```

On first start it generates a random data key wrapped under your passphrase and
prints `dezhan server listening on port 8080`.

## Use it with the AWS CLI

```sh
aws configure set aws_access_key_id     dezhanadmin
aws configure set aws_secret_access_key dezhandemosecretkey0123456789
aws configure set default.s3.addressing_style path

ALIAS="aws --endpoint-url http://localhost:8080 --region us-east-1"

$ALIAS s3 mb s3://backups                  # create a bucket
$ALIAS s3 cp ./data.tar s3://backups/      # upload (any size; multipart handled)
$ALIAS s3 ls s3://backups/                 # list
$ALIAS s3 cp s3://backups/data.tar ./      # download
```

(Use your own keys via `DEZHAN_ACCESS_KEY` / `DEZHAN_SECRET` when starting the
server.)

## Use it with restic

```sh
export AWS_ACCESS_KEY_ID=dezhanadmin
export AWS_SECRET_ACCESS_KEY=dezhandemosecretkey0123456789
restic -r s3:http://localhost:8080/backups init
restic -r s3:http://localhost:8080/backups backup ~/documents
```

## Make a bucket immutable (WORM / Object Lock)

```sh
# objects in this bucket cannot be overwritten or deleted before they expire
$ALIAS s3api create-bucket --bucket vault --object-lock-enabled-for-bucket
$ALIAS s3 cp important.bak s3://vault/
$ALIAS s3 rm s3://vault/important.bak      # -> denied (403) until retention expires
```

Retention is enforced by a formally verified state machine, and a manipulated
system clock cannot expire a lock.

## What works

Standard S3, validated against the AWS SDK (boto3):

- Buckets: create / head / delete / list, location, versioning, object-lock config
- Objects: put, get, head, delete, byte-range reads, copy, batch delete
- Large objects and multipart uploads
- Versioning with delete markers (`GET`/`DELETE` by version id, list versions)
- Content-Type and user metadata (`x-amz-meta-*`)
- Conditional requests (`If-None-Match` / `If-Match`)
- Presigned URLs, and SigV4 auth (header and query forms)
- Object Lock / WORM, legal hold, and audited retention

## Configuration

| Variable | Meaning | Default |
|---|---|---|
| `DEZHAN_VAULT_KEY` | passphrase the data key is wrapped under | `dezhan-demo-vault-key` |
| `DEZHAN_NEW_VAULT_KEY` | set to rotate the passphrase on startup | (unset) |
| `DEZHAN_REQUIRE_AUTH` | reject unsigned requests when set | (unset = anonymous) |
| `DEZHAN_ACCESS_KEY` / `DEZHAN_SECRET` | the S3 credential | `dezhanadmin` / demo secret |
| `DEZHAN_CREDENTIALS` | extra `accesskey secret` lines, one per account | `<root>/credentials` |
| `DEZHAN_KDF_ITERS` | PBKDF2 work factor | `200000` |

Server arguments: `dezhan_server [port] [data-dir]` (defaults `8080`,
`/tmp/dezhan-vault`).

## Operations

- `GET /healthz` - liveness (`ok` or `sealed`)
- `GET /metrics` - Prometheus metrics (objects, storage bytes, scrub status, air-gap state, ...)
- `POST /admin/seal` - make the vault read-only
- `POST /admin/scrub` - verify and self-heal every object now
- `POST /admin/checkpoint` - sign the audit head; `dezhan_verify <data-dir>` re-checks it offline
- A web UI is served at `/`

## How it works

Provable immutability is the point: the retention state machine, clock-integrity
guard, append-only audit chain, and erasure coding are written in SPARK and
machine-checked by `gnatprove` (325 checks, 0 unproved). The cryptography
(SHA-256/512, ChaCha20, HMAC-SHA256, Ed25519) is in-tree with no external
dependency. See [`docs/SPEC.md`](docs/SPEC.md) for the specification and
[`docs/NOTES.md`](docs/NOTES.md) for design notes and current limitations.

Licensed under Apache-2.0.
