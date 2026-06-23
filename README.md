# dezhan

dezhan is a secure backup vault. It replaces Veeam and MinIO with one system: an
immutable, air-gapped, S3-compatible object store built for banking-grade
security and stability, where the integrity-critical core is formally verified
in SPARK (machine-proved, not just tested).

- **Immutable by construction.** WORM retention with compliance and governance
  locks and legal hold. A retained object cannot be deleted before expiry, and a
  manipulated system clock cannot expire it.
- **S3-compatible.** PUT/GET/HEAD/DELETE, multipart upload, listing, and AWS
  SigV4 auth, so existing backup tools and clients work unchanged.
- **Verifiable integrity.** Every object is content-addressed, erasure-coded, and
  continuously scrubbed and self-healed; the trusted core's invariants are proved
  with `gnatprove`.
- **Air-gapped.** One-way ingest, sync windows, an operator seal, and
  technology-break export for offline isolation.

## Assurance

The integrity-critical core is written in SPARK and discharged by `gnatprove`
with 270 checks and 0 unproved:

- **Retention State Machine.** Retention can be extended but never shortened. In
  compliance mode a retained object cannot be deleted before expiry, with no
  override; governance mode allows only an audited bypass; a legal hold blocks
  deletion absolutely (even past expiry, even under a bypass) until released.
- **Clock Integrity Guard.** Trusted time advances only by a monotonic clock and
  is provably independent of the system clock, so moving the clock cannot expire
  a lock.
- **Audit Chain.** An append-only, hash-chained log (in-tree SHA-256). A past
  entry cannot be altered without breaking the link to its successor.
- **Erasure Coding.** Systematic Reed-Solomon over GF(2^8). Any K of the N shards
  reconstruct the original data.

The cryptographic primitives (SHA-256, ChaCha20, HMAC-SHA256) are in-tree with no
external dependency, validated against published test vectors.

## Platform

On top of the verified core, dezhan runs an end-to-end S3 service:

- **Storage** (`Dezhan.Storage.Cas`): content-addressed chunks, deduplication,
  in-tree DEFLATE compression (`Dezhan.Storage.Deflate`, RFC 1951), encryption at
  source (ChaCha20 under a per-object convergent nonce), and Reed-Solomon erasure
  coding (4 data + 2 parity per chunk). A background scrub verifies every shard
  and rebuilds missing or corrupt ones from parity.
- **Vault** (`Dezhan.Vault`): WORM orchestration tying storage, retention, clock,
  and audit together, with multipart uploads, garbage collection, legal hold, and
  air-gap modes. State is persisted, so the vault survives a restart.
- **Server** (`dezhan_server`): an HTTP/S3-style API on `GNAT.Sockets` with no
  external dependency, AWS SigV4 auth, Prometheus `/metrics`, `/healthz`, and a
  minimal web UI.
- **CLI** (`dezhan_cli`): a thin signed client, including `sput` for a
  SigV4-signed PUT.

See [`docs/SPEC.md`](docs/SPEC.md) for the specification (the source of truth) and
[`docs/NOTES.md`](docs/NOTES.md) for the roadmap and current limitations.

## Build and verify

Requires the Ada/SPARK toolchain (GNAT, `gprbuild`, and `gnatprove`, for example
installed with [Alire](https://alire.ada.dev)).

```sh
cd trusted_core
gprbuild -P dezhan_trusted_core.gpr                          # build the library
gprbuild -P tests/tests.gpr                                  # build the tests
gnatprove -P dezhan_trusted_core.gpr --level=2 --report=all  # prove the invariants
./tests/obj/test_retention && ./tests/obj/test_clock_guard   # run the tests
```

## Run

```sh
gprbuild -P server/dezhan_server.gpr
server/obj/dezhan_server 8080 /tmp/dezhan-vault   # then open http://localhost:8080/
```

## Layout

```
docs/SPEC.md    specification (source of truth)
docs/NOTES.md   roadmap and current limitations
docs/design/    per-unit design documents
trusted_core/   SPARK-verified core (src/) and tests (tests/)
storage/        content-addressed storage engine (Ada)
vault/          WORM orchestration over the trusted core (Ada)
server/         HTTP/S3-style server + web UI (Ada, GNAT.Sockets)
cli/            command-line client (Ada)
auth/           AWS SigV4 signing core (Ada, on the verified HMAC-SHA256)
```

Licensed under Apache-2.0.
