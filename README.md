# dezhan

dezhan is an on-premise cyber-resilience platform for regulated organizations: an
immutable, air-gapped, formally verifiable backup vault. The value proposition is
provable immutability, meaning integrity-critical behavior is verified with SPARK
rather than only tested.

## Status

Trusted core under construction. Every invariant is discharged by `gnatprove`
with 0 unproved checks:

- **Retention State Machine.** Retention can be extended but never shortened. In
  compliance mode a retained object cannot be deleted before expiry, with no
  override; governance mode allows only an audited bypass.
- **Clock Integrity Guard.** Trusted time advances only by a monotonic clock and
  is provably independent of the untrusted system clock, so moving the system
  clock cannot expire a lock.
- **Audit Chain.** An append-only, hash-chained log with in-tree SHA-256. A past
  entry cannot be altered without breaking the link to its successor (proved,
  given standard hash collision resistance).
- **Erasure Coding.** Systematic Reed-Solomon over GF(2^8). Any K of the N shards
  reconstruct the original data; validated by an exhaustive round-trip test.

This completes the SPARK-verified trusted core (232 checks, 0 unproved).

Platform layer (regular Ada), an end-to-end POC on top of the verified core:

- **Storage** (`Dezhan.Storage.Cas`): content-addressed chunks (SHA-256), a
  Merkle-style manifest, deduplication, encryption at source (ChaCha20), and
  corruption detection on read.
- **Vault** (`Dezhan.Vault`): ties storage + retention + clock + audit into WORM
  behavior. A compliance-locked object cannot be deleted before expiry (even with
  a bypass), a manipulated clock cannot expire it, and every action is recorded
  in a self-verifying audit chain.
- **Server** (`dezhan_server`): a small HTTP API (PUT/GET/HEAD/DELETE under
  `/v/<name>`, plus `/healthz`, Prometheus `/metrics`, and a minimal web UI at
  `/`), built on `GNAT.Sockets` with no external dependency.
- **CLI** (`dezhan_cli`): a thin client for the server.

The vault persists its object index, audit chain, and trusted-time high-water
mark to disk, so it survives a restart. SigV4 authentication, multipart uploads,
and key management are not in the POC (see `docs/NOTES.md`).

See [`docs/SPEC.md`](docs/SPEC.md) for the specification and
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
```

## Run the POC

```sh
# in the build environment (GNAT + gnatprove via Alire)
gprbuild -P server/dezhan_server.gpr
server/obj/dezhan_server 8080 /tmp/dezhan-vault   # then open http://localhost:8080/
```

Licensed under Apache-2.0.
