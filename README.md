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

Platform layer (regular Ada, in progress): a content-addressed storage engine
(`Dezhan.Storage.Cas`) stores objects as SHA-256-addressed chunks with a
Merkle-style manifest, deduplicates, and detects corruption on read.

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
```

Licensed under Apache-2.0.
