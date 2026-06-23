# Roadmap and current limitations

This file tracks two things deliberately: planned future improvements, and stale
or placeholder implementations that exist today and must not be mistaken for
finished, verified work. Keep it current as the trusted core grows.

## Stale / placeholder / not-yet-verified implementations

- **`Dezhan.Platform.Clock` is an unverified FFI boundary.** It binds
  `clock_gettime` with `SPARK_Mode => Off`. It hardcodes `Boot_Changed => False`
  (single process lifetime, no cross-reboot detection) and drops sub-second
  precision. It is untrusted by design; the Clock Guard validates its output.
- **Guard state persistence lives in the vault layer.** The pure Clock Guard
  keeps state in memory and takes it from the caller; the vault now persists the
  trusted-time high-water mark (the `Floor`) and the sealed flag in its on-disk
  snapshot and restores them on open, so trusted time does not reset to zero on
  restart. On reload the monotonic baseline is re-taken from the next sample
  (conservative: it never overestimates elapsed time).
- **Seal semantics.** An operator seal (`Vault.Seal`, `POST /admin/seal`) makes
  the vault read-only: writes raise `Vault_Sealed` (HTTP 503) and the seal
  persists across restart. A clock anomaly is treated as a separate alarm
  (surfaced by `Sealed`/metrics and the audit chain), not an automatic freeze,
  because the retention guarantee already holds (trusted time never advanced) and
  freezing on every clock blip would be too aggressive. Auto-seal policy on
  anomaly, and an operator unseal workflow, are future decisions.
- **Trusted time is whole seconds from an opaque epoch (0).** It is
  monotonic-elapsed, not wall-clock. Absolute calendar time for display is not
  provided by the trusted core.
- **Forward-jump `Tolerance` has no chosen policy.** It is a caller parameter
  today; a sane default and operator policy are not yet defined.
- **`alire.toml` is metadata only.** Builds and proofs are driven by `gprbuild`
  and `gnatprove` directly; the crate manifest may be incomplete.
- **Reed-Solomon reconstruction correctness is test-validated, not proved.**
  gnatprove proves the erasure unit free of run-time errors and terminating; the
  guarantee that any K of N shards reconstruct the original (the MDS property) is
  validated by an exhaustive round-trip test, the same model used for SHA-256
  against NIST vectors. Bounds are fixed (Max_Data 8, Max_Parity 8, shard length
  1024).

## Future improvements (per docs/SPEC.md, deferred by scope)

Trusted core (all four units implemented and verified): the remaining trusted-core
work is the deferred Audit Chain extras: signed checkpoints (Ed25519 plus key
management) and the standalone independent verifier tool.

Platform layer (regular Ada, not SPARK-verified to the trusted-core degree):

- Content-addressed storage engine: a first slice exists
  (`Dezhan.Storage.Cas`): fixed-size chunking, SHA-256 content addressing,
  deduplication, Merkle-style manifest, integrity verification, corruption
  detection, and encryption at source (ChaCha20, `Dezhan.Trusted_Core.Cipher`).
  Still to do: content-defined chunking, multi-level manifests for large objects
  (a single object is currently capped near 1 MB), compression, a background
  garbage collection of unreferenced chunks (a deleted object's chunks are
  currently orphaned, not reclaimed).
- Background scrubbing is implemented: `Vault.Scrub` verifies every object's
  manifest and chunks against their digests; the server runs it during idle
  periods and exposes `POST /admin/scrub` plus `dezhan_scrub_*` metrics. Still to
  do: scheduling policy/cadence and quarantining or auto-repairing detected
  corruption (the latter needs erasure-coding integration).
- Key management is not implemented: where the vault key comes from, rotation,
  per-object keys, and key wrapping are future work. The store takes a key from
  the caller; tests use a fixed key and a zero nonce with a per-chunk counter
  (a per-object random nonce is the intended hardening).
- Vault + HTTP API + CLI + web UI: implemented as an end-to-end POC
  (`Dezhan.Vault`, `dezhan_server`, `dezhan_cli`). WORM enforced, audit chain,
  health, Prometheus metrics, minimal UI. Durable persistence is implemented:
  the object index, audit chain, and trusted-time high-water mark are written to
  `<root>/vault.state` on each mutation and reloaded on open, so the vault
  survives a restart (write-temp-then-rename; full crash-safety with fsync and a
  binary format is still to do). Still to do: AWS SigV4 authentication, multipart
  uploads, S3 bucket/prefix semantics (a flat object list exists via GET /v),
concurrency (the server is single-threaded). The SigV4 signing core
(`Dezhan.Sigv4`, on the RFC 4231-validated `Dezhan.Trusted_Core.HMAC`) is
implemented and validated byte-for-byte against the AWS worked example. Still to
do: wire it into the server (canonicalize the live request: URI/header
canonicalization, payload hash, credential store) and validate against real S3
clients; that request-canonicalization exactness is the remaining work.
  structured logs, and real key management (a fixed demo key is used).
- General-purpose Standard (mutable) per-bucket mode alongside Immutable, so
  dezhan can serve as a general-purpose S3 store. Post-MVP; immutability stays
  the headline. Both modes share the S3 API, storage engine, audit chain, and
  scrubbing; only Immutable buckets use the retention state machine.
- Local auth realm, RBAC, quorum approvals, API tokens, service accounts.
- Observability: structured logs (health endpoints and Prometheus metrics exist).
- Air-gap features: the seal operation (operator read-only) is implemented;
  sync windows, one-way ingest, and technology break are still to do.
- Hardware-backed time anchor (TPM or secure RTC) behind the existing pluggable
  seam in the Clock Guard.
- Durable, crash-safe persistence for trusted-core state.
