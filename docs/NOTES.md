# Roadmap and current limitations

This file tracks two things deliberately: planned future improvements, and stale
or placeholder implementations that exist today and must not be mistaken for
finished, verified work. Keep it current as the trusted core grows.

## Stale / placeholder / not-yet-verified implementations

- **`Dezhan.Platform.Clock` is an unverified FFI boundary.** It binds
  `clock_gettime` with `SPARK_Mode => Off`. It hardcodes `Boot_Changed => False`
  (single process lifetime, no cross-reboot detection) and drops sub-second
  precision. It is untrusted by design; the Clock Guard validates its output.
- **Guard state is not persisted.** The monotonic high-water mark
  (`Guard_State`) lives in memory only and is supplied by the caller. For the
  trusted-time floor to remain meaningful across reboots it must be persisted
  durably; that lands with the storage engine. Until then, trusted time resets
  on restart.
- **Seal is latched but not consumed.** The Clock Guard sets `Sealed` on detected
  manipulation, but nothing yet forces the vault into read-only or raises an
  operator alarm. Wiring seal to vault behavior is pending.
- **Trusted time is whole seconds from an opaque epoch (0).** It is
  monotonic-elapsed, not wall-clock. Absolute calendar time for display is not
  provided by the trusted core.
- **Forward-jump `Tolerance` has no chosen policy.** It is a caller parameter
  today; a sane default and operator policy are not yet defined.
- **`alire.toml` is metadata only.** Builds and proofs are driven by `gprbuild`
  and `gnatprove` directly; the crate manifest may be incomplete.

## Future improvements (per docs/SPEC.md, deferred by scope)

Trusted core, remaining units:

- **Audit Chain.** Hash-chained append-only log with in-tree SPARK SHA-256 and a
  tamper-evidence proof. Signed checkpoints (Ed25519 plus key management) and the
  standalone independent verifier tool are a following cycle.
- **Erasure Coding.** Reed-Solomon redundancy with configurable layout,
  reconstruction, and corruption detection.

Platform, later phases:

- Content-addressed storage engine: chunking, deduplication, compression,
  encryption at source, Merkle manifests, background scrubbing.
- S3-compatible vault API: PUT/GET/HEAD/LIST, multipart, AWS SigV4, Object Lock.
- Local auth realm, RBAC, quorum approvals, API tokens, service accounts.
- CLI and minimal web UI.
- Observability: Prometheus metrics, structured logs, health endpoints.
- Air-gap features: sync windows, seal operation, one-way ingest, technology
  break.
- Hardware-backed time anchor (TPM or secure RTC) behind the existing pluggable
  seam in the Clock Guard.
- Durable, crash-safe persistence for trusted-core state.
