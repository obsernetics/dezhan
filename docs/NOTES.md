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
  1024). The storage engine now uses it: each chunk is stored as 4 data + 2
  parity shards (each with its own digest), so up to 2 lost/corrupt shards per
  chunk are reconstructed on read; beyond that, loss is detected. Manifests are
  erasure-protected the same way (stored as shard directories), so no single
  metadata corruption loses an object. Tuning the K/M layout per data class is a
  follow-up.

## Future improvements (per docs/SPEC.md, deferred by scope)

Trusted core: all four units plus both Audit Chain extras are implemented.
The standalone independent audit verifier (`verifier/`, `dezhan_verify <root>`)
re-parses `<root>/vault.state`, rebuilds the audit log, and re-checks it with the
SPARK-proven `Verify_Chain`, sharing no code with the vault writer (a flipped
field, forged hash, or re-linked entry all fail; exit 0 valid, 1 otherwise).
Signed checkpoints are implemented with in-tree SHA-512 (FIPS 180-4,
SPARK-proved) and Ed25519 (RFC 8032, a TweetNaCl port, validated against test
vectors): the vault signs the audit head (`Make_Checkpoint`, `POST
/admin/checkpoint`) with a key derived from the vault key, and the verifier
checks the signature against the published public key. Remaining key-management
nicety: an operator-held (rather than vault-derived) checkpoint key and escrow.

Platform layer (regular Ada, not SPARK-verified to the trusted-core degree):

- Content-addressed storage engine: a first slice exists
  (`Dezhan.Storage.Cas`): fixed-size chunking, SHA-256 content addressing,
  deduplication, Merkle-style manifest, integrity verification, corruption
  detection, and encryption at source (ChaCha20, `Dezhan.Trusted_Core.Cipher`).
  Compression is implemented: an in-tree DEFLATE codec
  (`Dezhan.Storage.Deflate`, RFC 1951, no external dependency) compresses each
  object before encryption; the manifest records the chosen mode and original
  length, and Put keeps the smaller of compressed/stored. The codec is validated
  for round-trip and for wire compatibility with zlib (raw, wbits = -15) in both
  directions.
  Still to do: content-defined chunking, multi-level manifests for large objects
  (a single object is currently capped near 1 MB), a background
  garbage collection (implemented: `Vault.Collect_Garbage` reclaims chunks and
  manifests not referenced by any live object, composite part, or in-flight
  upload). Large objects are supported via multipart
  composite objects (below), so the ~1 MB single-Put manifest cap is no longer a
  hard limit; a native multi-level manifest for single Puts is still nice to have.
- Multipart upload is implemented: `Vault.Create_Upload/Upload_Part/
  Complete_Upload/Abort_Upload` store parts as individual encrypted objects and
  complete into a composite object (its id points to the ordered list of part
  ids; Get reassembles them), which removes the single-object size cap. The
  server exposes it S3-style: `POST /v/<name>?uploads`, `PUT
  /v/<name>?uploadId=<id>`, `POST /v/<name>?uploadId=<id>` to complete, `DELETE`
  to abort. Vault logic is unit-tested; the HTTP routes are build-verified.
  Remaining: S3-exact part numbers/ETags, and query-string SigV4 canonicalization
  for signed multipart requests.
- Background scrubbing self-heals: `Vault.Scrub` verifies every object's
  manifest and chunks against their digests and rebuilds any missing or corrupt
  shard from parity in place (`Cas.Repair`), restoring full redundancy. Repair
  rewrites bit-identical content-addressed bytes, so it preserves immutability
  and is safe on a sealed vault. The server runs it during idle periods and on
  `POST /admin/scrub`, and exposes `dezhan_scrub_*` metrics including
  `dezhan_scrub_shards_repaired`. Objects that lost more than M shards are
  quarantined (audited, persisted, `dezhan_quarantined` metric); a read of a
  quarantined object is refused. Still to do: scheduling policy/cadence.
- Encryption is authenticated (encrypt-then-MAC) with key separation. The vault
  key is split into independent ENC and MAC subkeys (HMAC-SHA256 with distinct
  labels); each object carries a keyed tag, HMAC-SHA256(MK, manifest-digest),
  verified before any plaintext is produced, so a wrong key or any tampering is
  rejected (`Auth_Failed`) rather than yielding garbage. ChaCha20 uses a
  per-object nonce derived convergently from content and the enc subkey, so the
  keystream is never reused across distinct objects while identical content still
  deduplicates and Put stays idempotent. Tradeoff: convergent encryption lets a
  party that already knows a plaintext confirm whether it is stored.
- The server derives the data-encryption key from a passphrase with
  PBKDF2-HMAC-SHA256 (`Dezhan.Kdf`, validated against published vectors) over a
  per-vault random salt and a configurable work factor. The data-encryption key
  is a random DEK wrapped (encrypt-then-MAC, `Dezhan.Keystore`) under that
  passphrase-derived key and stored in `<root>/vault.key`; setting
  `DEZHAN_NEW_VAULT_KEY` re-wraps the same DEK under a new passphrase, so
  rotation never re-encrypts data. A wrong passphrase is refused at startup.
  Still to do: per-object keys and external escrow/HSM of the DEK.
- Vault + HTTP API + CLI + web UI: implemented as an end-to-end POC
  (`Dezhan.Vault`, `dezhan_server`, `dezhan_cli`). WORM enforced, audit chain,
  health, Prometheus metrics, minimal UI. Durable persistence is implemented:
  the object index, audit chain, and trusted-time high-water mark are written to
  `<root>/vault.state` on each mutation and reloaded on open, so the vault
  survives a restart. The write is crash-safe: the new state is written to a
  temp file, fsynced, atomically renamed over the live state, and the directory
  is fsynced (`Dezhan.Platform.Sync`, an audited libc FFI), so a crash leaves
  either the old or the new complete state, never a partial file. The on-disk
  format is text (a binary format is optional and not required for durability).
  An S3-compatible API is implemented and validated against the AWS SDK (boto3):
  path-style buckets and objects, ListBuckets/ListObjectsV2 (prefix/delimiter/
  continuation), CopyObject, batch delete, S3-XML multipart (partNumber-ordered),
  object versioning with delete markers (ListObjectVersions, GET/DELETE by
  versionId), Content-Type and x-amz-meta-* user metadata, conditional requests
  (If-None-Match/If-Match), object-lock buckets enforcing WORM, S3 `<Error>`
  bodies, and SigV4 in both header and presigned-URL form enforced on all data
  paths. Large single objects over the one-manifest limit are transparently
  stored as composites, so a plain large PUT works without multipart. The legacy
  flat `/v` API remains, so the bucket names `v`, `ui`, `admin`, `metrics`, and
  `healthz` are reserved (rejected on create as they collide with control
  routes). The whole S3 surface is exercised by a committed end-to-end test,
  `scripts/smoke.sh` (boto3), and the build aggregates into `dezhan.gpr`. The
  server handles connections concurrently (a pool of worker tasks; all vault
  access serialized by a lock, so integrity holds) and answers CORS preflight.
  Still to do on the S3 layer: the MinIO admin/IAM
  surface and lifecycle policies (the latter conflicts with immutable retention).
  SigV4 authentication is implemented
and enforced: the signing core (`Dezhan.Sigv4`, on the RFC 4231-validated
`Dezhan.Trusted_Core.HMAC`) is validated byte-for-byte against the AWS worked
example; the server verifies an `AWS4-HMAC-SHA256` Authorization header on `/v`
requests against a demo credential (anonymous allowed unless
`DEZHAN_REQUIRE_AUTH` is set, then 401; bad signature 403), and the CLI `sput`
command signs requests. A multi-account credential store (a "akid secret"
credentials file plus the seeded demo account) and query-string canonicalization
(so signed multipart verifies) are implemented. Remaining: interop validation
against real S3 clients (Veeam/restic), whose exact canonicalization should be
confirmed end to end, and management of the vault's data-encryption key (a fixed
demo key is used at rest).
- General-purpose Standard (mutable) per-bucket mode alongside Immutable, so
  dezhan can serve as a general-purpose S3 store. Post-MVP; immutability stays
  the headline. Both modes share the S3 API, storage engine, audit chain, and
  scrubbing; only Immutable buckets use the retention state machine.
- Local auth realm, RBAC, quorum approvals, API tokens, service accounts.
- Observability: structured (key=value) request logs, a `/healthz` endpoint, and
  Prometheus `/metrics` covering object count, storage bytes on disk, quarantined
  objects, audit length, scrub status (runs/corrupt/shards repaired), retention
  denials, trusted time, and air-gap status (sealed, ingest-only, sync window).
  Replication lag is not applicable (multi-site replication is excluded from MVP).
- Air-gap features (vault level, implemented): operator seal (read-only),
  one-way ingest (Get raises Egress_Denied), sync windows (writes raise
  Sync_Closed while closed), and technology-break export (copy the store to an
  independent, openable destination). All persisted and exposed on the server
  admin API (POST /admin/ingest-only, /admin/sync-window, /admin/export,
  /admin/gc). Still to do: scheduled (wall-clock) sync windows. The server also
  returns S3 ETag headers (the object content id) on PUT/GET/HEAD and emits
  structured (key=value) request log lines.
- Hardware-backed time anchor (TPM or secure RTC) behind the existing pluggable
  seam in the Clock Guard.
- Durable, crash-safe persistence for trusted-core state.
- CI/CD: `.github/workflows/ci.yml` provisions the toolchain via Alire, builds
  the whole product, runs every unit test (`scripts/test.sh`), and runs the SPARK
  proof of the trusted core as a **hard gate** (`scripts/prove.sh`, gnatprove
  `--checks-as-errors=on`): a single unproved check fails the build, so the
  mandatory immutability invariants stay machine-proved on every commit. The
  gate script is verified in the dev VM (0 unproved); the workflow follows
  standard Alire-on-GitHub-Actions patterns but has not been run on a GitHub
  runner from this offline environment, so the first run may need a minor
  toolchain-provisioning tweak. SBOM, signed static-binary releases, and
  coverage reporting are the remaining distribution items.
