# Design: Content-Addressed Storage engine (first slice)

Date: 2026-06-23
Status: First slice implemented
Spec source of truth: `docs/SPEC.md` (Storage Engine).

## Goal

Begin the platform storage layer: a content-addressed immutable store following
`Object -> Chunk -> Hash -> Immutable Storage`, reusing the SPARK-verified
SHA-256 from the trusted core. This is regular Ada (`SPARK_Mode => Off`) because
it does file I/O; the trust comes from the verified hash plus integrity checks
on every read.

## This slice (`Dezhan.Storage.Cas`)

- An object is split into fixed-size chunks (4096 bytes). Each chunk is stored at
  `objects/<2 hex>/<64 hex>` under its SHA-256, so identical chunks deduplicate
  and the store is naturally immutable (a different object yields a different id).
- A manifest holds the object length and the ordered chunk digests; its own
  SHA-256, in hex, is the object id, stored at `manifests/<64 hex>`.
- `Put` returns the object id and is idempotent. `Get` reassembles, verifying the
  manifest against the requested id and every chunk against its digest. `Verify`
  scrubs without reassembling. Any mismatch raises `Corruption_Detected`
  (Merkle-style integrity, so silent corruption is caught).

## Validated by test

`test_cas`: round-trip equality, intact verify, stable id on re-put
(deduplication), corruption detection after a chunk byte is flipped, and empty
object round-trip.

## Known limitations (tracked in docs/NOTES.md)

- Fixed-size chunking; content-defined chunking is future.
- Single-level manifest: the manifest must fit the SHA-256 input bound, capping a
  single object at roughly 1 MB. A multi-level Merkle manifest removes this.
- No encryption at rest yet, no compression, no background scrubber loop, no GC of
  unreferenced chunks. Not formally verified (file I/O).

## Next

Encryption at source, a multi-level manifest for large objects, then the S3 vault
facade that exposes this store with Object Lock and per-bucket modes.
