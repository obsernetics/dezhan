# Design: Erasure Coding (SPARK trusted core)

Date: 2026-06-23
Status: Implemented and verified
Spec source of truth: `docs/SPEC.md` (Trusted Core, Erasure Coding).

## Goal

Fourth and final trusted-core unit: Reed-Solomon redundancy enforcing the
mandatory invariant:

```
Recoverable failures must always reconstruct original content.
```

Requirements (per spec): configurable data/parity layout, reconstruction of
missing shards, corruption detection.

## Approach

Systematic Reed-Solomon over GF(2^8) (the de-facto standard for storage erasure
codes), implemented in-tree in SPARK with no external dependency.

- Field: GF(256) with reduction polynomial 0x11D. Addition is XOR; multiplication
  is the bytewise carry-less multiply with reduction; inversion is `a^254`
  (made total, with `inv(0) = 0`, so no division precondition is needed).
- Coding matrix: the data shards are kept verbatim (systematic). Parity rows come
  from a Cauchy matrix `C[i][j] = inv(X[i] xor Y[j])` with disjoint point sets
  `Y = {0..K-1}` and `X = {Max_Data .. Max_Data+M-1}`. Cauchy matrices are MDS, so
  any K of the N = K+M shards suffice to reconstruct.
- Encode: each parity byte is the GF combination of the K data bytes at that
  offset.
- Reconstruct: pick any K available shards, build the K-by-K submatrix of the
  full coding matrix for those shards, invert it by Gauss-Jordan over GF(256),
  and recover the K data shards per byte offset. Returns a Success flag (False
  only if fewer than K shards are available or, defensively, the submatrix is
  singular, which cannot happen for the MDS construction).

## Bounds (fixed, for predictable proofs)

`Max_Data = 8`, `Max_Parity = 8`, `Max_Shards = 16`, `Max_Shard_Length = 1024`.
K, M, and the shard length are runtime parameters within these bounds.

## What is proved, and what is validated

- gnatprove proves the whole unit free of run-time errors and terminating
  (all array indexing within bounds, GF loops bounded, `Pow` loop variant).
- Algebraic correctness (that any K of N shards reconstruct the original) is the
  Reed-Solomon / MDS theorem; it is not formally proved here, exactly as SHA-256
  correctness is validated against NIST vectors rather than proved. It is
  validated by an exhaustive round-trip test: for a representative layout, every
  erasure pattern that leaves at least K shards present reconstructs the original
  data exactly. This is recorded as a known boundary in `docs/NOTES.md`.

## Corruption detection

Silent corruption (wrong bytes at unknown positions) is detected by the content
hashes and scrubbing in the storage engine and the audit chain, which then mark
the bad shard as an erasure for this unit to reconstruct. Reed-Solomon here
operates on the erasure model (known-missing shards).

## Acceptance criteria

1. The library and tests compile.
2. `gnatprove` reports 0 unproved checks across the trusted core.
3. `test_erasure` passes, including the exhaustive erasure round-trip.
