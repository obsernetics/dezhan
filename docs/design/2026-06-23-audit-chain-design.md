# Design: Audit Chain (SPARK trusted core)

Date: 2026-06-23
Status: Implemented and verified
Design scope: Trusted Core, Audit Chain. (The standalone docs/SPEC.md has been retired; the implementation and these design docs are the reference.)

## Goal

Third unit of the SPARK trusted core: an append-only, hash-chained log enforcing
the mandatory invariant:

```
Past audit records cannot be altered undetected.
```

Decisions: SHA-256 is implemented in-tree in SPARK (no external crypto
dependency). Signed checkpoints (Ed25519 plus key management), the on-disk log
format, and the standalone independent verifier tool are deferred to later
cycles (see `docs/NOTES.md`).

## Components

- `Dezhan.Trusted_Core.Hashing`: SHA-256 (FIPS 180-4) over byte arrays, using
  32-bit modular arithmetic so no overflow can occur. gnatprove proves absence of
  run-time errors and termination; correctness is validated against NIST vectors.
- `Dezhan.Trusted_Core.Audit`: the hash-chained log built on that hash.

## Data model

An `Audit_Entry` holds `Seq`, `Time` (the trusted time from the Clock Guard),
`Kind`, `Subject` (a digest identifying the object), `Detail`, `Prev_Hash`, and
`Hash`. `Hash_Of` serializes the hashed fields in a fixed byte layout and applies
SHA-256. `Compute_Hash (E)` calls `Hash_Of` on the entry fields and is therefore
provably independent of the stored `Hash` field: setting an entry's hash cannot
change its computed hash. The genesis entry has sequence 0 and a zero
`Prev_Hash`; each later entry stores `Prev_Hash = predecessor.Hash`.

## Invariants proved by gnatprove

- SHA-256: no run-time errors, terminates.
- `Genesis_Entry` and `Append`: the result is self-consistent
  (`Hash = Compute_Hash (result)`) and `Append`'s result links to its
  predecessor (correct sequence and `Prev_Hash`).
- `Lemma_Tamper_Breaks_Link`: if `P` and a tampered `P'` are both
  self-consistent, `P'` differs from `P` in some hashed field, and `E` links to
  `P`, then `E` does not link to `P'`. In other words, a past entry cannot be
  altered without breaking the successor's link. This rests on one explicit
  assumption (`Assume_Hash_Binds`): equal hashes imply equal fields, which
  combines SHA-256 collision resistance with the injectivity of the fixed-layout
  serialization. Neither is provable; both are standard cryptographic
  assumptions, documented here and in `docs/NOTES.md`.

`Verify_Chain` is an executable whole-chain check (genesis head plus a valid link
at each step) used by the tests and, later, the independent verifier. The full
inductive "head digest determines the whole chain" theorem is future work; this
cycle proves the per-link property and exercises chain verification at runtime.

## Acceptance criteria

1. The library and tests compile.
2. `gnatprove` reports 0 unproved checks across the trusted core.
3. `test_hashing` (NIST vectors) and `test_audit` (build, verify, tamper
   detection) run green.
