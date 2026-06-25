# Design: Encryption at source (ChaCha20)

Date: 2026-06-23
Status: Implemented (cipher proved for run-time safety, validated by RFC vector)
Design scope: Storage Engine (encryption at source; MVP: encryption at rest).
(The standalone docs/SPEC.md has been retired; the implementation and these
design docs are the reference.)

## Cipher: `Dezhan.Trusted_Core.Cipher`

ChaCha20 (RFC 8439) implemented in-tree in SPARK, like the SHA-256 hash. gnatprove
proves it free of run-time errors and terminating; correctness is validated
against the RFC 8439 section 2.4.2 test vector, and a round-trip test confirms
that applying `XCrypt` twice with the same parameters is the identity.
`XCrypt (Key, Nonce, Counter, Data)` XORs Data in place with the keystream, so
encryption and decryption are the same operation.

## Integration with the content-addressed store

`Dezhan.Storage.Cas` now encrypts at source: `Put` and `Get` take a 256-bit key.
Each chunk is encrypted with ChaCha20 before it is hashed and written, so the
bytes on disk are cipher text (encryption at rest). The content address is the
SHA-256 of the cipher text, and reads verify that cipher-text digest before
decrypting, so corruption is still detected without the key (`Verify` needs no
key). Each chunk uses a disjoint keystream range: nonce zero and counter base
`chunk_index * 64` (a 4096-byte chunk is 64 ChaCha20 blocks), so no keystream is
reused within an object.

Validated by `test_cas`: the right key round-trips, a wrong key cannot recover
the data, integrity verification and deduplication still hold.

## Known limitations (tracked in docs/NOTES.md)

- Key management is not implemented: where the vault key comes from, rotation,
  per-object keys, and key wrapping are future work. Tests use a fixed key.
- The nonce is fixed at zero with a per-chunk counter, which is safe only because
  each object is encrypted under a key/layout that does not reuse a chunk index
  with different content. A per-object random nonce is the intended hardening.
- Deduplication is within a single key (convergent encryption is not used).
