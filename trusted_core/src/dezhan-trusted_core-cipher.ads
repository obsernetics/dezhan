--  ChaCha20 stream cipher (RFC 8439), for encryption at source.
--
--  Implemented in-tree in SPARK like the SHA-256 hash: gnatprove proves absence
--  of run-time errors and termination; correctness is validated against the
--  RFC 8439 test vector. Encryption and decryption are the same operation (XOR
--  with the keystream). Key management (where keys come from, rotation, wrapping)
--  is a separate concern handled above this primitive.
with Interfaces;                  use Interfaces;
with Dezhan.Trusted_Core.Hashing; use Dezhan.Trusted_Core.Hashing;  --  Byte, Byte_Array
package Dezhan.Trusted_Core.Cipher with SPARK_Mode is

   type Key_256  is array (0 .. 31) of Byte;  --  256-bit key
   type Nonce_96 is array (0 .. 11) of Byte;  --  96-bit nonce

   --  XOR Data in place with the ChaCha20 keystream for (Key, Nonce, Counter).
   --  Applying it twice with the same parameters recovers the original.
   procedure XCrypt
     (Key     : Key_256;
      Nonce   : Nonce_96;
      Counter : Unsigned_32;
      Data    : in out Byte_Array);

end Dezhan.Trusted_Core.Cipher;
