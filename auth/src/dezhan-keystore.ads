--  Key wrapping for passphrase rotation.
--
--  The vault encrypts data under a random 256-bit data-encryption key (DEK).
--  The DEK is wrapped (encrypt-then-MAC) under a key-encryption key (KEK)
--  derived from the operator passphrase. Rotating the passphrase only re-wraps
--  the DEK, so stored data is never re-encrypted. Built on the SPARK-verified
--  ChaCha20 and HMAC-SHA256.
with Dezhan.Trusted_Core.Cipher;  use Dezhan.Trusted_Core.Cipher;
with Dezhan.Trusted_Core.Hashing; use Dezhan.Trusted_Core.Hashing;
package Dezhan.Keystore with SPARK_Mode => Off is

   type Wrapped_Key is record
      Nonce  : Nonce_96;   --  per-wrap random nonce
      Cipher : Key_256;    --  ChaCha20-encrypted DEK
      Tag    : Digest;     --  HMAC-SHA256 over Nonce || Cipher
   end record;

   --  Wrap DEK under KEK with the given nonce. Key-separated: independent
   --  encryption and MAC subkeys are derived from KEK.
   function Wrap (KEK : Key_256; Nonce : Nonce_96; DEK : Key_256)
                  return Wrapped_Key;

   --  Recover the DEK. Ok is False (and DEK zeroed) if the tag does not verify,
   --  i.e. the passphrase is wrong or the wrapped key was tampered with.
   procedure Unwrap (KEK : Key_256; W : Wrapped_Key;
                     DEK : out Key_256; Ok : out Boolean);

end Dezhan.Keystore;
