--  Ed25519 signatures (RFC 8032), for signed audit checkpoints. This is a port
--  of the public-domain TweetNaCl reference implementation (field arithmetic
--  over 2^255-19, Edwards-curve scalar multiplication, sign/verify), built on
--  the in-tree SHA-512. Regular Ada (SPARK_Mode off, like DEFLATE): correctness
--  is validated against RFC 8032 test vectors rather than proved. The audit
--  chain's tamper-evidence is proved independently; signatures add operator
--  authentication of checkpoints on top.
with Dezhan.Trusted_Core.Hashing; use Dezhan.Trusted_Core.Hashing;
package Dezhan.Trusted_Core.Ed25519 with SPARK_Mode => Off is

   type Key_32 is array (0 .. 31) of Byte;   --  seed or public key
   type Sig_64 is array (0 .. 63) of Byte;   --  signature (R || S)

   --  Public key for a 32-byte secret seed.
   function Public_Key (Seed : Key_32) return Key_32;

   --  Detached signature of Msg under Seed.
   function Sign (Seed : Key_32; Msg : Byte_Array) return Sig_64
     with Pre => Msg'Length <= 4096;

   --  True iff Sig is a valid Ed25519 signature of Msg under Public.
   function Verify (Public : Key_32; Msg : Byte_Array; Sig : Sig_64)
                    return Boolean
     with Pre => Msg'Length <= 4096;

end Dezhan.Trusted_Core.Ed25519;
