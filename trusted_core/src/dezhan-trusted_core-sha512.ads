--  SHA-512 (FIPS 180-4), in-tree, the hash Ed25519 uses for signed audit
--  checkpoints. Same construction as the SHA-256 here, with 64-bit words and 80
--  rounds. Validated against published test vectors in the test suite.
with Dezhan.Trusted_Core.Hashing; use Dezhan.Trusted_Core.Hashing;
package Dezhan.Trusted_Core.SHA512 with SPARK_Mode is

   type Digest512 is array (Natural range 0 .. 63) of Byte;  --  512 bits

   --  Upper bound on the input length accepted (Ed25519 hashes only short
   --  prefixes plus the checkpoint payload, so this is ample).
   Max_Message : constant := 8192;

   function SHA512 (Msg : Byte_Array) return Digest512
     with Pre => Msg'Length <= Max_Message;

end Dezhan.Trusted_Core.SHA512;
