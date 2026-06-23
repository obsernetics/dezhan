--  HMAC-SHA256 (RFC 2104 / RFC 4231), built on the in-tree SHA-256.
--
--  Used for AWS Signature V4 request authentication and (later) signed audit
--  checkpoints. SPARK-verified for absence of run-time errors; correctness is
--  validated against the RFC 4231 test vectors.
with Dezhan.Trusted_Core.Hashing; use Dezhan.Trusted_Core.Hashing;
package Dezhan.Trusted_Core.HMAC with SPARK_Mode is

   Max_Key : constant := 256;
   --  Leave room for the 64-byte key block prefixed to the message inside the
   --  inner hash (SHA-256 accepts up to Hashing.Max_Message).
   Max_Msg : constant := Hashing.Max_Message - 64;

   function HMAC_SHA256 (Key : Byte_Array; Msg : Byte_Array) return Digest
     with Pre => Key'Length <= Max_Key and then Msg'Length <= Max_Msg;

end Dezhan.Trusted_Core.HMAC;
