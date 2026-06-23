--  PBKDF2-HMAC-SHA256 (RFC 8018) for deriving a vault key from a passphrase.
--
--  Built on the SPARK-verified HMAC-SHA256. A single output block is produced
--  (dkLen = hLen = 32 bytes = one Digest), which is all a 256-bit key needs.
--  Correctness is validated against published PBKDF2-HMAC-SHA256 test vectors.
with Dezhan.Trusted_Core.Hashing; use Dezhan.Trusted_Core.Hashing;
package Dezhan.Kdf with SPARK_Mode => Off is

   --  Derive a 256-bit key. Iterations is the PBKDF2 work factor (c); a higher
   --  value makes brute-forcing the passphrase proportionally more expensive.
   function PBKDF2_HMAC_SHA256
     (Password, Salt : Byte_Array; Iterations : Positive) return Digest
     with Pre => Password'Length <= 256 and then Salt'Length <= 8000;

end Dezhan.Kdf;
