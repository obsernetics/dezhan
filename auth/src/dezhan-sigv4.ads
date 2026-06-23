--  AWS Signature Version 4 signing core (RFC-style HMAC chain), built on the
--  SPARK-verified HMAC-SHA256. This computes the SigV4 signing key and the final
--  signature from a string-to-sign; constructing the canonical request from a
--  live HTTP request (URI/header canonicalization, payload hash) is the server's
--  job. Regular Ada (string handling); the cryptography underneath is verified.
package Dezhan.Sigv4 with SPARK_Mode => Off is

   --  Lowercase hex of a 32-byte digest (64 chars).
   --  The SigV4 four-step signing key: HMAC chain over date, region, service,
   --  and the "aws4_request" terminator, keyed initially by "AWS4"+secret.
   function Signature
     (Secret, Date, Region, Service, String_To_Sign : String) return String;

end Dezhan.Sigv4;
