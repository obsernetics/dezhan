--  AWS Signature Version 4 signing core (RFC-style HMAC chain), built on the
--  SPARK-verified HMAC-SHA256. This computes the SigV4 signing key and the final
--  signature from a string-to-sign; constructing the canonical request from a
--  live HTTP request (URI/header canonicalization, payload hash) is the server's
--  job. Regular Ada (string handling); the cryptography underneath is verified.
package Dezhan.Sigv4 with SPARK_Mode => Off is

   --  Final SigV4 signature from a fully formed string-to-sign. The signing key
   --  is the four-step HMAC chain over date/region/service/aws4_request, keyed
   --  initially by "AWS4"+secret. Validated against the AWS worked example.
   function Signature
     (Secret, Date, Region, Service, String_To_Sign : String) return String;

   --  Lowercase hex of SHA-256 over Data (Data must fit the hash input bound).
   function Hex_SHA256 (Data : String) return String;

   --  Compute the expected SigV4 signature for a request. Builds the canonical
   --  request and string-to-sign per AWS, then signs. The server compares the
   --  result to the client's Signature; equality authenticates the request.
   --    Canonical_Headers : "name:value\n" lines for the signed headers (sorted,
   --                        lowercase names, trimmed values).
   --    Signed_Headers    : "h1;h2;..." sorted lowercase names.
   --    Payload_Hash      : hex SHA-256 of the body, or "UNSIGNED-PAYLOAD".
   function Signature_For
     (Secret, Method, Canonical_URI, Canonical_Query,
      Canonical_Headers, Signed_Headers, Payload_Hash,
      Amz_Date, Scope_Date, Region, Service : String) return String;

end Dezhan.Sigv4;
