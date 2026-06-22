--  SHA-256 in SPARK (FIPS 180-4), used by the Audit Chain.
--
--  Implemented in-tree so the hash lives inside the verified core with no
--  external crypto dependency. gnatprove proves absence of run-time errors and
--  termination; functional correctness is validated against NIST test vectors
--  in the test suite. Collision resistance is a cryptographic assumption, not a
--  provable property; the Audit Chain documents where it relies on it.
with Interfaces; use Interfaces;
package Dezhan.Trusted_Core.Hashing with SPARK_Mode is

   subtype Byte is Interfaces.Unsigned_8;
   type Byte_Array is array (Natural range <>) of Byte;

   subtype Digest_Index is Natural range 0 .. 31;
   type Digest is array (Digest_Index) of Byte;  --  256 bits

   --  Upper bound on the input length this implementation accepts. Audit-entry
   --  serializations are far smaller; this also bounds the padded buffer.
   Max_Message : constant := 8192;

   function SHA256 (Msg : Byte_Array) return Digest
     with Pre => Msg'Length <= Max_Message;

end Dezhan.Trusted_Core.Hashing;
