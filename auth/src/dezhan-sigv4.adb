with Dezhan.Trusted_Core.Hashing; use Dezhan.Trusted_Core.Hashing;
with Dezhan.Trusted_Core.HMAC;    use Dezhan.Trusted_Core.HMAC;

package body Dezhan.Sigv4 with SPARK_Mode => Off is

   Hex_Digits : constant String := "0123456789abcdef";

   function To_Bytes (S : String) return Byte_Array is
      R : Byte_Array (0 .. S'Length - 1);
   begin
      for I in 0 .. S'Length - 1 loop
         R (I) := Byte (Character'Pos (S (S'First + I)));
      end loop;
      return R;
   end To_Bytes;

   function Digest_Bytes (D : Digest) return Byte_Array is
      R : Byte_Array (0 .. 31);
   begin
      for I in 0 .. 31 loop
         R (I) := D (I);
      end loop;
      return R;
   end Digest_Bytes;

   function Hex (D : Digest) return String is
      R : String (1 .. 64);
   begin
      for I in 0 .. 31 loop
         R (I * 2 + 1) := Hex_Digits (Integer (D (I)) / 16 + 1);
         R (I * 2 + 2) := Hex_Digits (Integer (D (I)) mod 16 + 1);
      end loop;
      return R;
   end Hex;

   LF : constant String := (1 => ASCII.LF);

   function Hex_SHA256 (Data : String) return String is
   begin
      return Hex (SHA256 (To_Bytes (Data)));
   end Hex_SHA256;

   function Signature_For
     (Secret, Method, Canonical_URI, Canonical_Query,
      Canonical_Headers, Signed_Headers, Payload_Hash,
      Amz_Date, Scope_Date, Region, Service : String) return String
   is
      Canonical_Request : constant String :=
        Method & LF & Canonical_URI & LF & Canonical_Query & LF
        & Canonical_Headers & LF & Signed_Headers & LF & Payload_Hash;
      Scope : constant String :=
        Scope_Date & "/" & Region & "/" & Service & "/aws4_request";
      String_To_Sign : constant String :=
        "AWS4-HMAC-SHA256" & LF & Amz_Date & LF & Scope & LF
        & Hex_SHA256 (Canonical_Request);
   begin
      return Signature (Secret, Scope_Date, Region, Service, String_To_Sign);
   end Signature_For;

   function Signature
     (Secret, Date, Region, Service, String_To_Sign : String) return String
   is
      K_Date    : constant Digest :=
        HMAC_SHA256 (To_Bytes ("AWS4" & Secret), To_Bytes (Date));
      K_Region  : constant Digest :=
        HMAC_SHA256 (Digest_Bytes (K_Date), To_Bytes (Region));
      K_Service : constant Digest :=
        HMAC_SHA256 (Digest_Bytes (K_Region), To_Bytes (Service));
      K_Signing : constant Digest :=
        HMAC_SHA256 (Digest_Bytes (K_Service), To_Bytes ("aws4_request"));
   begin
      return Hex (HMAC_SHA256 (Digest_Bytes (K_Signing),
                               To_Bytes (String_To_Sign)));
   end Signature;

end Dezhan.Sigv4;
