with Ada.Strings.Unbounded;       use Ada.Strings.Unbounded;
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

   function Uri_Encode (S : String) return String is
      Out_S : String (1 .. 3 * S'Length);
      Last  : Natural := 0;
   begin
      for C of S loop
         if C in 'A' .. 'Z' | 'a' .. 'z' | '0' .. '9' | '-' | '_' | '.' | '~' then
            Last := Last + 1;
            Out_S (Last) := C;
         else
            Out_S (Last + 1) := '%';
            Out_S (Last + 2) := Hex_Digits (Character'Pos (C) / 16 + 1);
            Out_S (Last + 3) := Hex_Digits (Character'Pos (C) mod 16 + 1);
            Last := Last + 3;
         end if;
      end loop;
      return Out_S (1 .. Last);
   end Uri_Encode;

   function Canonical_Query (Raw_Query : String) return String is
      Max   : constant := 64;
      Parts : array (1 .. Max) of Unbounded_String;
      N     : Natural := 0;

      procedure Add (Token : String) is
         Eq : Natural := 0;
      begin
         if Token'Length = 0 or else N = Max then
            return;
         end if;
         for I in Token'Range loop
            if Token (I) = '=' then
               Eq := I;
               exit;
            end if;
         end loop;
         N := N + 1;
         if Eq = 0 then
            Parts (N) := To_Unbounded_String (Uri_Encode (Token) & "=");
         else
            Parts (N) := To_Unbounded_String
              (Uri_Encode (Token (Token'First .. Eq - 1)) & "="
               & Uri_Encode (Token (Eq + 1 .. Token'Last)));
         end if;
      end Add;

      Start : Natural := Raw_Query'First;
   begin
      for I in Raw_Query'Range loop
         if Raw_Query (I) = '&' then
            Add (Raw_Query (Start .. I - 1));
            Start := I + 1;
         end if;
      end loop;
      if Raw_Query'Length > 0 then
         Add (Raw_Query (Start .. Raw_Query'Last));
      end if;

      --  Selection sort by encoded "name=value".
      for I in 1 .. N loop
         for J in I + 1 .. N loop
            if Parts (J) < Parts (I) then
               declare
                  T : constant Unbounded_String := Parts (I);
               begin
                  Parts (I) := Parts (J);
                  Parts (J) := T;
               end;
            end if;
         end loop;
      end loop;

      declare
         R : Unbounded_String;
      begin
         for I in 1 .. N loop
            if I > 1 then
               Append (R, "&");
            end if;
            Append (R, Parts (I));
         end loop;
         return To_String (R);
      end;
   end Canonical_Query;

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
