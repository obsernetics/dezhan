pragma Ada_2022;
with Interfaces;       use Interfaces;
with Ada.Text_IO;      use Ada.Text_IO;
with Ada.Command_Line; use Ada.Command_Line;
with Dezhan.Trusted_Core.Hashing; use Dezhan.Trusted_Core.Hashing;
with Dezhan.Kdf;                  use Dezhan.Kdf;

--  Validates PBKDF2-HMAC-SHA256 against published test vectors
--  (P = "password", S = "salt"), so the KDF is proven correct, not just run.
procedure Test_Kdf is

   Failures : Natural := 0;

   procedure Check (Cond : Boolean; Msg : String) is
   begin
      if Cond then
         Put_Line ("ok   - " & Msg);
      else
         Put_Line ("FAIL - " & Msg);
         Failures := Failures + 1;
      end if;
   end Check;

   function To_Bytes (S : String) return Byte_Array is
      R : Byte_Array (0 .. S'Length - 1);
   begin
      for I in 0 .. S'Length - 1 loop
         R (I) := Byte (Character'Pos (S (S'First + I)));
      end loop;
      return R;
   end To_Bytes;

   Hex : constant String := "0123456789abcdef";

   function To_Hex (D : Digest) return String is
      R : String (1 .. 64);
   begin
      for I in 0 .. 31 loop
         R (I * 2 + 1) := Hex (Integer (D (I) / 16) + 1);
         R (I * 2 + 2) := Hex (Integer (D (I) mod 16) + 1);
      end loop;
      return R;
   end To_Hex;

   Pw : constant Byte_Array := To_Bytes ("password");
   Sa : constant Byte_Array := To_Bytes ("salt");

begin
   Check (To_Hex (PBKDF2_HMAC_SHA256 (Pw, Sa, 1)) =
          "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
          "PBKDF2-HMAC-SHA256 c=1 matches the published vector");
   Check (To_Hex (PBKDF2_HMAC_SHA256 (Pw, Sa, 2)) =
          "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43",
          "PBKDF2-HMAC-SHA256 c=2 matches the published vector");

   New_Line;
   if Failures = 0 then
      Put_Line ("ALL TESTS PASSED");
   else
      Put_Line ("FAILURES:" & Failures'Image);
      Set_Exit_Status (Failure);
   end if;
end Test_Kdf;
