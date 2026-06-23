pragma Ada_2022;
with Interfaces;       use Interfaces;
with Ada.Text_IO;      use Ada.Text_IO;
with Ada.Command_Line; use Ada.Command_Line;
with Dezhan.Trusted_Core.Hashing; use Dezhan.Trusted_Core.Hashing;
with Dezhan.Trusted_Core.SHA512;  use Dezhan.Trusted_Core.SHA512;

--  Validates SHA-512 against FIPS 180-4 / published test vectors.
procedure Test_SHA512 is

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

   HexD : constant String := "0123456789abcdef";

   function Hex (D : Digest512) return String is
      R : String (1 .. 128);
   begin
      for I in 0 .. 63 loop
         R (I * 2 + 1) := HexD (Integer (D (I) / 16) + 1);
         R (I * 2 + 2) := HexD (Integer (D (I) mod 16) + 1);
      end loop;
      return R;
   end Hex;

   function B (S : String) return Byte_Array is
      R : Byte_Array (0 .. S'Length - 1);
   begin
      for I in 0 .. S'Length - 1 loop
         R (I) := Byte (Character'Pos (S (S'First + I)));
      end loop;
      return R;
   end B;

begin
   Check (Hex (SHA512 (B (""))) =
          "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" &
          "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
          "SHA-512 of empty string");
   Check (Hex (SHA512 (B ("abc"))) =
          "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" &
          "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
          "SHA-512 of 'abc'");
   Check (Hex (SHA512 (B ("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghi" &
                          "jklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"))) =
          "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018" &
          "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
          "SHA-512 of the 112-byte NIST vector");

   New_Line;
   if Failures = 0 then
      Put_Line ("ALL TESTS PASSED");
   else
      Put_Line ("FAILURES:" & Failures'Image);
      Set_Exit_Status (Failure);
   end if;
end Test_SHA512;
