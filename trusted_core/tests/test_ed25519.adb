pragma Ada_2022;
with Interfaces;       use Interfaces;
with Ada.Text_IO;      use Ada.Text_IO;
with Ada.Command_Line; use Ada.Command_Line;
with Dezhan.Trusted_Core.Hashing; use Dezhan.Trusted_Core.Hashing;
with Dezhan.Trusted_Core.Ed25519; use Dezhan.Trusted_Core.Ed25519;

--  Validates Ed25519 against RFC 8032 test vectors (Verify is checked against the
--  published public key/signature, so it is standard-compliant independent of the
--  seed), plus sign/verify round-trip and negative cases.
procedure Test_Ed25519 is

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

   function Nib (C : Character) return Natural is
     (case C is
         when '0' .. '9' => Character'Pos (C) - Character'Pos ('0'),
         when 'a' .. 'f' => Character'Pos (C) - Character'Pos ('a') + 10,
         when others     => 0);

   function Key (S : String) return Key_32 is
      R : Key_32;
   begin
      for I in 0 .. 31 loop
         R (I) := Byte (Nib (S (S'First + I * 2)) * 16 + Nib (S (S'First + I * 2 + 1)));
      end loop;
      return R;
   end Key;

   function Sig (S : String) return Sig_64 is
      R : Sig_64;
   begin
      for I in 0 .. 63 loop
         R (I) := Byte (Nib (S (S'First + I * 2)) * 16 + Nib (S (S'First + I * 2 + 1)));
      end loop;
      return R;
   end Sig;

   Empty : constant Byte_Array (1 .. 0) := (others => 0);

   --  RFC 8032 Test 1 (empty message).
   Pub1 : constant Key_32 :=
     Key ("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
   Sig1 : constant Sig_64 :=
     Sig ("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e0652249015" &
          "55fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");

   --  RFC 8032 Test 2 (one-byte message 0x72).
   Pub2 : constant Key_32 :=
     Key ("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
   Msg2 : constant Byte_Array (0 .. 0) := (0 => 16#72#);
   Sig2 : constant Sig_64 :=
     Sig ("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" &
          "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");

   Seed : constant Key_32 :=
     (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
      17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32);

   function Str (S : String) return Byte_Array is
      R : Byte_Array (0 .. S'Length - 1);
   begin
      for I in 0 .. S'Length - 1 loop
         R (I) := Byte (Character'Pos (S (S'First + I)));
      end loop;
      return R;
   end Str;

begin
   Check (Verify (Pub1, Empty, Sig1), "RFC 8032 test 1 signature verifies");
   Check (Verify (Pub2, Msg2, Sig2), "RFC 8032 test 2 signature verifies");

   declare
      Bad : Sig_64 := Sig1;
   begin
      Bad (10) := Bad (10) xor 1;
      Check (not Verify (Pub1, Empty, Bad), "tampered signature is rejected");
   end;
   Check (not Verify (Pub2, Empty, Sig2),
          "valid signature over a different message is rejected");

   --  Sign/verify round-trip through the (RFC-validated) verifier.
   declare
      Pub : constant Key_32 := Public_Key (Seed);
      M   : constant Byte_Array := Str ("checkpoint payload to sign");
      S   : constant Sig_64 := Sign (Seed, M);
      Bad : Sig_64 := S;
      Wrong_Pub : Key_32 := Pub;
   begin
      Check (Verify (Pub, M, S), "freshly signed message verifies");
      Bad (40) := Bad (40) xor 8;
      Check (not Verify (Pub, M, Bad), "round-trip: tampered signature rejected");
      Wrong_Pub (0) := Wrong_Pub (0) xor 1;
      Check (not Verify (Wrong_Pub, M, S), "round-trip: wrong public key rejected");
      Check (not Verify (Pub, Str ("different payload"), S),
             "round-trip: signature does not verify a different message");
   end;

   New_Line;
   if Failures = 0 then
      Put_Line ("ALL TESTS PASSED");
   else
      Put_Line ("FAILURES:" & Failures'Image);
      Set_Exit_Status (Failure);
   end if;
end Test_Ed25519;
