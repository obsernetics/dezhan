pragma Ada_2022;
with Ada.Text_IO;      use Ada.Text_IO;
with Ada.Command_Line; use Ada.Command_Line;
with Interfaces;       use Interfaces;
with Dezhan.Trusted_Core.Hashing; use Dezhan.Trusted_Core.Hashing;
with Dezhan.Trusted_Core.Cipher;  use Dezhan.Trusted_Core.Cipher;

--  Validates ChaCha20 against the RFC 8439 section 2.4.2 test vector, and that
--  encryption followed by decryption is the identity.
procedure Test_Cipher is

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

   Key : constant Key_256 :=
     (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
      16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31);

   Nonce : constant Nonce_96 :=
     (0, 0, 0, 0, 0, 0, 0, 16#4a#, 0, 0, 0, 0);

   Plain_Text : constant String :=
     "Ladies and Gentlemen of the class of '99: If I could offer you only "
     & "one tip for the future, sunscreen would be it.";

   --  RFC 8439 section 2.4.2 expected ciphertext (114 bytes).
   Expected : constant Byte_Array (0 .. 113) :=
     (16#6e#, 16#2e#, 16#35#, 16#9a#, 16#25#, 16#68#, 16#f9#, 16#80#,
      16#41#, 16#ba#, 16#07#, 16#28#, 16#dd#, 16#0d#, 16#69#, 16#81#,
      16#e9#, 16#7e#, 16#7a#, 16#ec#, 16#1d#, 16#43#, 16#60#, 16#c2#,
      16#0a#, 16#27#, 16#af#, 16#cc#, 16#fd#, 16#9f#, 16#ae#, 16#0b#,
      16#f9#, 16#1b#, 16#65#, 16#c5#, 16#52#, 16#47#, 16#33#, 16#ab#,
      16#8f#, 16#59#, 16#3d#, 16#ab#, 16#cd#, 16#62#, 16#b3#, 16#57#,
      16#16#, 16#39#, 16#d6#, 16#24#, 16#e6#, 16#51#, 16#52#, 16#ab#,
      16#8f#, 16#53#, 16#0c#, 16#35#, 16#9f#, 16#08#, 16#61#, 16#d8#,
      16#07#, 16#ca#, 16#0d#, 16#bf#, 16#50#, 16#0d#, 16#6a#, 16#61#,
      16#56#, 16#a3#, 16#8e#, 16#08#, 16#8a#, 16#22#, 16#b6#, 16#5e#,
      16#52#, 16#bc#, 16#51#, 16#4d#, 16#16#, 16#cc#, 16#f8#, 16#06#,
      16#81#, 16#8c#, 16#e9#, 16#1a#, 16#b7#, 16#79#, 16#37#, 16#36#,
      16#5a#, 16#f9#, 16#0b#, 16#bf#, 16#74#, 16#a3#, 16#5b#, 16#e6#,
      16#b4#, 16#0b#, 16#8e#, 16#ed#, 16#f2#, 16#78#, 16#5e#, 16#42#,
      16#87#, 16#4d#);

   Buf      : Byte_Array (0 .. Plain_Text'Length - 1);
   Original : Byte_Array (0 .. Plain_Text'Length - 1);
   Match    : Boolean := True;
begin
   for I in 0 .. Plain_Text'Length - 1 loop
      Buf (I)      := Byte (Character'Pos (Plain_Text (Plain_Text'First + I)));
      Original (I) := Buf (I);
   end loop;

   --  Encrypt with counter 1 (per the RFC vector).
   XCrypt (Key, Nonce, 1, Buf);
   for I in Buf'Range loop
      if Buf (I) /= Expected (I) then
         Match := False;
      end if;
   end loop;
   Check (Match, "ChaCha20 matches the RFC 8439 test vector");

   --  Decrypt (same operation) restores the plaintext.
   XCrypt (Key, Nonce, 1, Buf);
   Match := True;
   for I in Buf'Range loop
      if Buf (I) /= Original (I) then
         Match := False;
      end if;
   end loop;
   Check (Match, "decrypt is the inverse of encrypt");

   New_Line;
   if Failures = 0 then
      Put_Line ("ALL TESTS PASSED");
   else
      Put_Line ("FAILURES:" & Failures'Image);
      Set_Exit_Status (Failure);
   end if;
end Test_Cipher;
