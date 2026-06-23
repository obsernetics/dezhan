pragma Ada_2022;
with Interfaces;       use Interfaces;
with Ada.Text_IO;      use Ada.Text_IO;
with Ada.Command_Line; use Ada.Command_Line;
with Dezhan.Trusted_Core.Cipher; use Dezhan.Trusted_Core.Cipher;
with Dezhan.Keystore;            use Dezhan.Keystore;

--  Wrap/unwrap round-trip and rejection of a wrong KEK or a tampered tag.
procedure Test_Keystore is

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

   function Eq (A, B : Key_256) return Boolean is
   begin
      for I in A'Range loop
         if A (I) /= B (I) then
            return False;
         end if;
      end loop;
      return True;
   end Eq;

   KEK   : constant Key_256 := (others => 7);
   Other : constant Key_256 := (others => 9);
   Nonce : constant Nonce_96 := (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12);
   DEK   : constant Key_256 :=
     (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
      17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32);

   W   : constant Wrapped_Key := Wrap (KEK, Nonce, DEK);
   Got : Key_256;
   Ok  : Boolean;
begin
   --  The wrapped form must not expose the DEK in the clear.
   Check (not Eq (W.Cipher, DEK), "wrapped key is not the plaintext DEK");

   Unwrap (KEK, W, Got, Ok);
   Check (Ok and then Eq (Got, DEK), "unwrap with the right KEK recovers the DEK");

   Unwrap (Other, W, Got, Ok);
   Check (not Ok, "unwrap with a wrong KEK is rejected (wrong passphrase)");

   declare
      T : Wrapped_Key := W;
   begin
      T.Tag (0) := T.Tag (0) xor 1;   --  flip one tag bit
      Unwrap (KEK, T, Got, Ok);
      Check (not Ok, "a tampered wrapped key is rejected");
   end;

   New_Line;
   if Failures = 0 then
      Put_Line ("ALL TESTS PASSED");
   else
      Put_Line ("FAILURES:" & Failures'Image);
      Set_Exit_Status (Failure);
   end if;
end Test_Keystore;
