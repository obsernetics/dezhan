pragma Ada_2022;
with Ada.Text_IO;      use Ada.Text_IO;
with Ada.Command_Line; use Ada.Command_Line;
with Dezhan.Trusted_Core.Hashing; use Dezhan.Trusted_Core.Hashing;
with Dezhan.Trusted_Core.HMAC;    use Dezhan.Trusted_Core.HMAC;

--  Validates HMAC-SHA256 against RFC 4231 test vectors.
procedure Test_HMAC is

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

   function From_String (S : String) return Byte_Array is
      R : Byte_Array (0 .. S'Length - 1);
   begin
      for I in 0 .. S'Length - 1 loop
         R (I) := Byte (Character'Pos (S (S'First + I)));
      end loop;
      return R;
   end From_String;

   --  RFC 4231 Test Case 2: key="Jefe", data="what do ya want for nothing?"
   D_Case2 : constant Digest :=
     (16#5b#, 16#dc#, 16#c1#, 16#46#, 16#bf#, 16#60#, 16#75#, 16#4e#,
      16#6a#, 16#04#, 16#24#, 16#26#, 16#08#, 16#95#, 16#75#, 16#c7#,
      16#5a#, 16#00#, 16#3f#, 16#08#, 16#9d#, 16#27#, 16#39#, 16#83#,
      16#9d#, 16#ec#, 16#58#, 16#b9#, 16#64#, 16#ec#, 16#38#, 16#43#);

   --  RFC 4231 Test Case 1: key = 20 bytes of 0x0b, data = "Hi There"
   Key1 : constant Byte_Array (0 .. 19) := (others => 16#0b#);
   D_Case1 : constant Digest :=
     (16#b0#, 16#34#, 16#4c#, 16#61#, 16#d8#, 16#db#, 16#38#, 16#53#,
      16#5c#, 16#a8#, 16#af#, 16#ce#, 16#af#, 16#0b#, 16#f1#, 16#2b#,
      16#88#, 16#1d#, 16#c2#, 16#00#, 16#c9#, 16#83#, 16#3d#, 16#a7#,
      16#26#, 16#e9#, 16#37#, 16#6c#, 16#2e#, 16#32#, 16#cf#, 16#f7#);

begin
   Check (HMAC_SHA256 (Key1, From_String ("Hi There")) = D_Case1,
          "HMAC-SHA256 matches RFC 4231 test case 1");
   Check (HMAC_SHA256 (From_String ("Jefe"),
                       From_String ("what do ya want for nothing?")) = D_Case2,
          "HMAC-SHA256 matches RFC 4231 test case 2");

   New_Line;
   if Failures = 0 then
      Put_Line ("ALL TESTS PASSED");
   else
      Put_Line ("FAILURES:" & Failures'Image);
      Set_Exit_Status (Failure);
   end if;
end Test_HMAC;
