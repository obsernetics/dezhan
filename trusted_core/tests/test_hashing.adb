pragma Ada_2022;
with Ada.Text_IO;      use Ada.Text_IO;
with Ada.Command_Line; use Ada.Command_Line;
with Dezhan.Trusted_Core.Hashing; use Dezhan.Trusted_Core.Hashing;

--  Validates the in-tree SHA-256 against NIST test vectors. gnatprove proves the
--  implementation free of run-time errors; these vectors confirm it computes the
--  correct function.
procedure Test_Hashing is

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

   Empty : constant Byte_Array (0 .. -1) := (others => 0);

   --  SHA256("") = e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855
   D_Empty : constant Digest :=
     (16#e3#, 16#b0#, 16#c4#, 16#42#, 16#98#, 16#fc#, 16#1c#, 16#14#,
      16#9a#, 16#fb#, 16#f4#, 16#c8#, 16#99#, 16#6f#, 16#b9#, 16#24#,
      16#27#, 16#ae#, 16#41#, 16#e4#, 16#64#, 16#9b#, 16#93#, 16#4c#,
      16#a4#, 16#95#, 16#99#, 16#1b#, 16#78#, 16#52#, 16#b8#, 16#55#);

   --  SHA256("abc") = ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad
   D_Abc : constant Digest :=
     (16#ba#, 16#78#, 16#16#, 16#bf#, 16#8f#, 16#01#, 16#cf#, 16#ea#,
      16#41#, 16#41#, 16#40#, 16#de#, 16#5d#, 16#ae#, 16#22#, 16#23#,
      16#b0#, 16#03#, 16#61#, 16#a3#, 16#96#, 16#17#, 16#7a#, 16#9c#,
      16#b4#, 16#10#, 16#ff#, 16#61#, 16#f2#, 16#00#, 16#15#, 16#ad#);

   --  SHA256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
   --  = 248d6a61 d20638b8 e5c02693 0c3e6039 a33ce459 64ff2167 f6ecedd4 19db06c1
   D_Long : constant Digest :=
     (16#24#, 16#8d#, 16#6a#, 16#61#, 16#d2#, 16#06#, 16#38#, 16#b8#,
      16#e5#, 16#c0#, 16#26#, 16#93#, 16#0c#, 16#3e#, 16#60#, 16#39#,
      16#a3#, 16#3c#, 16#e4#, 16#59#, 16#64#, 16#ff#, 16#21#, 16#67#,
      16#f6#, 16#ec#, 16#ed#, 16#d4#, 16#19#, 16#db#, 16#06#, 16#c1#);

begin
   Check (SHA256 (Empty) = D_Empty, "SHA256 of empty string matches NIST vector");
   Check (SHA256 (From_String ("abc")) = D_Abc, "SHA256 of ""abc"" matches NIST vector");
   Check (SHA256 (From_String
            ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")) = D_Long,
          "SHA256 of 56-byte message matches NIST vector");
   Check (SHA256 (From_String ("abc")) /= SHA256 (From_String ("abd")),
          "different inputs produce different digests");

   New_Line;
   if Failures = 0 then
      Put_Line ("ALL TESTS PASSED");
   else
      Put_Line ("FAILURES:" & Failures'Image);
      Set_Exit_Status (Failure);
   end if;
end Test_Hashing;
