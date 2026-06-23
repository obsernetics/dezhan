pragma Ada_2022;
with Ada.Text_IO;      use Ada.Text_IO;
with Ada.Command_Line; use Ada.Command_Line;
with Dezhan.Storage.Deflate; use Dezhan.Storage.Deflate;

--  Round-trip and compression-ratio checks for the in-tree DEFLATE.
procedure Test_Deflate is

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

   function Round_Trips (D : Buffer) return Boolean is
   begin
      return Inflate (Deflate (D)) = D;
   end Round_Trips;

   function From_Str (S : String) return Buffer is
      R : Buffer (0 .. S'Length - 1);
   begin
      for I in 0 .. S'Length - 1 loop
         R (I) := Octet (Character'Pos (S (S'First + I)));
      end loop;
      return R;
   end From_Str;

   Empty : constant Buffer (1 .. 0) := (others => 0);
   Rep   : constant Buffer (0 .. 999) := (others => 65);  --  all 'A'
   Pat   : Buffer (0 .. 4095);
   Text  : constant Buffer :=
     From_Str ("the quick brown fox jumps over the lazy dog. " &
               "the quick brown fox jumps over the lazy dog. " &
               "the quick brown fox jumps over the lazy dog.");
begin
   for I in Pat'Range loop
      Pat (I) := Octet ((I * 7 + I / 3) mod 256);
   end loop;

   Check (Round_Trips (Empty), "round-trips empty input");
   Check (Round_Trips (From_Str ("hello, dezhan")), "round-trips a short string");
   Check (Round_Trips (Rep), "round-trips highly repetitive data");
   Check (Round_Trips (Pat), "round-trips patterned data");
   Check (Round_Trips (Text), "round-trips repeated text");

   Check (Deflate (Rep)'Length < Rep'Length / 4,
          "repetitive data compresses to under a quarter");
   Check (Deflate (Text)'Length < Text'Length,
          "repeated text compresses smaller");

   New_Line;
   if Failures = 0 then
      Put_Line ("ALL TESTS PASSED");
   else
      Put_Line ("FAILURES:" & Failures'Image);
      Set_Exit_Status (Failure);
   end if;
end Test_Deflate;
