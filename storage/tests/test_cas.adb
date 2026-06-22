pragma Ada_2022;
with Ada.Text_IO;           use Ada.Text_IO;
with Ada.Command_Line;      use Ada.Command_Line;
with Ada.Streams;           use Ada.Streams;
with Ada.Streams.Stream_IO;
with Ada.Directories;       use Ada.Directories;
with Dezhan.Trusted_Core.Cipher; use Dezhan.Trusted_Core.Cipher;
with Dezhan.Storage.Cas;    use Dezhan.Storage.Cas;

--  Exercises the content-addressed store: round-trip, deduplication (stable
--  id), integrity verification, and corruption detection.
procedure Test_Cas is

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

   Root : constant String := "/tmp/dezhan_cas_test";

   function Equal (A, B : Stream_Element_Array) return Boolean is
   begin
      if A'Length /= B'Length then
         return False;
      end if;
      for I in A'Range loop
         if A (I) /= B (B'First + (I - A'First)) then
            return False;
         end if;
      end loop;
      return True;
   end Equal;

   --  Overwrite the first byte of the first stored chunk file, simulating
   --  silent media corruption. Returns True if a chunk was corrupted.
   function Corrupt_A_Chunk return Boolean is
      Sub : Search_Type;
      Dir : Directory_Entry_Type;
   begin
      Start_Search (Sub, Compose (Root, "objects"), "",
                    (Directory => True, others => False));
      while More_Entries (Sub) loop
         Get_Next_Entry (Sub, Dir);
         if Simple_Name (Dir) /= "." and then Simple_Name (Dir) /= ".." then
            declare
               Files : Search_Type;
               F_Ent : Directory_Entry_Type;
            begin
               Start_Search (Files, Full_Name (Dir), "",
                             (Ordinary_File => True, others => False));
               if More_Entries (Files) then
                  Get_Next_Entry (Files, F_Ent);
                  declare
                     F : Ada.Streams.Stream_IO.File_Type;
                     B : constant Stream_Element_Array (1 .. 1) := (1 => 255);
                  begin
                     Ada.Streams.Stream_IO.Open
                       (F, Ada.Streams.Stream_IO.Out_File, Full_Name (F_Ent));
                     Ada.Streams.Stream_IO.Write (F, B);
                     Ada.Streams.Stream_IO.Close (F);
                  end;
                  End_Search (Files);
                  End_Search (Sub);
                  return True;
               end if;
               End_Search (Files);
            end;
         end if;
      end loop;
      End_Search (Sub);
      return False;
   end Corrupt_A_Chunk;

   Key : constant Key_256 :=
     (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
      17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32);
   Wrong_Key : constant Key_256 := (others => 99);

   Data : Stream_Element_Array (1 .. 10_000);   --  spans three 4096-byte chunks

begin
   if Exists (Root) then
      Delete_Tree (Root);
   end if;
   Initialize (Root);

   for I in Data'Range loop
      Data (I) := Stream_Element ((Integer (I) * 7) mod 256);
   end loop;

   declare
      Id    : constant Object_Id := Put (Root, Key, Data);
      Back  : constant Stream_Element_Array := Get (Root, Key, Id);
      Wrong : constant Stream_Element_Array := Get (Root, Wrong_Key, Id);
   begin
      Check (Equal (Back, Data), "round-trip with the right key returns the original");
      Check (not Equal (Wrong, Data), "wrong key does not recover the data (encrypted at rest)");
      Check (Verify (Root, Id), "verify reports the object intact");
      Check (Put (Root, Key, Data) = Id, "same bytes and key yield the same id");

      Check (Corrupt_A_Chunk, "a stored chunk was found to corrupt");
      Check (not Verify (Root, Id), "verify detects the corrupted chunk");
   end;

   --  Empty object round-trips.
   declare
      Empty : constant Stream_Element_Array (1 .. 0) := (others => 0);
      Id    : constant Object_Id := Put (Root, Key, Empty);
      Back  : constant Stream_Element_Array := Get (Root, Key, Id);
   begin
      Check (Back'Length = 0, "empty object round-trips");
   end;

   New_Line;
   if Failures = 0 then
      Put_Line ("ALL TESTS PASSED");
   else
      Put_Line ("FAILURES:" & Failures'Image);
      Set_Exit_Status (Failure);
   end if;
end Test_Cas;
