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

   --  Delete up to N shard files from the first chunk directory found (chunks
   --  are stored as objects/<2hex>/<64hex>/{1..6,idx}). Returns how many were
   --  removed. Two calls remove from the same chunk, so 2 then 2 more drops it
   --  below the K=4 recovery threshold.
   function Delete_N_Shards (N : Positive) return Natural is
      Deleted : Natural := 0;
      L1 : Search_Type;
      E1 : Directory_Entry_Type;
   begin
      Start_Search (L1, Compose (Root, "objects"), "",
                    (Directory => True, others => False));
      while More_Entries (L1) loop
         Get_Next_Entry (L1, E1);
         if Simple_Name (E1) /= "." and then Simple_Name (E1) /= ".." then
            declare
               L2 : Search_Type;
               E2 : Directory_Entry_Type;
            begin
               Start_Search (L2, Full_Name (E1), "",
                             (Directory => True, others => False));
               while More_Entries (L2) loop
                  Get_Next_Entry (L2, E2);
                  if Simple_Name (E2) /= "." and then Simple_Name (E2) /= ".." then
                     for S in 1 .. 6 loop
                        exit when Deleted >= N;
                        declare
                           F : constant String := Compose
                             (Full_Name (E2),
                              (1 => Character'Val (Character'Pos ('0') + S)));
                        begin
                           if Exists (F) then
                              Delete_File (F);
                              Deleted := Deleted + 1;
                           end if;
                        end;
                     end loop;
                     End_Search (L2);
                     End_Search (L1);
                     return Deleted;
                  end if;
               end loop;
               End_Search (L2);
            end;
         end if;
      end loop;
      End_Search (L1);
      return Deleted;
   end Delete_N_Shards;

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

      --  Erasure coding: losing up to M=2 shards of a chunk is recoverable.
      Check (Delete_N_Shards (2) = 2, "removed 2 of 6 shards from a chunk");
      Check (Verify (Root, Id),
             "erasure recovers: object intact after losing 2 shards");
      Check (Equal (Get (Root, Key, Id), Data),
             "object reassembles from parity after losing 2 shards");

      --  Losing more than M shards of a chunk is unrecoverable and detected.
      Check (Delete_N_Shards (2) = 2, "removed 2 more shards (4 of 6 gone)");
      Check (not Verify (Root, Id),
             "verify detects unrecoverable loss (> M shards)");
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
