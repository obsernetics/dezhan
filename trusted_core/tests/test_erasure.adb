pragma Ada_2022;
with Ada.Text_IO;      use Ada.Text_IO;
with Ada.Command_Line; use Ada.Command_Line;
with Interfaces; use Interfaces;
with Dezhan.Trusted_Core.Erasure; use Dezhan.Trusted_Core.Erasure;

--  Validates the Reed-Solomon erasure code. gnatprove proves the unit free of
--  run-time errors; this test validates the reconstruction guarantee by an
--  exhaustive round-trip: for K=4, M=3 (N=7), every erasure pattern that leaves
--  at least K shards present reconstructs the original data exactly.
procedure Test_Erasure is

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

   K : constant := 4;
   M : constant := 3;
   N : constant := K + M;
   L : constant := 16;

   Data   : Data_Block   := (others => (others => 0));
   Parity : Parity_Block;
   Full   : Shard_Block  := (others => (others => 0));

begin
   --  Fill K data shards with a distinct pattern per shard/byte.
   for I in 1 .. K loop
      for B in 1 .. L loop
         Data (I, B) := Symbol ((I * 37 + B * 5) mod 256);
      end loop;
   end loop;

   Encode (K, M, L, Data, Parity);

   --  Assemble the full set of N shards: data then parity.
   for I in 1 .. K loop
      for B in 1 .. L loop
         Full (I, B) := Data (I, B);
      end loop;
   end loop;
   for I in 1 .. M loop
      for B in 1 .. L loop
         Full (K + I, B) := Parity (I, B);
      end loop;
   end loop;

   --  All present: trivial reconstruction returns the data.
   declare
      All_Present : constant Present_Map := (others => True);
      Out_Data    : Data_Block;
      Ok          : Boolean;
      Match       : Boolean := True;
   begin
      Reconstruct (K, M, L, All_Present, Full, Out_Data, Ok);
      for I in 1 .. K loop
         for B in 1 .. L loop
            if Out_Data (I, B) /= Data (I, B) then
               Match := False;
            end if;
         end loop;
      end loop;
      Check (Ok and Match, "reconstruct with all shards present returns the data");
   end;

   --  Exhaustive: every subset of present shards is tested. Whenever at least K
   --  of the N shards are present, reconstruction must succeed and be exact.
   declare
      Total_Tested : Natural := 0;
      All_Good     : Boolean := True;
   begin
      for Mask in 0 .. 2 ** N - 1 loop
         declare
            P     : Present_Map := (others => False);
            Count : Natural := 0;
         begin
            for I in 1 .. N loop
               if (Mask / (2 ** (I - 1))) mod 2 = 1 then
                  P (I) := True;
                  Count := Count + 1;
               end if;
            end loop;

            if Count >= K then
               declare
                  Out_Data : Data_Block;
                  Ok       : Boolean;
               begin
                  Reconstruct (K, M, L, P, Full, Out_Data, Ok);
                  Total_Tested := Total_Tested + 1;
                  if not Ok then
                     All_Good := False;
                  else
                     for I in 1 .. K loop
                        for B in 1 .. L loop
                           if Out_Data (I, B) /= Data (I, B) then
                              All_Good := False;
                           end if;
                        end loop;
                     end loop;
                  end if;
               end;
            end if;
         end;
      end loop;
      Check (All_Good, "every erasure pattern with >= K present reconstructs exactly");
      Put_Line ("       (" & Total_Tested'Image & " erasure patterns verified)");
   end;

   --  Fewer than K shards present: reconstruction reports failure.
   declare
      P        : Present_Map := (others => False);
      Out_Data : Data_Block;
      Ok       : Boolean;
   begin
      P (1) := True;  --  only one shard present, need K=4
      Reconstruct (K, M, L, P, Full, Out_Data, Ok);
      Check (not Ok, "too few shards present is reported as failure");
   end;

   New_Line;
   if Failures = 0 then
      Put_Line ("ALL TESTS PASSED");
   else
      Put_Line ("FAILURES:" & Failures'Image);
      Set_Exit_Status (Failure);
   end if;
end Test_Erasure;
