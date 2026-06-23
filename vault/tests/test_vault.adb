pragma Ada_2022;
with Ada.Text_IO;      use Ada.Text_IO;
with Ada.Command_Line; use Ada.Command_Line;
with Ada.Directories;
with Ada.Streams;      use Ada.Streams;
with Ada.Streams.Stream_IO;
with Dezhan.Trusted_Core.Times;     use Dezhan.Trusted_Core.Times;
with Dezhan.Trusted_Core.Retention; use Dezhan.Trusted_Core.Retention;
with Dezhan.Trusted_Core.Cipher;    use Dezhan.Trusted_Core.Cipher;
with Dezhan.Vault;                  use Dezhan.Vault;

--  End-to-end POC test: the vault enforces WORM via the trusted core. A
--  compliance-locked object cannot be deleted before expiry even with a bypass,
--  a manipulated clock cannot expire it, and every action is recorded in a
--  self-verifying audit chain.
procedure Test_Vault is

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

   Root : constant String  := "/tmp/dezhan_vault_test";
   Key  : constant Key_256 := (others => 7);

   function Bytes (S : String) return Stream_Element_Array is
      R : Stream_Element_Array (1 .. S'Length);
   begin
      for I in 1 .. S'Length loop
         R (Stream_Element_Offset (I)) :=
           Stream_Element (Character'Pos (S (S'First + I - 1)));
      end loop;
      return R;
   end Bytes;

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

   --  Flip a byte in every stored chunk file, simulating bit rot. Corrupts all
   --  chunks (orphaned and live) so any live object is guaranteed affected.
   function Corrupt_All_Chunks return Natural is
      use Ada.Directories;
      Sub     : Search_Type;
      Dir     : Directory_Entry_Type;
      Damaged : Natural := 0;
   begin
      Start_Search (Sub, Compose (Root, "objects"), "",
                    (Directory => True, others => False));
      while More_Entries (Sub) loop
         Get_Next_Entry (Sub, Dir);
         if Simple_Name (Dir) /= "." and then Simple_Name (Dir) /= ".." then
            declare
               Files : Search_Type;
               FE    : Directory_Entry_Type;
            begin
               Start_Search (Files, Full_Name (Dir), "",
                             (Ordinary_File => True, others => False));
               while More_Entries (Files) loop
                  Get_Next_Entry (Files, FE);
                  declare
                     F : Ada.Streams.Stream_IO.File_Type;
                     B : constant Stream_Element_Array (1 .. 1) := (1 => 255);
                  begin
                     Ada.Streams.Stream_IO.Open
                       (F, Ada.Streams.Stream_IO.Out_File, Full_Name (FE));
                     Ada.Streams.Stream_IO.Write (F, B);
                     Ada.Streams.Stream_IO.Close (F);
                     Damaged := Damaged + 1;
                  end;
               end loop;
               End_Search (Files);
            end;
         end if;
      end loop;
      End_Search (Sub);
      return Damaged;
   end Corrupt_All_Chunks;

   V : Vault_Type;

begin
   if Ada.Directories.Exists (Root) then
      Ada.Directories.Delete_Tree (Root);
   end if;
   Open (V, Root, Key);

   --  Advance trusted time to 100 (monotonic 1000 -> 1100, realtime tracks).
   Tick_Clock (V, Mono => 1000, Realtime => 5000, Boot_Changed => False);
   Tick_Clock (V, Mono => 1100, Realtime => 5100, Boot_Changed => False);
   Check (Now (V) = 100, "trusted time advanced to 100");

   --  Store a compliance-locked object retained for 1000 units (expiry 1100).
   declare
      Payload : constant Stream_Element_Array := Bytes ("top secret backup data");
   begin
      Put_Object (V, "backup-1", Payload, Compliance, Retain_For => 1000);
      Check (Contains (V, "backup-1"),          "object stored");
      Check (Equal (Get_Object (V, "backup-1"), Payload),
             "object round-trips through encrypted storage");
   end;

   --  Deletion before expiry is denied, even with a bypass (compliance mode).
   Check (not Delete_Object (V, "backup-1", Bypass => False),
          "compliance object cannot be deleted before expiry");
   Check (not Delete_Object (V, "backup-1", Bypass => True),
          "compliance object cannot be bypass-deleted before expiry");
   Check (Contains (V, "backup-1"), "object still present after denied deletes");

   --  A forward clock attack must not expire the lock. Realtime jumps far ahead,
   --  but trusted time only advances by the monotonic delta.
   Tick_Clock (V, Mono => 1150, Realtime => 9_999_999, Boot_Changed => False);
   Check (Sealed (V), "clock manipulation sealed the vault");
   Check (Now (V) = 150, "trusted time ignored the realtime jump");
   Check (not Delete_Object (V, "backup-1", Bypass => True),
          "object still locked despite the clock attack");

   --  After real (monotonic) time passes the expiry, deletion is allowed.
   Tick_Clock (V, Mono => 2300, Realtime => 9_999_999, Boot_Changed => False);
   Check (Now (V) >= 1100, "monotonic time has passed the retention expiry");
   Check (Delete_Object (V, "backup-1", Bypass => False),
          "object is deletable after genuine expiry");
   Check (not Contains (V, "backup-1"), "object removed after allowed delete");

   --  The audit chain recorded everything and verifies.
   Check (Audit_Length (V) > 1, "audit chain recorded events");
   Check (Audit_Verifies (V), "audit chain verifies (tamper-evident)");

   --  Durability: a new vault opened on the same root recovers the metadata,
   --  audit chain, retention locks, and trusted-time high-water mark.
   Put_Object (V, "persist-me", Bytes ("durable payload"), Compliance,
               Retain_For => 100_000);
   declare
      V2 : Vault_Type;
   begin
      Open (V2, Root, Key);
      Check (Contains (V2, "persist-me"),
             "object survives reopen (durable metadata)");
      Check (Equal (Get_Object (V2, "persist-me"), Bytes ("durable payload")),
             "reopened object round-trips");
      Check (Audit_Verifies (V2),
             "audit chain survives reopen and verifies");
      Check (not Contains (V2, "backup-1"),
             "earlier deletion persisted across reopen");
      Check (not Delete_Object (V2, "persist-me", Bypass => True),
             "retention survives reopen (still locked)");
   end;

   --  Background scrubbing: a clean sweep reports all objects intact; after a
   --  chunk is corrupted on disk, the scrub detects it.
   declare
      Before : constant Scrub_Report := Scrub (V);
   begin
      Check (Before.Total >= 1 and then Before.Corrupt = 0,
             "scrub reports all objects intact");
   end;
   Check (Corrupt_All_Chunks > 0, "stored chunks were corrupted on disk");
   declare
      After : constant Scrub_Report := Scrub (V);
   begin
      Check (After.Corrupt >= 1, "scrub detects the corrupted object");
   end;

   --  Air-gap seal: once the operator seals the vault, writes are refused, and
   --  the seal persists across a reopen.
   Seal (V);
   Check (Sealed (V), "operator seal makes the vault read-only");
   declare
      Raised : Boolean := False;
   begin
      begin
         Put_Object (V, "after-seal", Bytes ("x"), Compliance, Retain_For => 100);
      exception
         when Vault_Sealed => Raised := True;
      end;
      Check (Raised, "writes are refused while sealed");
   end;
   declare
      V3 : Vault_Type;
   begin
      Open (V3, Root, Key);
      Check (Sealed (V3), "seal persists across reopen");
   end;

   New_Line;
   if Failures = 0 then
      Put_Line ("ALL TESTS PASSED");
   else
      Put_Line ("FAILURES:" & Failures'Image);
      Set_Exit_Status (Failure);
   end if;
end Test_Vault;
