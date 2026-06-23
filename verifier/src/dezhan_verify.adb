pragma Ada_2022;
--  Independent audit-chain verifier (SPEC: Audit Chain -> "Independent
--  verification tool"). Reads <root>/vault.state, reconstructs the append-only
--  audit log from its serialized form, and re-checks it with the SPARK-proven
--  Verify_Chain. It shares no code with the vault's writer, so it confirms the
--  chain's tamper-evidence from the outside: a flipped field, a forged hash, or
--  a re-linked entry all fail. Exit status is 0 on a valid chain, 1 otherwise.
with Ada.Text_IO;                 use Ada.Text_IO;
with Ada.Command_Line;            use Ada.Command_Line;
with Ada.Directories;
with Ada.Containers.Vectors;
with Dezhan.Trusted_Core.Times;   use Dezhan.Trusted_Core.Times;
with Dezhan.Trusted_Core.Hashing; use Dezhan.Trusted_Core.Hashing;
with Dezhan.Trusted_Core.Audit;   use Dezhan.Trusted_Core.Audit;

procedure Dezhan_Verify is

   --  N-th whitespace-separated field of Line ("" if absent).
   function Field (Line : String; N : Positive) return String is
      I     : Natural := Line'First;
      Count : Natural := 0;
   begin
      while I <= Line'Last loop
         while I <= Line'Last and then Line (I) = ' ' loop
            I := I + 1;
         end loop;
         exit when I > Line'Last;
         declare
            Start : constant Natural := I;
         begin
            while I <= Line'Last and then Line (I) /= ' ' loop
               I := I + 1;
            end loop;
            Count := Count + 1;
            if Count = N then
               return Line (Start .. I - 1);
            end if;
         end;
      end loop;
      return "";
   end Field;

   function Nibble (C : Character) return Natural is
     (case C is
         when '0' .. '9' => Character'Pos (C) - Character'Pos ('0'),
         when 'a' .. 'f' => Character'Pos (C) - Character'Pos ('a') + 10,
         when 'A' .. 'F' => Character'Pos (C) - Character'Pos ('A') + 10,
         when others     => 0);

   function From_Hex (S : String) return Digest is
      D : Digest := (others => 0);
   begin
      if S'Length < 64 then
         return D;
      end if;
      for I in 0 .. 31 loop
         D (I) := Byte (Nibble (S (S'First + I * 2)) * 16
                        + Nibble (S (S'First + I * 2 + 1)));
      end loop;
      return D;
   end From_Hex;

   package Entry_Vec is new Ada.Containers.Vectors (Natural, Audit_Entry);

begin
   if Argument_Count < 1 then
      Put_Line ("usage: dezhan_verify <vault-root>");
      Set_Exit_Status (Failure);
      return;
   end if;

   declare
      Root  : constant String := Argument (1);
      Path  : constant String := Ada.Directories.Compose (Root, "vault.state");
      F     : File_Type;
      Items : Entry_Vec.Vector;
   begin
      if not Ada.Directories.Exists (Path) then
         Put_Line ("no vault.state under " & Root);
         Set_Exit_Status (Failure);
         return;
      end if;

      Open (F, In_File, Path);
      while not End_Of_File (F) loop
         declare
            Line : constant String := Get_Line (F);
         begin
            if Field (Line, 1) = "A" then
               declare
                  E : Audit_Entry;
               begin
                  E.Seq       := Natural'Value (Field (Line, 2));
                  E.Time      := Trusted_Time'Value (Field (Line, 3));
                  E.Kind      :=
                    Audit_Event'Val (Integer'Value (Field (Line, 4)));
                  E.Subject   := From_Hex (Field (Line, 5));
                  E.Detail    := Trusted_Time'Value (Field (Line, 6));
                  E.Prev_Hash := From_Hex (Field (Line, 7));
                  E.Hash      := From_Hex (Field (Line, 8));
                  Items.Append (E);
               end;
            end if;
         end;
      end loop;
      Close (F);

      declare
         N : constant Natural := Natural (Items.Length);
      begin
         if N = 0 then
            Put_Line ("audit chain is empty (no entries found)");
            Set_Exit_Status (Failure);
            return;
         end if;
         declare
            C : Chain (0 .. N - 1);
         begin
            for I in 0 .. N - 1 loop
               C (I) := Items (I);
            end loop;
            if Verify_Chain (C) then
               Put_Line ("audit chain OK:" & Natural'Image (N)
                         & " entries verified (tamper-evident)");
            else
               Put_Line ("audit chain FAILED: tamper or corruption detected");
               Set_Exit_Status (Failure);
            end if;
         end;
      end;
   end;
end Dezhan_Verify;
