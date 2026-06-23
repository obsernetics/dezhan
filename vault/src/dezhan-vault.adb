with Ada.Strings.Unbounded;            use Ada.Strings.Unbounded;
with Ada.Strings.Hash;
with Ada.Text_IO;                       use Ada.Text_IO;
with Ada.Directories;                   use Ada.Directories;
with Ada.Containers.Indefinite_Hashed_Maps;
with Ada.Containers.Vectors;
with Dezhan.Trusted_Core.Hashing;       use Dezhan.Trusted_Core.Hashing;
with Dezhan.Trusted_Core.Clock_Guard;
with Dezhan.Trusted_Core.Audit;         use Dezhan.Trusted_Core.Audit;
with Dezhan.Storage.Cas;                use Dezhan.Storage.Cas;
with Dezhan.Platform.Clock;

package body Dezhan.Vault with SPARK_Mode => Off is

   package CG renames Dezhan.Trusted_Core.Clock_Guard;

   Clock_Tolerance : constant Trusted_Time := 2;

   type Meta is record
      Id   : Object_Id;
      Lock : Retention_Lock;
   end record;

   package Meta_Maps is new Ada.Containers.Indefinite_Hashed_Maps
     (Key_Type => String, Element_Type => Meta,
      Hash => Ada.Strings.Hash, Equivalent_Keys => "=");

   package Log_Vectors is new Ada.Containers.Vectors
     (Index_Type => Natural, Element_Type => Audit_Entry);

   type State is record
      Root      : Unbounded_String;
      Key       : Key_256;
      Clock     : CG.Guard_State;
      Started   : Boolean := False; --  clock baseline taken from the first tick
      Op_Sealed : Boolean := False; --  operator-initiated read-only seal
      Index     : Meta_Maps.Map;
      Log       : Log_Vectors.Vector;
   end record;

   --  Writes are refused only by an operator seal (air-gap read-only). A clock
   --  anomaly is a separate alarm (surfaced by Sealed/metrics): it does not by
   --  itself freeze the vault, because the retention guarantee already holds
   --  (trusted time never advanced), and freezing on every clock blip would be
   --  too aggressive.
   function Read_Only (V : Vault_Type) return Boolean is (V.Self.Op_Sealed);

   function Name_Digest (Name : String) return Digest is
      B : Byte_Array (0 .. Name'Length - 1);
   begin
      for I in 0 .. Name'Length - 1 loop
         B (I) := Byte (Character'Pos (Name (Name'First + I)));
      end loop;
      return SHA256 (B);
   end Name_Digest;

   procedure Add_Audit
     (V       : in out Vault_Type;
      Kind    : Audit_Event;
      Subject : Digest;
      Detail  : Trusted_Time)
   is
      Last : constant Audit_Entry := V.Self.Log.Last_Element;
   begin
      V.Self.Log.Append
        (Append (Last, CG.Now (V.Self.Clock), Kind, Subject, Detail));
   end Add_Audit;

   --  ---- Durable persistence (text snapshot, atomically replaced) ----

   Hex_Digits : constant String := "0123456789abcdef";

   function State_Path (V : Vault_Type) return String is
     (Compose (To_String (V.Self.Root), "vault.state"));

   function To_Hex (D : Digest) return String is
      R : String (1 .. 64);
   begin
      for I in 0 .. 31 loop
         R (I * 2 + 1) := Hex_Digits (Integer (D (I)) / 16 + 1);
         R (I * 2 + 2) := Hex_Digits (Integer (D (I)) mod 16 + 1);
      end loop;
      return R;
   end To_Hex;

   function Nibble (C : Character) return Natural is
     (if C in '0' .. '9' then Character'Pos (C) - Character'Pos ('0')
      else Character'Pos (C) - Character'Pos ('a') + 10);

   function From_Hex (S : String) return Digest is
      D : Digest := (others => 0);
   begin
      for I in 0 .. 31 loop
         D (I) := Byte (Nibble (S (S'First + I * 2)) * 16
                        + Nibble (S (S'First + I * 2 + 1)));
      end loop;
      return D;
   end From_Hex;

   function Str_To_Hex (S : String) return String is
      R : String (1 .. S'Length * 2);
   begin
      for I in 0 .. S'Length - 1 loop
         declare
            B : constant Natural := Character'Pos (S (S'First + I));
         begin
            R (I * 2 + 1) := Hex_Digits (B / 16 + 1);
            R (I * 2 + 2) := Hex_Digits (B mod 16 + 1);
         end;
      end loop;
      return R;
   end Str_To_Hex;

   function Hex_To_Str (H : String) return String is
      R : String (1 .. H'Length / 2);
   begin
      for I in 0 .. R'Length - 1 loop
         R (I + 1) := Character'Val
           (Nibble (H (H'First + I * 2)) * 16 + Nibble (H (H'First + I * 2 + 1)));
      end loop;
      return R;
   end Hex_To_Str;

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

   procedure Save (V : Vault_Type) is
      Tmp : constant String := State_Path (V) & ".tmp";
      F   : File_Type;
   begin
      Create (F, Out_File, Tmp);
      Put_Line (F, "DEZHAN_VAULT 1");
      Put_Line (F, "CLOCK " & Trusted_Time'Image (CG.Now (V.Self.Clock))
                   & (if CG.Is_Sealed (V.Self.Clock) then " 1" else " 0")
                   & (if V.Self.Op_Sealed then " 1" else " 0"));
      for Cur in V.Self.Index.Iterate loop
         declare
            Name : constant String := Meta_Maps.Key (Cur);
            M    : constant Meta    := Meta_Maps.Element (Cur);
         begin
            Put_Line (F, "OBJ " & Str_To_Hex (Name) & " " & String (M.Id)
                         & Lock_Mode'Pos (M.Lock.Mode)'Image
                         & M.Lock.Retain_Until'Image
                         & M.Lock.Created_At'Image);
         end;
      end loop;
      Put_Line (F, "AUDIT" & Natural'Image (Natural (V.Self.Log.Length)));
      for I in 0 .. Natural (V.Self.Log.Length) - 1 loop
         declare
            E : constant Audit_Entry := V.Self.Log.Element (I);
         begin
            Put_Line (F, "A" & E.Seq'Image & E.Time'Image
                         & Audit_Event'Pos (E.Kind)'Image
                         & " " & To_Hex (E.Subject) & E.Detail'Image
                         & " " & To_Hex (E.Prev_Hash)
                         & " " & To_Hex (E.Hash));
         end;
      end loop;
      Close (F);
      if Exists (State_Path (V)) then
         Delete_File (State_Path (V));
      end if;
      Rename (Tmp, State_Path (V));
   end Save;

   procedure Load (V : in out Vault_Type) is
      F : File_Type;
   begin
      Open (F, In_File, State_Path (V));
      while not End_Of_File (F) loop
         declare
            Line : constant String := Get_Line (F);
            Tag  : constant String := Field (Line, 1);
         begin
            if Tag = "CLOCK" then
               V.Self.Clock :=
                 (Floor     => Trusted_Time'Value (Field (Line, 2)),
                  Last_Mono => 0,
                  Last_Real => 0,
                  Anomaly   => CG.None,
                  Sealed    => Field (Line, 3) = "1");
               V.Self.Op_Sealed := Field (Line, 4) = "1";
               V.Self.Started := False;  --  re-baseline monotonic on next tick
            elsif Tag = "OBJ" then
               V.Self.Index.Include
                 (Hex_To_Str (Field (Line, 2)),
                  (Id   => Object_Id (Field (Line, 3)),
                   Lock =>
                     (Mode         =>
                        Lock_Mode'Val (Integer'Value (Field (Line, 4))),
                      Retain_Until => Trusted_Time'Value (Field (Line, 5)),
                      Created_At   => Trusted_Time'Value (Field (Line, 6)))));
            elsif Tag = "A" then
               V.Self.Log.Append
                 (Audit_Entry'
                    (Seq       => Natural'Value (Field (Line, 2)),
                     Time      => Trusted_Time'Value (Field (Line, 3)),
                     Kind      =>
                       Audit_Event'Val (Integer'Value (Field (Line, 4))),
                     Subject   => From_Hex (Field (Line, 5)),
                     Detail    => Trusted_Time'Value (Field (Line, 6)),
                     Prev_Hash => From_Hex (Field (Line, 7)),
                     Hash      => From_Hex (Field (Line, 8))));
            end if;
         end;
      end loop;
      Close (F);
   end Load;

   procedure Open (V : out Vault_Type; Root : String; Key : Key_256) is
   begin
      V.Self := new State;
      V.Self.Root := To_Unbounded_String (Root);
      V.Self.Key  := Key;
      Initialize (Root);
      if Exists (Compose (Root, "vault.state")) then
         Load (V);
      else
         V.Self.Clock :=
           CG.Init ((Mono => 0, Realtime => 0, Boot_Changed => False));
         V.Self.Log.Append (Genesis_Entry (Time => 0));
      end if;
   end Open;

   procedure Put_Object
     (V          : in out Vault_Type;
      Name       : String;
      Data       : Stream_Element_Array;
      Mode       : Lock_Mode;
      Retain_For : Trusted_Time)
   is
   begin
      if Read_Only (V) then
         raise Vault_Sealed;
      end if;
      if Mode = Unlocked then
         raise Invalid_Mode;
      end if;
      declare
         At_Time : constant Trusted_Time := CG.Now (V.Self.Clock);
         Id      : constant Object_Id :=
           Put (To_String (V.Self.Root), V.Self.Key, Data);
         Lock    : constant Retention_Lock :=
           Create_Lock (Mode, At_Time + Retain_For, At_Time);
      begin
         V.Self.Index.Include (Name, (Id => Id, Lock => Lock));
         Add_Audit (V, Lock_Created, Name_Digest (Name), At_Time + Retain_For);
         Save (V);
      end;
   end Put_Object;

   function Get_Object (V : Vault_Type; Name : String) return Stream_Element_Array is
   begin
      if not V.Self.Index.Contains (Name) then
         raise Not_Found;
      end if;
      return Get (To_String (V.Self.Root), V.Self.Key, V.Self.Index.Element (Name).Id);
   end Get_Object;

   function Contains (V : Vault_Type; Name : String) return Boolean is
     (V.Self.Index.Contains (Name));

   function Object_Count (V : Vault_Type) return Natural is
     (Natural (V.Self.Index.Length));

   function Object_Names (V : Vault_Type) return String is
      R : Unbounded_String;
   begin
      for Cur in V.Self.Index.Iterate loop
         Append (R, Meta_Maps.Key (Cur));
         Append (R, ASCII.LF);
      end loop;
      return To_String (R);
   end Object_Names;

   function Scrub (V : Vault_Type) return Scrub_Report is
      R : Scrub_Report;
   begin
      for Cur in V.Self.Index.Iterate loop
         R.Total := R.Total + 1;
         if Verify (To_String (V.Self.Root), Meta_Maps.Element (Cur).Id) then
            R.Intact := R.Intact + 1;
         else
            R.Corrupt := R.Corrupt + 1;
         end if;
      end loop;
      return R;
   end Scrub;

   function Delete_Object
     (V : in out Vault_Type; Name : String; Bypass : Boolean) return Boolean
   is
   begin
      if Read_Only (V) then
         raise Vault_Sealed;
      end if;
      if not V.Self.Index.Contains (Name) then
         raise Not_Found;
      end if;
      declare
         M       : constant Meta := V.Self.Index.Element (Name);
         At_Time : constant Trusted_Time := CG.Now (V.Self.Clock);
         Auth    : constant Authorization := (Bypass_Governance => Bypass);
      begin
         if Can_Delete (M.Lock, At_Time, Auth) then
            V.Self.Index.Delete (Name);
            Add_Audit (V, Delete_Allowed, Name_Digest (Name), At_Time);
            Save (V);
            return True;
         else
            Add_Audit (V, Delete_Denied, Name_Digest (Name), At_Time);
            Save (V);
            return False;
         end if;
      end;
   end Delete_Object;

   procedure Tick_Clock
     (V            : in out Vault_Type;
      Mono         : Trusted_Time;
      Realtime     : Trusted_Time;
      Boot_Changed : Boolean)
   is
      Sample : constant CG.Clock_Sample :=
        (Mono => Mono, Realtime => Realtime, Boot_Changed => Boot_Changed);
   begin
      if not V.Self.Started then
         --  First reading sets the baseline; no elapsed time yet.
         V.Self.Clock := CG.Init (Sample);
         V.Self.Started := True;
         return;
      end if;

      declare
         Before : constant Boolean := CG.Is_Sealed (V.Self.Clock);
      begin
         V.Self.Clock := CG.Tick (V.Self.Clock, Sample, Clock_Tolerance);
         if CG.Is_Sealed (V.Self.Clock) and then not Before then
            Add_Audit (V, Seal_Engaged, (others => 0), CG.Now (V.Self.Clock));
            Save (V);
         end if;
      end;
   end Tick_Clock;

   procedure Tick_From_System (V : in out Vault_Type) is
      Sample : constant CG.Clock_Sample := Dezhan.Platform.Clock.Sample;
   begin
      Tick_Clock (V, Sample.Mono, Sample.Realtime, Sample.Boot_Changed);
   end Tick_From_System;

   procedure Seal (V : in out Vault_Type) is
   begin
      if not V.Self.Op_Sealed then
         V.Self.Op_Sealed := True;
         Add_Audit (V, Seal_Engaged, (others => 0), CG.Now (V.Self.Clock));
         Save (V);
      end if;
   end Seal;

   function Now (V : Vault_Type) return Trusted_Time is
     (CG.Now (V.Self.Clock));

   function Sealed (V : Vault_Type) return Boolean is
     (V.Self.Op_Sealed or else CG.Is_Sealed (V.Self.Clock));

   function Audit_Length (V : Vault_Type) return Natural is
     (Natural (V.Self.Log.Length));

   function Audit_Verifies (V : Vault_Type) return Boolean is
      N : constant Natural := Natural (V.Self.Log.Length);
      C : Chain (0 .. N - 1);
   begin
      for I in 0 .. N - 1 loop
         C (I) := V.Self.Log.Element (I);
      end loop;
      return Verify_Chain (C);
   end Audit_Verifies;

end Dezhan.Vault;
