with Ada.Strings;                      use Ada.Strings;
with Ada.Strings.Fixed;                use Ada.Strings.Fixed;
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

   package CG  renames Dezhan.Trusted_Core.Clock_Guard;
   package Cas renames Dezhan.Storage.Cas;

   Clock_Tolerance : constant Trusted_Time := 2;

   type Meta is record
      Id        : Object_Id;
      Lock      : Retention_Lock;
      Composite : Boolean := False;  --  Id points to a list of part ids
   end record;

   package Meta_Maps is new Ada.Containers.Indefinite_Hashed_Maps
     (Key_Type => String, Element_Type => Meta,
      Hash => Ada.Strings.Hash, Equivalent_Keys => "=");

   package Log_Vectors is new Ada.Containers.Vectors
     (Index_Type => Natural, Element_Type => Audit_Entry);

   package Id_Vectors is new Ada.Containers.Vectors
     (Index_Type => Natural, Element_Type => Object_Id);

   type Upload is record
      Name       : Unbounded_String;
      Mode       : Lock_Mode := Compliance;
      Retain_For : Trusted_Time := 0;
      Parts      : Id_Vectors.Vector;
   end record;

   package Upload_Maps is new Ada.Containers.Indefinite_Hashed_Maps
     (Key_Type => String, Element_Type => Upload,
      Hash => Ada.Strings.Hash, Equivalent_Keys => "=");

   type State is record
      Root       : Unbounded_String;
      Key        : Key_256;
      Clock      : CG.Guard_State;
      Started    : Boolean := False; --  clock baseline taken from the first tick
      Op_Sealed  : Boolean := False; --  operator-initiated read-only seal
      Last_Boot  : Unbounded_String := Null_Unbounded_String;  --  kernel boot id
      Ingest_Only : Boolean := False;  --  one-way ingest: reads blocked
      Sync_Shut   : Boolean := False;  --  sync window closed: writes blocked
      Index      : Meta_Maps.Map;
      Log        : Log_Vectors.Vector;
      Uploads    : Upload_Maps.Map;  --  in-flight multipart uploads (transient)
      Upload_Seq : Natural := 0;
   end record;

   --  Writes are refused only by an operator seal (air-gap read-only). A clock
   --  anomaly is a separate alarm (surfaced by Sealed/metrics): it does not by
   --  itself freeze the vault, because the retention guarantee already holds
   --  (trusted time never advanced), and freezing on every clock blip would be
   --  too aggressive.
   function Read_Only (V : Vault_Type) return Boolean is (V.Self.Op_Sealed);

   --  Guard for ingest (store/upload): blocked by an operator seal or a closed
   --  sync window.
   procedure Check_Ingest (V : Vault_Type) is
   begin
      if V.Self.Op_Sealed then
         raise Vault_Sealed;
      end if;
      if V.Self.Sync_Shut then
         raise Sync_Closed;
      end if;
   end Check_Ingest;

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
      Put_Line (F, "BOOT " & To_String (V.Self.Last_Boot));
      Put_Line (F, "MODES " & (if V.Self.Ingest_Only then "1" else "0")
                   & " " & (if V.Self.Sync_Shut then "1" else "0"));
      for Cur in V.Self.Index.Iterate loop
         declare
            Name : constant String := Meta_Maps.Key (Cur);
            M    : constant Meta    := Meta_Maps.Element (Cur);
         begin
            Put_Line (F, "OBJ " & Str_To_Hex (Name) & " " & String (M.Id)
                         & Lock_Mode'Pos (M.Lock.Mode)'Image
                         & M.Lock.Retain_Until'Image
                         & M.Lock.Created_At'Image
                         & (if M.Composite then " 1" else " 0")
                         & (if M.Lock.Legal_Hold then " 1" else " 0"));
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
            elsif Tag = "BOOT" then
               V.Self.Last_Boot := To_Unbounded_String (Field (Line, 2));
            elsif Tag = "MODES" then
               V.Self.Ingest_Only := Field (Line, 2) = "1";
               V.Self.Sync_Shut   := Field (Line, 3) = "1";
            elsif Tag = "OBJ" then
               V.Self.Index.Include
                 (Hex_To_Str (Field (Line, 2)),
                  (Id   => Object_Id (Field (Line, 3)),
                   Lock =>
                     (Mode         =>
                        Lock_Mode'Val (Integer'Value (Field (Line, 4))),
                      Retain_Until => Trusted_Time'Value (Field (Line, 5)),
                      Created_At   => Trusted_Time'Value (Field (Line, 6)),
                      Legal_Hold   => Field (Line, 8) = "1"),
                   Composite => Field (Line, 7) = "1"));
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
      Check_Ingest (V);
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
         V.Self.Index.Include (Name, (Id => Id, Lock => Lock, Composite => False));
         Add_Audit (V, Lock_Created, Name_Digest (Name), At_Time + Retain_For);
         Save (V);
      end;
   end Put_Object;

   function Get_Object (V : Vault_Type; Name : String) return Stream_Element_Array is
      Root : constant String := To_String (V.Self.Root);
   begin
      if V.Self.Ingest_Only then
         raise Egress_Denied;
      end if;
      if not V.Self.Index.Contains (Name) then
         raise Not_Found;
      end if;
      declare
         M : constant Meta := V.Self.Index.Element (Name);
      begin
         if not M.Composite then
            return Get (Root, V.Self.Key, M.Id);
         end if;
         --  Composite: M.Id is a list of 64-char part ids; fetch and join them.
         declare
            List : constant Stream_Element_Array := Get (Root, V.Self.Key, M.Id);
            N    : constant Natural := Natural (List'Length) / 64;
            Acc  : Unbounded_String;
         begin
            for P in 0 .. N - 1 loop
               declare
                  Pid : Object_Id;
               begin
                  for I in 0 .. 63 loop
                     Pid (Pid'First + I) :=
                       Character'Val (Natural
                         (List (List'First + Stream_Element_Offset (P * 64 + I))));
                  end loop;
                  declare
                     Part : constant Stream_Element_Array :=
                       Get (Root, V.Self.Key, Pid);
                  begin
                     for B in Part'Range loop
                        Append (Acc, Character'Val (Natural (Part (B))));
                     end loop;
                  end;
               end;
            end loop;
            declare
               R : Stream_Element_Array (1 .. Stream_Element_Offset (Length (Acc)));
            begin
               for I in 1 .. Length (Acc) loop
                  R (Stream_Element_Offset (I)) :=
                    Stream_Element (Character'Pos (Element (Acc, I)));
               end loop;
               return R;
            end;
         end;
      end;
   end Get_Object;

   function Create_Upload
     (V          : in out Vault_Type;
      Name       : String;
      Mode       : Lock_Mode;
      Retain_For : Trusted_Time) return String
   is
   begin
      Check_Ingest (V);
      if Mode = Unlocked then
         raise Invalid_Mode;
      end if;
      V.Self.Upload_Seq := V.Self.Upload_Seq + 1;
      declare
         Id : constant String :=
           "upload-" & Trim (V.Self.Upload_Seq'Image, Ada.Strings.Both);
      begin
         V.Self.Uploads.Include
           (Id, (Name       => To_Unbounded_String (Name),
                 Mode       => Mode,
                 Retain_For => Retain_For,
                 Parts      => Id_Vectors.Empty_Vector));
         return Id;
      end;
   end Create_Upload;

   procedure Upload_Part
     (V : in out Vault_Type; Upload_Id : String; Data : Stream_Element_Array)
   is
   begin
      Check_Ingest (V);
      if not V.Self.Uploads.Contains (Upload_Id) then
         raise No_Such_Upload;
      end if;
      declare
         U   : Upload := V.Self.Uploads.Element (Upload_Id);
         Pid : constant Object_Id :=
           Put (To_String (V.Self.Root), V.Self.Key, Data);
      begin
         U.Parts.Append (Pid);
         V.Self.Uploads.Replace (Upload_Id, U);
      end;
   end Upload_Part;

   procedure Complete_Upload (V : in out Vault_Type; Upload_Id : String) is
   begin
      Check_Ingest (V);
      if not V.Self.Uploads.Contains (Upload_Id) then
         raise No_Such_Upload;
      end if;
      declare
         U       : constant Upload := V.Self.Uploads.Element (Upload_Id);
         Name    : constant String := To_String (U.Name);
         At_Time : constant Trusted_Time := CG.Now (V.Self.Clock);
         List    : Stream_Element_Array
                     (1 .. Stream_Element_Offset (Natural (U.Parts.Length) * 64));
         Pos     : Stream_Element_Offset := 1;
      begin
         for P of U.Parts loop
            for I in 1 .. 64 loop
               List (Pos) := Stream_Element (Character'Pos (P (P'First + I - 1)));
               Pos := Pos + 1;
            end loop;
         end loop;
         declare
            List_Id : constant Object_Id :=
              Put (To_String (V.Self.Root), V.Self.Key, List);
            Lock    : constant Retention_Lock :=
              Create_Lock (U.Mode, At_Time + U.Retain_For, At_Time);
         begin
            V.Self.Index.Include
              (Name, (Id => List_Id, Lock => Lock, Composite => True));
            Add_Audit (V, Lock_Created, Name_Digest (Name),
                       At_Time + U.Retain_For);
         end;
         V.Self.Uploads.Delete (Upload_Id);
         Save (V);
      end;
   end Complete_Upload;

   procedure Abort_Upload (V : in out Vault_Type; Upload_Id : String) is
   begin
      if V.Self.Uploads.Contains (Upload_Id) then
         V.Self.Uploads.Delete (Upload_Id);
      end if;
   end Abort_Upload;

   function Contains (V : Vault_Type; Name : String) return Boolean is
     (V.Self.Index.Contains (Name));

   function Object_Count (V : Vault_Type) return Natural is
     (Natural (V.Self.Index.Length));

   function Object_Etag (V : Vault_Type; Name : String) return String is
     (if V.Self.Index.Contains (Name)
      then String (V.Self.Index.Element (Name).Id) else "");

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
      R    : Scrub_Report;
      Root : constant String := To_String (V.Self.Root);
   begin
      for Cur in V.Self.Index.Iterate loop
         R.Total := R.Total + 1;
         declare
            Res : constant Repair_Result :=
              Repair (Root, Meta_Maps.Element (Cur).Id);
         begin
            if not Res.Recoverable then
               R.Corrupt := R.Corrupt + 1;
            elsif Res.Shards_Repaired > 0 then
               R.Repaired := R.Repaired + 1;
               R.Shards_Repaired := R.Shards_Repaired + Res.Shards_Repaired;
            else
               R.Intact := R.Intact + 1;
            end if;
         end;
      end loop;
      return R;
   end Scrub;

   function Collect_Garbage (V : in out Vault_Type) return Natural is
      Root : constant String := To_String (V.Self.Root);
      Live : Id_Vectors.Vector;

      procedure Add_Parts (Composite_Id : Object_Id) is
         List : constant Stream_Element_Array := Get (Root, V.Self.Key, Composite_Id);
         N    : constant Natural := Natural (List'Length) / 64;
      begin
         for P in 0 .. N - 1 loop
            declare
               Pid : Object_Id;
            begin
               for I in 0 .. 63 loop
                  Pid (Pid'First + I) := Character'Val
                    (Natural (List (List'First + Stream_Element_Offset (P * 64 + I))));
               end loop;
               Live.Append (Pid);
            end;
         end loop;
      end Add_Parts;

   begin
      --  Live: every object's manifest id; composite part ids; and the parts of
      --  any in-flight upload (so collection never reclaims work in progress).
      for Cur in V.Self.Index.Iterate loop
         declare
            M : constant Meta := Meta_Maps.Element (Cur);
         begin
            Live.Append (M.Id);
            if M.Composite then
               Add_Parts (M.Id);
            end if;
         end;
      end loop;
      for Cur in V.Self.Uploads.Iterate loop
         for Pid of Upload_Maps.Element (Cur).Parts loop
            Live.Append (Pid);
         end loop;
      end loop;

      declare
         A : Cas.Id_List (1 .. Natural (Live.Length));
         R : Natural;
      begin
         for I in A'Range loop
            A (I) := Live (I - 1);
         end loop;
         Cas.Collect_Garbage (Root, A, R);
         return R;
      end;
   end Collect_Garbage;

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

   procedure Set_Legal_Hold (V : in out Vault_Type; Name : String) is
   begin
      if not V.Self.Index.Contains (Name) then
         raise Not_Found;
      end if;
      declare
         M : Meta := V.Self.Index.Element (Name);
      begin
         M.Lock := Set_Hold (M.Lock);
         V.Self.Index.Replace (Name, M);
         Add_Audit (V, Legal_Hold_Set, Name_Digest (Name),
                    CG.Now (V.Self.Clock));
         Save (V);
      end;
   end Set_Legal_Hold;

   procedure Release_Legal_Hold (V : in out Vault_Type; Name : String) is
   begin
      if not V.Self.Index.Contains (Name) then
         raise Not_Found;
      end if;
      declare
         M : Meta := V.Self.Index.Element (Name);
      begin
         M.Lock := Release_Hold (M.Lock);
         V.Self.Index.Replace (Name, M);
         Add_Audit (V, Legal_Hold_Released, Name_Digest (Name),
                    CG.Now (V.Self.Clock));
         Save (V);
      end;
   end Release_Legal_Hold;

   function Has_Legal_Hold (V : Vault_Type; Name : String) return Boolean is
     (V.Self.Index.Contains (Name)
      and then V.Self.Index.Element (Name).Lock.Legal_Hold);

   procedure Tick_From_System (V : in out Vault_Type) is
      Sample  : constant CG.Clock_Sample := Dezhan.Platform.Clock.Sample;
      Boot    : constant String := Dezhan.Platform.Clock.Boot_Id;
      Old     : constant String := To_String (V.Self.Last_Boot);
      Rebooted : constant Boolean := Old'Length > 0 and then Old /= Boot;
   begin
      V.Self.Last_Boot := To_Unbounded_String (Boot);
      Tick_Clock (V, Sample.Mono, Sample.Realtime, Boot_Changed => Rebooted);
      if Old /= Boot then
         Save (V);  --  persist the (new) boot id on first observation or a reboot
      end if;
   end Tick_From_System;

   procedure Seal (V : in out Vault_Type) is
   begin
      if not V.Self.Op_Sealed then
         V.Self.Op_Sealed := True;
         Add_Audit (V, Seal_Engaged, (others => 0), CG.Now (V.Self.Clock));
         Save (V);
      end if;
   end Seal;

   procedure Set_One_Way_Ingest (V : in out Vault_Type; Enabled : Boolean) is
   begin
      V.Self.Ingest_Only := Enabled;
      Save (V);
   end Set_One_Way_Ingest;

   function One_Way_Ingest (V : Vault_Type) return Boolean is
     (V.Self.Ingest_Only);

   procedure Open_Sync_Window (V : in out Vault_Type) is
   begin
      V.Self.Sync_Shut := False;
      Save (V);
   end Open_Sync_Window;

   procedure Close_Sync_Window (V : in out Vault_Type) is
   begin
      V.Self.Sync_Shut := True;
      Save (V);
   end Close_Sync_Window;

   function Sync_Window_Open (V : Vault_Type) return Boolean is
     (not V.Self.Sync_Shut);

   procedure Export (V : Vault_Type; Dest : String) is
      procedure Copy_Tree (Src, Dst : String) is
         S : Search_Type;
         E : Directory_Entry_Type;
      begin
         Create_Path (Dst);
         Start_Search (S, Src, "");
         while More_Entries (S) loop
            Get_Next_Entry (S, E);
            declare
               Name : constant String := Simple_Name (E);
            begin
               if Name /= "." and then Name /= ".." then
                  if Kind (E) = Directory then
                     Copy_Tree (Full_Name (E), Compose (Dst, Name));
                  else
                     Copy_File (Full_Name (E), Compose (Dst, Name));
                  end if;
               end if;
            end;
         end loop;
         End_Search (S);
      end Copy_Tree;
   begin
      Copy_Tree (To_String (V.Self.Root), Dest);
   end Export;

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
