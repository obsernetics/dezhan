with Ada.Strings;                      use Ada.Strings;
with Ada.Strings.Fixed;                use Ada.Strings.Fixed;
with Ada.Strings.Unbounded;            use Ada.Strings.Unbounded;
with Ada.Strings.Hash;
with Ada.Text_IO;                       use Ada.Text_IO;
with Ada.Directories;                   use Ada.Directories;
with Ada.Containers.Indefinite_Hashed_Maps;
with Ada.Containers.Vectors;
with Ada.Containers.Ordered_Maps;
with Interfaces;                        use Interfaces;
with Dezhan.Trusted_Core.Hashing;       use Dezhan.Trusted_Core.Hashing;
with Dezhan.Trusted_Core.HMAC;          use Dezhan.Trusted_Core.HMAC;
with Dezhan.Trusted_Core.Clock_Guard;
with Dezhan.Trusted_Core.Audit;         use Dezhan.Trusted_Core.Audit;
with Dezhan.Trusted_Core.Ed25519;
with Dezhan.Storage.Cas;                use Dezhan.Storage.Cas;
with Dezhan.Platform.Clock;
with Dezhan.Platform.Sync;

package body Dezhan.Vault with SPARK_Mode => Off is

   package CG   renames Dezhan.Trusted_Core.Clock_Guard;
   package Cas  renames Dezhan.Storage.Cas;
   package Sync renames Dezhan.Platform.Sync;

   Clock_Tolerance : constant Trusted_Time := 2;

   type Meta is record
      Id          : Object_Id;
      Lock        : Retention_Lock;
      Composite   : Boolean := False;  --  Id points to a list of part ids
      Quarantined : Boolean := False;  --  scrub found it unrepairable (lost > M)
      Size        : Natural := 0;      --  object plaintext length (for listings)
      User_Meta   : Unbounded_String := Null_Unbounded_String;  --  opaque headers
   end record;

   package Meta_Maps is new Ada.Containers.Indefinite_Hashed_Maps
     (Key_Type => String, Element_Type => Meta,
      Hash => Ada.Strings.Hash, Equivalent_Keys => "=");

   package Log_Vectors is new Ada.Containers.Vectors
     (Index_Type => Natural, Element_Type => Audit_Entry);

   package Id_Vectors is new Ada.Containers.Vectors
     (Index_Type => Natural, Element_Type => Object_Id);

   --  Parts keyed by part number so completion concatenates them in order.
   package Part_Maps is new Ada.Containers.Ordered_Maps
     (Key_Type => Positive, Element_Type => Object_Id);

   type Upload is record
      Name       : Unbounded_String;
      Mode       : Lock_Mode := Compliance;
      Retain_For : Trusted_Time := 0;
      Parts      : Part_Maps.Map;
      Total      : Natural := 0;       --  cumulative bytes across parts
   end record;

   package Upload_Maps is new Ada.Containers.Indefinite_Hashed_Maps
     (Key_Type => String, Element_Type => Upload,
      Hash => Ada.Strings.Hash, Equivalent_Keys => "=");

   --  S3 buckets: name -> object-lock-enabled (immutable) flag. The same map
   --  type also tracks the versioning-enabled set.
   package Bucket_Maps is new Ada.Containers.Indefinite_Hashed_Maps
     (Key_Type => String, Element_Type => Boolean,
      Hash => Ada.Strings.Hash, Equivalent_Keys => "=");

   --  Object versioning: per "bucket/key" history of versions.
   type Version_Entry is record
      Vid     : Unbounded_String;    --  version id
      Id      : Object_Id;           --  content object for this version
      Size    : Natural := 0;
      Meta    : Unbounded_String;    --  Content-Type / user metadata blob
      Deleted : Boolean := False;    --  delete marker (no content)
   end record;
   package Ver_Vecs is new Ada.Containers.Vectors (Natural, Version_Entry);
   package Ver_Maps is new Ada.Containers.Indefinite_Hashed_Maps
     (Key_Type => String, Element_Type => Ver_Vecs.Vector,
      Hash => Ada.Strings.Hash, Equivalent_Keys => "=",
      "=" => Ver_Vecs."=");

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
      Buckets    : Bucket_Maps.Map;
      Versioned  : Bucket_Maps.Map;  --  buckets with versioning enabled
      Versions   : Ver_Maps.Map;     --  "bucket/key" -> version history
      Ver_Seq    : Natural := 0;     --  monotonic version-id source
      Jrnl_Count : Natural := 0;     --  journal records since the last snapshot
      Jrnl_Buf   : Unbounded_String; --  records pending in the current commit
      Jrnl_Pend  : Natural := 0;     --  records buffered but not yet flushed
   end record;

   --  Compact (rewrite a full snapshot, clear the journal) after this many
   --  appended records, bounding both the journal size and replay time.
   Compact_Limit : constant := 20_000;

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

   --  Forward declarations: the journal serializer and appender are defined
   --  with the persistence code below, but Add_Audit (above the callers) uses
   --  them to record each audit entry incrementally.
   function A_Line (E : Audit_Entry) return String;
   procedure Append_Jrnl (V : Vault_Type; Line : String);

   procedure Add_Audit
     (V       : in out Vault_Type;
      Kind    : Audit_Event;
      Subject : Digest;
      Detail  : Trusted_Time)
   is
      E : constant Audit_Entry :=
        Append (V.Self.Log.Last_Element, CG.Now (V.Self.Clock),
                Kind, Subject, Detail);
   begin
      V.Self.Log.Append (E);
      Append_Jrnl (V, A_Line (E));
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

   function Journal_Path (V : Vault_Type) return String is
     (Compose (To_String (V.Self.Root), "vault.journal"));

   --  ---- Record serializers (shared by the snapshot and the journal) ----
   function Core_Clock (V : Vault_Type) return String is
     ("CLOCK " & Trusted_Time'Image (CG.Now (V.Self.Clock))
      & (if CG.Is_Sealed (V.Self.Clock) then " 1" else " 0")
      & (if V.Self.Op_Sealed then " 1" else " 0"));
   function Core_Boot (V : Vault_Type) return String is
     ("BOOT " & To_String (V.Self.Last_Boot));
   function Core_Modes (V : Vault_Type) return String is
     ("MODES " & (if V.Self.Ingest_Only then "1" else "0")
      & " " & (if V.Self.Sync_Shut then "1" else "0"));
   function Core_Vseq (V : Vault_Type) return String is
     ("VSEQ" & Natural'Image (V.Self.Ver_Seq));
   function Bkt_Line (Name : String; Lock : Boolean) return String is
     ("BKT " & Str_To_Hex (Name) & (if Lock then " 1" else " 0"));
   function Vsn_Line (Name : String; On : Boolean) return String is
     ("VSN " & Str_To_Hex (Name) & (if On then " 1" else " 0"));
   function Ver_Line (Name : String; E : Version_Entry) return String is
     ("VER " & Str_To_Hex (Name) & " " & To_String (E.Vid)
      & " " & String (E.Id) & Natural'Image (E.Size)
      & (if E.Deleted then " 1" else " 0")
      & " " & Str_To_Hex (To_String (E.Meta)));
   function Obj_Line (Name : String; M : Meta) return String is
     ("OBJ " & Str_To_Hex (Name) & " " & String (M.Id)
      & Lock_Mode'Pos (M.Lock.Mode)'Image
      & M.Lock.Retain_Until'Image & M.Lock.Created_At'Image
      & (if M.Composite then " 1" else " 0")
      & (if M.Lock.Legal_Hold then " 1" else " 0")
      & (if M.Quarantined then " 1" else " 0")
      & Natural'Image (M.Size)
      & " " & Str_To_Hex (To_String (M.User_Meta)));

   function A_Line (E : Audit_Entry) return String is
     ("A" & E.Seq'Image & E.Time'Image & Audit_Event'Pos (E.Kind)'Image
      & " " & To_Hex (E.Subject) & E.Detail'Image
      & " " & To_Hex (E.Prev_Hash) & " " & To_Hex (E.Hash));

   --  Full snapshot: write the entire state atomically, then start a fresh,
   --  empty journal. Used at open and as periodic compaction; also the persist
   --  path for infrequent (non-hot) mutations.
   procedure Save (V : Vault_Type) is
      Tmp : constant String := State_Path (V) & ".tmp";
      F   : File_Type;
   begin
      Create (F, Out_File, Tmp);
      Put_Line (F, "DEZHAN_VAULT 1");
      Put_Line (F, Core_Clock (V));
      Put_Line (F, Core_Boot (V));
      Put_Line (F, Core_Modes (V));
      for Cur in V.Self.Buckets.Iterate loop
         Put_Line (F, Bkt_Line (Bucket_Maps.Key (Cur), Bucket_Maps.Element (Cur)));
      end loop;
      for Cur in V.Self.Versioned.Iterate loop
         if Bucket_Maps.Element (Cur) then
            Put_Line (F, Vsn_Line (Bucket_Maps.Key (Cur), True));
         end if;
      end loop;
      Put_Line (F, Core_Vseq (V));
      for Cur in V.Self.Versions.Iterate loop
         for E of Ver_Maps.Element (Cur) loop
            Put_Line (F, Ver_Line (Ver_Maps.Key (Cur), E));
         end loop;
      end loop;
      for Cur in V.Self.Index.Iterate loop
         Put_Line (F, Obj_Line (Meta_Maps.Key (Cur), Meta_Maps.Element (Cur)));
      end loop;
      Put_Line (F, "AUDIT" & Natural'Image (Natural (V.Self.Log.Length)));
      for I in 0 .. Natural (V.Self.Log.Length) - 1 loop
         Put_Line (F, A_Line (V.Self.Log.Element (I)));
      end loop;
      Close (F);
      Sync.Fsync (Tmp);
      Sync.Durable_Rename (Tmp, State_Path (V), To_String (V.Self.Root));
      --  The snapshot now holds everything: reset the journal and any buffer.
      declare
         J : File_Type;
      begin
         Create (J, Out_File, Journal_Path (V));
         Close (J);
         Sync.Fsync (Journal_Path (V));
      end;
      V.Self.Jrnl_Count := 0;
      V.Self.Jrnl_Buf   := Null_Unbounded_String;
      V.Self.Jrnl_Pend  := 0;
   end Save;

   --  Buffer one delta for the current mutation (no I/O yet); Commit_Jrnl
   --  flushes the whole batch with a single fsync.
   procedure Append_Jrnl (V : Vault_Type; Line : String) is
   begin
      Append (V.Self.Jrnl_Buf, Line & ASCII.LF);
      V.Self.Jrnl_Pend := V.Self.Jrnl_Pend + 1;
   end Append_Jrnl;

   --  Group commit: write all buffered records and fsync once. Compacts to a
   --  fresh snapshot (which also flushes) once the journal grows past the limit.
   procedure Commit_Jrnl (V : Vault_Type) is
      J : File_Type;
   begin
      if V.Self.Jrnl_Pend = 0 then
         return;
      end if;
      if V.Self.Jrnl_Count + V.Self.Jrnl_Pend >= Compact_Limit then
         Save (V);   --  snapshot captures the in-memory state and clears buffer
         return;
      end if;
      begin
         Open (J, Append_File, Journal_Path (V));
      exception
         when others => Create (J, Out_File, Journal_Path (V));
      end;
      Put (J, To_String (V.Self.Jrnl_Buf));
      Close (J);
      Sync.Fsync (Journal_Path (V));
      V.Self.Jrnl_Count := V.Self.Jrnl_Count + V.Self.Jrnl_Pend;
      V.Self.Jrnl_Buf   := Null_Unbounded_String;
      V.Self.Jrnl_Pend  := 0;
   end Commit_Jrnl;

   --  Hot-path journal helpers.
   procedure J_Obj (V : Vault_Type; Name : String) is
   begin
      Append_Jrnl (V, Obj_Line (Name, V.Self.Index.Element (Name)));
   end J_Obj;
   procedure J_Del (V : Vault_Type; Name : String) is
   begin
      Append_Jrnl (V, "DEL " & Str_To_Hex (Name));
   end J_Del;
   procedure J_Ver (V : Vault_Type; Name : String; E : Version_Entry) is
   begin
      Append_Jrnl (V, Ver_Line (Name, E));
   end J_Ver;
   procedure J_Vseq (V : Vault_Type) is
   begin
      Append_Jrnl (V, Core_Vseq (V));
   end J_Vseq;

   --  Apply one persisted record. Idempotent so the snapshot and then the
   --  journal (which may overlap after a crash mid-compaction) can both be
   --  replayed safely: object/bucket writes overwrite, deletes tolerate
   --  absence, versions dedup by id, and audit entries dedup by sequence.
   procedure Apply_Line (V : in out Vault_Type; Line : String) is
      Tag : constant String := Field (Line, 1);
   begin
      if Tag = "CLOCK" then
         V.Self.Clock :=
           (Floor     => Trusted_Time'Value (Field (Line, 2)),
            Last_Mono => 0, Last_Real => 0, Anomaly => CG.None,
            Sealed    => Field (Line, 3) = "1");
         V.Self.Op_Sealed := Field (Line, 4) = "1";
         V.Self.Started := False;
      elsif Tag = "BOOT" then
         V.Self.Last_Boot := To_Unbounded_String (Field (Line, 2));
      elsif Tag = "MODES" then
         V.Self.Ingest_Only := Field (Line, 2) = "1";
         V.Self.Sync_Shut   := Field (Line, 3) = "1";
      elsif Tag = "BKT" then
         V.Self.Buckets.Include
           (Hex_To_Str (Field (Line, 2)), Field (Line, 3) = "1");
      elsif Tag = "BKD" then
         declare
            N : constant String := Hex_To_Str (Field (Line, 2));
         begin
            if V.Self.Buckets.Contains (N) then
               V.Self.Buckets.Delete (N);
            end if;
         end;
      elsif Tag = "VSN" then
         --  Old snapshots wrote no flag (meaning enabled); treat that as on.
         V.Self.Versioned.Include
           (Hex_To_Str (Field (Line, 2)), Field (Line, 3) /= "0");
      elsif Tag = "VSEQ" then
         V.Self.Ver_Seq := Natural'Value (Field (Line, 2));
      elsif Tag = "VER" then
         declare
            Name : constant String := Hex_To_Str (Field (Line, 2));
            Vid  : constant String := Field (Line, 3);
            E    : constant Version_Entry :=
              (Vid     => To_Unbounded_String (Vid),
               Id      => Object_Id (Field (Line, 4)),
               Size    => Natural'Value (Field (Line, 5)),
               Deleted => Field (Line, 6) = "1",
               Meta    => To_Unbounded_String (Hex_To_Str (Field (Line, 7))));
            Vec  : Ver_Vecs.Vector;
            Seen : Boolean := False;
         begin
            if V.Self.Versions.Contains (Name) then
               Vec := V.Self.Versions.Element (Name);
               for X of Vec loop
                  if To_String (X.Vid) = Vid then
                     Seen := True;
                  end if;
               end loop;
            end if;
            if not Seen then
               Vec.Append (E);
               V.Self.Versions.Include (Name, Vec);
            end if;
         end;
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
             Composite   => Field (Line, 7) = "1",
             Quarantined => Field (Line, 9) = "1",
             Size        => (if Field (Line, 10) = "" then 0
                             else Natural'Value (Field (Line, 10))),
             User_Meta   =>
               To_Unbounded_String (Hex_To_Str (Field (Line, 11)))));
      elsif Tag = "DEL" then
         declare
            N : constant String := Hex_To_Str (Field (Line, 2));
         begin
            if V.Self.Index.Contains (N) then
               V.Self.Index.Delete (N);
            end if;
         end;
      elsif Tag = "A" then
         declare
            Seq : constant Natural := Natural'Value (Field (Line, 2));
         begin
            if Seq = Natural (V.Self.Log.Length) then   --  next expected
               V.Self.Log.Append
                 (Audit_Entry'
                    (Seq       => Seq,
                     Time      => Trusted_Time'Value (Field (Line, 3)),
                     Kind      =>
                       Audit_Event'Val (Integer'Value (Field (Line, 4))),
                     Subject   => From_Hex (Field (Line, 5)),
                     Detail    => Trusted_Time'Value (Field (Line, 6)),
                     Prev_Hash => From_Hex (Field (Line, 7)),
                     Hash      => From_Hex (Field (Line, 8))));
            end if;
         end;
      end if;
   end Apply_Line;

   procedure Load (V : in out Vault_Type) is
      F : File_Type;
   begin
      Open (F, In_File, State_Path (V));
      while not End_Of_File (F) loop
         Apply_Line (V, Get_Line (F));
      end loop;
      Close (F);
      --  Replay deltas appended since the last snapshot.
      if Exists (Journal_Path (V)) then
         Open (F, In_File, Journal_Path (V));
         while not End_Of_File (F) loop
            Apply_Line (V, Get_Line (F));
            V.Self.Jrnl_Count := V.Self.Jrnl_Count + 1;
         end loop;
         Close (F);
      end if;
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
      Retain_For : Trusted_Time;
      User_Meta  : String := "")
   is
      --  Part size for the large-object split (comfortably under the single
      --  -manifest cap). Objects up to Max_Single store as one manifest; larger
      --  ones split into Part_Size parts, so the chunker is never handed more
      --  than it (or the task stack) can take.
      Part_Size  : constant := 900_000;
      Max_Single : constant := 2_000_000;
      Root       : constant String := To_String (V.Self.Root);
   begin
      Check_Ingest (V);
      if Mode = Unlocked then
         raise Invalid_Mode;
      end if;
      declare
         At_Time : constant Trusted_Time := CG.Now (V.Self.Clock);
         Lock    : constant Retention_Lock :=
           Create_Lock (Mode, At_Time + Retain_For, At_Time);
         Obj_Id  : Object_Id;
         Comp    : Boolean := False;

         --  Store an over-sized object as a composite of Part_Size parts (the
         --  same shape as a completed multipart upload), so the chunker only
         --  ever sees bounded, single-manifest inputs.
         function Store_Composite return Object_Id is
            N_Parts : constant Natural :=
              (Natural (Data'Length) + Part_Size - 1) / Part_Size;
            List    : Stream_Element_Array
                        (1 .. Stream_Element_Offset (N_Parts * 64));
            LPos    : Stream_Element_Offset := 1;
         begin
            for P in 0 .. N_Parts - 1 loop
               declare
                  F : constant Stream_Element_Offset :=
                    Data'First + Stream_Element_Offset (P * Part_Size);
                  L : Stream_Element_Offset := F + Part_Size - 1;
               begin
                  if L > Data'Last then
                     L := Data'Last;
                  end if;
                  declare
                     Pid : constant Object_Id :=
                       Put (Root, V.Self.Key, Data (F .. L));
                  begin
                     for I in 0 .. 63 loop
                        List (LPos) :=
                          Stream_Element (Character'Pos (Pid (Pid'First + I)));
                        LPos := LPos + 1;
                     end loop;
                  end;
               end;
            end loop;
            return Put (Root, V.Self.Key, List);
         end Store_Composite;
      begin
         --  Split large objects up front: handing the whole object to the
         --  chunker copies it onto the task stack (and overflows past a few tens
         --  of MB) before the manifest-size fallback could fire. The exception
         --  path stays as a safety net for the boundary.
         if Natural (Data'Length) <= Max_Single then
            begin
               Obj_Id := Put (Root, V.Self.Key, Data);
            exception
               when Object_Too_Large =>
                  Comp := True;
                  Obj_Id := Store_Composite;
            end;
         else
            Comp := True;
            Obj_Id := Store_Composite;
         end if;

         V.Self.Index.Include
           (Name, (Id => Obj_Id, Lock => Lock, Composite => Comp,
                   Quarantined => False, Size => Natural (Data'Length),
                   User_Meta => To_Unbounded_String (User_Meta)));
         Add_Audit (V, Lock_Created, Name_Digest (Name), At_Time + Retain_For);
         J_Obj (V, Name);
         Commit_Jrnl (V);
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
         if M.Quarantined then
            raise Object_Quarantined;  --  scrub found it unrepairable
         end if;
         if not M.Composite then
            return Get (Root, V.Self.Key, M.Id);
         end if;
         --  Composite: M.Id is a list of 64-char part ids. Fetch each part and
         --  copy it in whole slices into the result, which is built as the
         --  return object (no extra whole-object copy, no per-byte loop).
         --  M.Size is the exact assembled length; parts may vary in size, so
         --  track the running position.
         declare
            List : constant Stream_Element_Array := Get (Root, V.Self.Key, M.Id);
            N    : constant Natural := Natural (List'Length) / 64;
         begin
            --  Fetch each part in order and copy it into the result as a whole
            --  slice. (Parts are fetched sequentially: a part may be DEFLATE
            --  -compressed, and the decompressor is not reentrant, so parts
            --  cannot be decoded concurrently.) M.Size is the exact assembled
            --  length; part sizes vary, so track the running position.
            return R : Stream_Element_Array
                         (1 .. Stream_Element_Offset (M.Size))
            do
               declare
                  Pos : Stream_Element_Offset := R'First;
               begin
                  for P in 0 .. N - 1 loop
                     declare
                        Pid : Object_Id;
                     begin
                        for I in 0 .. 63 loop
                           Pid (Pid'First + I) :=
                             Character'Val (Natural
                               (List (List'First
                                      + Stream_Element_Offset (P * 64 + I))));
                        end loop;
                        declare
                           Part : constant Stream_Element_Array :=
                             Get (Root, V.Self.Key, Pid);
                        begin
                           R (Pos .. Pos + Part'Length - 1) := Part;
                           Pos := Pos + Part'Length;
                        end;
                     end;
                  end loop;
               end;
            end return;
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
                 Parts      => Part_Maps.Empty_Map,
                 Total      => 0));
         return Id;
      end;
   end Create_Upload;

   procedure Upload_Part
     (V : in out Vault_Type; Upload_Id : String; Data : Stream_Element_Array;
      Part_Number : Natural := 0)
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
         PN  : constant Positive :=
           (if Part_Number > 0 then Part_Number
            elsif U.Parts.Is_Empty then 1
            else U.Parts.Last_Key + 1);
      begin
         if not U.Parts.Contains (PN) then
            U.Total := U.Total + Natural (Data'Length);
         end if;
         U.Parts.Include (PN, Pid);
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
              (Name, (Id => List_Id, Lock => Lock, Composite => True,
                      Quarantined => False, Size => U.Total,
                      User_Meta => Null_Unbounded_String));
            Add_Audit (V, Lock_Created, Name_Digest (Name),
                       At_Time + U.Retain_For);
         end;
         V.Self.Uploads.Delete (Upload_Id);
         J_Obj (V, Name);
         Commit_Jrnl (V);
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

   function Object_Size (V : Vault_Type; Name : String) return Natural is
     (if V.Self.Index.Contains (Name)
      then V.Self.Index.Element (Name).Size else 0);

   function Object_Meta (V : Vault_Type; Name : String) return String is
     (if V.Self.Index.Contains (Name)
      then To_String (V.Self.Index.Element (Name).User_Meta) else "");

   function Object_Deletable (V : Vault_Type; Name : String) return Boolean is
     (V.Self.Index.Contains (Name)
      and then Can_Delete (V.Self.Index.Element (Name).Lock,
                           CG.Now (V.Self.Clock),
                           (Bypass_Governance => False)));

   procedure Create_Bucket
     (V : in out Vault_Type; Name : String; Object_Lock : Boolean := False) is
   begin
      Check_Ingest (V);
      if V.Self.Buckets.Contains (Name) then
         raise Bucket_Exists_Error;
      end if;
      V.Self.Buckets.Include (Name, Object_Lock);
      Save (V);
   end Create_Bucket;

   function Bucket_Exists (V : Vault_Type; Name : String) return Boolean is
     (V.Self.Buckets.Contains (Name));

   function Bucket_Object_Lock (V : Vault_Type; Name : String) return Boolean is
     (V.Self.Buckets.Contains (Name) and then V.Self.Buckets.Element (Name));

   procedure Delete_Bucket (V : in out Vault_Type; Name : String) is
      Prefix : constant String := Name & "/";
   begin
      Check_Ingest (V);
      if not V.Self.Buckets.Contains (Name) then
         raise Not_Found;
      end if;
      for Cur in V.Self.Index.Iterate loop
         declare
            K : constant String := Meta_Maps.Key (Cur);
         begin
            if K'Length >= Prefix'Length
              and then K (K'First .. K'First + Prefix'Length - 1) = Prefix
            then
               raise Bucket_Not_Empty;
            end if;
         end;
      end loop;
      V.Self.Buckets.Delete (Name);
      Save (V);
   end Delete_Bucket;

   function List_Buckets (V : Vault_Type) return String is
      R : Unbounded_String;
   begin
      for Cur in V.Self.Buckets.Iterate loop
         Append (R, Bucket_Maps.Key (Cur));
         Append (R, ASCII.LF);
      end loop;
      return To_String (R);
   end List_Buckets;

   procedure Set_Versioning
     (V : in out Vault_Type; Bucket : String; On : Boolean) is
   begin
      V.Self.Versioned.Include (Bucket, On);
      Save (V);
   end Set_Versioning;

   function Bucket_Versioned (V : Vault_Type; Bucket : String) return Boolean is
     (V.Self.Versioned.Contains (Bucket)
      and then V.Self.Versioned.Element (Bucket));

   function Record_Version (V : in out Vault_Type; Name : String) return String is
      M   : constant Meta := V.Self.Index.Element (Name);
   begin
      V.Self.Ver_Seq := V.Self.Ver_Seq + 1;
      declare
         Vid : constant String :=
           Trim (V.Self.Ver_Seq'Image, Ada.Strings.Both);
         E   : constant Version_Entry :=
           (Vid     => To_Unbounded_String (Vid),
            Id      => M.Id,
            Size    => M.Size,
            Meta    => M.User_Meta,
            Deleted => False);
         Vec : Ver_Vecs.Vector;
      begin
         if V.Self.Versions.Contains (Name) then
            Vec := V.Self.Versions.Element (Name);
         end if;
         Vec.Append (E);
         V.Self.Versions.Include (Name, Vec);
         J_Vseq (V);
         J_Ver (V, Name, E);
         Commit_Jrnl (V);
         return Vid;
      end;
   end Record_Version;

   function Get_Object_Version
     (V : Vault_Type; Name, Vid : String) return Stream_Element_Array is
   begin
      if V.Self.Ingest_Only then
         raise Egress_Denied;
      end if;
      if not V.Self.Versions.Contains (Name) then
         raise Not_Found;
      end if;
      for E of V.Self.Versions.Element (Name) loop
         if To_String (E.Vid) = Vid then
            if E.Deleted then
               raise Not_Found;     --  a delete marker has no content
            end if;
            return Get (To_String (V.Self.Root), V.Self.Key, E.Id);
         end if;
      end loop;
      raise Not_Found;
   end Get_Object_Version;

   function Delete_Marker (V : in out Vault_Type; Name : String) return String is
      Vec : Ver_Vecs.Vector;
   begin
      V.Self.Ver_Seq := V.Self.Ver_Seq + 1;
      declare
         Vid : constant String := Trim (V.Self.Ver_Seq'Image, Ada.Strings.Both);
      begin
         if V.Self.Versions.Contains (Name) then
            Vec := V.Self.Versions.Element (Name);
         end if;
         declare
            E : constant Version_Entry :=
              (Vid     => To_Unbounded_String (Vid),
               Id      => (others => '0'),
               Size    => 0,
               Meta    => Null_Unbounded_String,
               Deleted => True);
         begin
            Vec.Append (E);
            V.Self.Versions.Include (Name, Vec);
            --  The key now reads as deleted; prior version objects are kept by
            --  the version log (and GC), so they remain retrievable by id.
            if V.Self.Index.Contains (Name) then
               V.Self.Index.Delete (Name);
               J_Del (V, Name);
            end if;
            Add_Audit (V, Delete_Allowed, Name_Digest (Name), CG.Now (V.Self.Clock));
            J_Vseq (V);
            J_Ver (V, Name, E);
            Commit_Jrnl (V);
            return Vid;
         end;
      end;
   end Delete_Marker;

   procedure Delete_Version (V : in out Vault_Type; Name, Vid : String) is
   begin
      if not V.Self.Versions.Contains (Name) then
         raise Not_Found;
      end if;
      declare
         Vec : Ver_Vecs.Vector := V.Self.Versions.Element (Name);
         Idx : Integer := -1;
      begin
         for I in Vec.First_Index .. Vec.Last_Index loop
            if To_String (Vec.Element (I).Vid) = Vid then
               Idx := I;
            end if;
         end loop;
         if Idx < 0 then
            raise Not_Found;
         end if;
         Vec.Delete (Idx);

         --  Repoint the live key to the newest surviving real version, if any.
         if V.Self.Index.Contains (Name) then
            V.Self.Index.Delete (Name);
         end if;
         for I in reverse Vec.First_Index .. Vec.Last_Index loop
            if not Vec.Element (I).Deleted then
               declare
                  E : constant Version_Entry := Vec.Element (I);
               begin
                  V.Self.Index.Include
                    (Name, (Id => E.Id, Lock => Create_Lock (Governance, 0, 0),
                            Composite => False, Quarantined => False,
                            Size => E.Size, User_Meta => E.Meta));
               end;
               exit;
            end if;
         end loop;

         if Vec.Is_Empty then
            V.Self.Versions.Delete (Name);
         else
            V.Self.Versions.Include (Name, Vec);
         end if;
         Save (V);
      end;
   end Delete_Version;

   function List_Object_Versions (V : Vault_Type; Bucket : String) return String is
      Prefix : constant String := Bucket & "/";
      R      : Unbounded_String;
   begin
      for Cur in V.Self.Versions.Iterate loop
         declare
            Name : constant String := Ver_Maps.Key (Cur);
         begin
            if Name'Length >= Prefix'Length
              and then Name (Name'First .. Name'First + Prefix'Length - 1) = Prefix
            then
               declare
                  Key : constant String :=
                    Name (Name'First + Prefix'Length .. Name'Last);
               begin
                  for E of Ver_Maps.Element (Cur) loop
                     Append (R, Key & ASCII.HT & To_String (E.Vid) & ASCII.HT
                       & Trim (E.Size'Image, Ada.Strings.Both) & ASCII.HT
                       & String (E.Id) & ASCII.HT
                       & (if E.Deleted then "1" else "0") & ASCII.LF);
                  end loop;
               end;
            end if;
         end;
      end loop;
      return To_String (R);
   end List_Object_Versions;

   function Scrub (V : Vault_Type) return Scrub_Report is
      R    : Scrub_Report;
      Root : constant String := To_String (V.Self.Root);
   begin
      for Cur in V.Self.Index.Iterate loop
         R.Total := R.Total + 1;
         declare
            Name : constant String := Meta_Maps.Key (Cur);
            M    : Meta := Meta_Maps.Element (Cur);
            Res  : constant Repair_Result := Repair (Root, M.Id);
         begin
            if not Res.Recoverable then
               R.Corrupt := R.Corrupt + 1;
               if not M.Quarantined then
                  --  New unrepairable object: quarantine it and record it in
                  --  the audit chain so the loss is visible and tamper-evident.
                  M.Quarantined := True;
                  V.Self.Index.Replace_Element (Cur, M);
                  V.Self.Log.Append
                    (Append (V.Self.Log.Last_Element, CG.Now (V.Self.Clock),
                             Dezhan.Trusted_Core.Audit.Object_Quarantined,
                             Name_Digest (Name), 0));
                  J_Obj (V, Name);
                  Append_Jrnl (V, A_Line (V.Self.Log.Last_Element));
               end if;
            else
               if Res.Shards_Repaired > 0 then
                  R.Repaired := R.Repaired + 1;
                  R.Shards_Repaired := R.Shards_Repaired + Res.Shards_Repaired;
               else
                  R.Intact := R.Intact + 1;
               end if;
               if M.Quarantined then
                  --  Redundancy was restored (e.g. shards copied back): lift it.
                  M.Quarantined := False;
                  V.Self.Index.Replace_Element (Cur, M);
                  J_Obj (V, Name);
               end if;
            end if;
         end;
      end loop;
      Commit_Jrnl (V);   --  one fsync for the whole scrub pass
      return R;
   end Scrub;

   function Quarantined_Count (V : Vault_Type) return Natural is
      N : Natural := 0;
   begin
      for M of V.Self.Index loop
         if M.Quarantined then
            N := N + 1;
         end if;
      end loop;
      return N;
   end Quarantined_Count;

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
      --  Retain every stored version's object.
      for Cur in V.Self.Versions.Iterate loop
         for E of Ver_Maps.Element (Cur) loop
            Live.Append (E.Id);
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
            J_Del (V, Name);
            Commit_Jrnl (V);
            return True;
         else
            Add_Audit (V, Delete_Denied, Name_Digest (Name), At_Time);
            Commit_Jrnl (V);   --  flush the buffered denial record
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

   --  Ed25519 checkpoint key, derived from the vault key (key separation) so
   --  there is no extra secret to manage; the public part is publishable.
   function Checkpoint_Seed (V : Vault_Type) return Dezhan.Trusted_Core.Ed25519.Key_32
   is
      Lbl : constant String := "dezhan/checkpoint/ed25519";
      KB  : Byte_Array (0 .. 31);
      LB  : Byte_Array (0 .. Lbl'Length - 1);
      H   : Digest;
      R   : Dezhan.Trusted_Core.Ed25519.Key_32;
   begin
      for I in 0 .. 31 loop
         KB (I) := V.Self.Key (I);
      end loop;
      for I in 0 .. Lbl'Length - 1 loop
         LB (I) := Byte (Character'Pos (Lbl (Lbl'First + I)));
      end loop;
      H := HMAC_SHA256 (KB, LB);
      for I in 0 .. 31 loop
         R (I) := H (I);
      end loop;
      return R;
   end Checkpoint_Seed;

   --  Lowercase hex of an arbitrary byte sequence.
   function Hex_Bytes (B : Byte_Array) return String is
      Digits_Hex : constant String := "0123456789abcdef";
      R : String (1 .. B'Length * 2);
   begin
      for I in 0 .. B'Length - 1 loop
         R (I * 2 + 1) := Digits_Hex (Integer (B (B'First + I)) / 16 + 1);
         R (I * 2 + 2) := Digits_Hex (Integer (B (B'First + I)) mod 16 + 1);
      end loop;
      return R;
   end Hex_Bytes;

   --  Checkpoint payload: 8-byte big-endian head sequence, then the head hash.
   function Head_Payload (Seq : Natural; Head : Digest) return Byte_Array is
      R : Byte_Array (0 .. 39) := (others => 0);
   begin
      for I in 0 .. 7 loop
         R (I) := Byte (Shift_Right (Unsigned_64 (Seq), 8 * (7 - I)) and 16#FF#);
      end loop;
      for I in 0 .. 31 loop
         R (8 + I) := Head (I);
      end loop;
      return R;
   end Head_Payload;

   function Checkpoint_Public_Key (V : Vault_Type) return String is
      use Dezhan.Trusted_Core.Ed25519;
      Pub : constant Key_32 := Public_Key (Checkpoint_Seed (V));
      B   : Byte_Array (0 .. 31);
   begin
      for I in 0 .. 31 loop
         B (I) := Pub (I);
      end loop;
      return Hex_Bytes (B);
   end Checkpoint_Public_Key;

   procedure Make_Checkpoint (V : Vault_Type) is
      use Dezhan.Trusted_Core.Ed25519;
      Last    : constant Audit_Entry := V.Self.Log.Last_Element;
      Seed    : constant Key_32      := Checkpoint_Seed (V);
      Pub     : constant Key_32      := Public_Key (Seed);
      Payload : constant Byte_Array  := Head_Payload (Last.Seq, Last.Hash);
      Sig     : constant Sig_64      := Sign (Seed, Payload);
      Pub_B   : Byte_Array (0 .. 31);
      Sig_B   : Byte_Array (0 .. 63);
      Path    : constant String := Compose (To_String (V.Self.Root), "vault.checkpoint");
      Tmp     : constant String := Path & ".tmp";
      F       : File_Type;
   begin
      for I in 0 .. 31 loop
         Pub_B (I) := Pub (I);
      end loop;
      for I in 0 .. 63 loop
         Sig_B (I) := Sig (I);
      end loop;
      Create (F, Out_File, Tmp);
      Put_Line (F, "CKPT" & Last.Seq'Image & " " & To_Hex (Last.Hash)
                   & " " & Hex_Bytes (Pub_B) & " " & Hex_Bytes (Sig_B));
      Close (F);
      Sync.Fsync (Tmp);
      Sync.Durable_Rename (Tmp, Path, To_String (V.Self.Root));
   end Make_Checkpoint;

end Dezhan.Vault;
