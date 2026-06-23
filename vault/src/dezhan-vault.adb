with Ada.Strings.Unbounded;            use Ada.Strings.Unbounded;
with Ada.Strings.Hash;
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
      Root    : Unbounded_String;
      Key     : Key_256;
      Clock   : CG.Guard_State;
      Started : Boolean := False;   --  clock baseline taken from the first tick
      Index   : Meta_Maps.Map;
      Log     : Log_Vectors.Vector;
   end record;

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

   procedure Open (V : out Vault_Type; Root : String; Key : Key_256) is
   begin
      V.Self := new State;
      V.Self.Root := To_Unbounded_String (Root);
      V.Self.Key  := Key;
      Initialize (Root);
      V.Self.Clock :=
        CG.Init ((Mono => 0, Realtime => 0, Boot_Changed => False));
      V.Self.Log.Append (Genesis_Entry (Time => 0));
   end Open;

   procedure Put_Object
     (V          : in out Vault_Type;
      Name       : String;
      Data       : Stream_Element_Array;
      Mode       : Lock_Mode;
      Retain_For : Trusted_Time)
   is
   begin
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

   function Delete_Object
     (V : in out Vault_Type; Name : String; Bypass : Boolean) return Boolean
   is
   begin
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
            return True;
         else
            Add_Audit (V, Delete_Denied, Name_Digest (Name), At_Time);
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
         end if;
      end;
   end Tick_Clock;

   procedure Tick_From_System (V : in out Vault_Type) is
      Sample : constant CG.Clock_Sample := Dezhan.Platform.Clock.Sample;
   begin
      Tick_Clock (V, Sample.Mono, Sample.Realtime, Sample.Boot_Changed);
   end Tick_From_System;

   function Now (V : Vault_Type) return Trusted_Time is
     (CG.Now (V.Self.Clock));

   function Sealed (V : Vault_Type) return Boolean is
     (CG.Is_Sealed (V.Self.Clock));

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
