--  Vault: the orchestration layer that turns the verified trusted-core
--  primitives into WORM behavior. It ties together:
--    * encrypted content-addressed storage (Dezhan.Storage.Cas),
--    * retention / Object Lock (Dezhan.Trusted_Core.Retention),
--    * trusted time (Dezhan.Trusted_Core.Clock_Guard), and
--    * the append-only audit chain (Dezhan.Trusted_Core.Audit).
--
--  An object stored with a Compliance lock cannot be deleted before expiry, even
--  with a bypass; every operation is recorded in the audit chain; trusted time
--  comes from the clock guard so a manipulated system clock cannot expire a lock.
--
--  Regular Ada (SPARK_Mode Off): it orchestrates verified components. Metadata
--  (object index, audit chain, clock high-water mark, seal, boot id) is persisted
--  to <root>/vault.state on each mutation and reloaded on open, so the vault
--  survives a restart; a reboot is detected via the kernel boot id.
with Ada.Streams; use Ada.Streams;
with Dezhan.Trusted_Core.Times;       use Dezhan.Trusted_Core.Times;
with Dezhan.Trusted_Core.Retention;   use Dezhan.Trusted_Core.Retention;
with Dezhan.Trusted_Core.Cipher;      use Dezhan.Trusted_Core.Cipher;
with Dezhan.Storage.Cas;
package Dezhan.Vault with SPARK_Mode => Off is

   type Vault_Type is limited private;

   Not_Found       : exception;
   Invalid_Mode    : exception;
   Vault_Sealed    : exception; --  raised by mutations while the vault is sealed
   No_Such_Upload  : exception;
   Egress_Denied   : exception; --  reads blocked in one-way-ingest mode
   Sync_Closed     : exception; --  writes blocked outside a sync window
   Object_Quarantined : exception; --  read of an object scrub found unrepairable
   --  Get of an object whose keyed auth tag does not verify (wrong key/tamper).
   Auth_Failed     : exception renames Dezhan.Storage.Cas.Auth_Failed;

   --  Open (or create) a vault rooted at Root, encrypted under Key.
   procedure Open (V : out Vault_Type; Root : String; Key : Key_256);

   --  Store Name with a retention lock of Mode for Retain_For trusted-time
   --  units from now. Mode must be Governance or Compliance.
   procedure Put_Object
     (V          : in out Vault_Type;
      Name       : String;
      Data       : Stream_Element_Array;
      Mode       : Lock_Mode;
      Retain_For : Trusted_Time;
      User_Meta  : String := "");

   function Get_Object (V : Vault_Type; Name : String) return Stream_Element_Array;

   --  Opaque per-object metadata blob stored at Put (Content-Type and user
   --  headers); "" if none. The vault does not interpret it.
   function Object_Meta (V : Vault_Type; Name : String) return String;

   --  Multipart upload (S3-style): begin an upload, append parts in order, then
   --  complete to store the object as a composite of its parts (which removes
   --  the single-manifest size limit), or abort. Parts and the completed object
   --  are encrypted at source like any object.
   function Create_Upload
     (V          : in out Vault_Type;
      Name       : String;
      Mode       : Lock_Mode;
      Retain_For : Trusted_Time) return String;

   --  Part_Number orders parts in the completed object (S3 clients upload parts
   --  concurrently and out of order). 0 means append after the highest so far.
   procedure Upload_Part
     (V : in out Vault_Type; Upload_Id : String; Data : Stream_Element_Array;
      Part_Number : Natural := 0);

   procedure Complete_Upload (V : in out Vault_Type; Upload_Id : String);
   procedure Abort_Upload    (V : in out Vault_Type; Upload_Id : String);

   function Contains (V : Vault_Type; Name : String) return Boolean;
   function Object_Count (V : Vault_Type) return Natural;

   --  Number of objects scrub has quarantined (lost more than M shards, so
   --  unrepairable). A read of a quarantined object raises Object_Quarantined.
   function Quarantined_Count (V : Vault_Type) return Natural;

   --  Plaintext length of a stored object (0 if absent), for S3 listings.
   function Object_Size (V : Vault_Type; Name : String) return Natural;

   --  True if Name exists and its lock currently permits deletion (expired and
   --  no legal hold). Gates S3 overwrites so a locked object is never replaced.
   function Object_Deletable (V : Vault_Type; Name : String) return Boolean;

   --  S3 buckets. Names map onto the flat object namespace as "<bucket>/<key>".
   --  An object-lock-enabled bucket is immutable (retention enforced).
   Bucket_Exists_Error : exception;  --  create over an existing bucket
   Bucket_Not_Empty    : exception;  --  delete a bucket that still has objects
   procedure Create_Bucket
     (V : in out Vault_Type; Name : String; Object_Lock : Boolean := False);
   function  Bucket_Exists      (V : Vault_Type; Name : String) return Boolean;
   function  Bucket_Object_Lock (V : Vault_Type; Name : String) return Boolean;
   procedure Delete_Bucket      (V : in out Vault_Type; Name : String);
   --  Newline-separated bucket names.
   function  List_Buckets       (V : Vault_Type) return String;

   --  The object's content id (its manifest hash), usable as an S3 ETag; "" if
   --  the object is absent.
   function Object_Etag (V : Vault_Type; Name : String) return String;

   --  Newline-separated list of stored object names.
   function Object_Names (V : Vault_Type) return String;

   --  Result of an integrity scrub over every stored object.
   type Scrub_Report is record
      Total           : Natural := 0;  --  objects examined
      Intact          : Natural := 0;  --  already fully redundant
      Repaired        : Natural := 0;  --  had >= 1 shard rebuilt from parity
      Corrupt         : Natural := 0;  --  lost more than M shards: unrepairable
      Shards_Repaired : Natural := 0;  --  total shard files rebuilt
   end record;

   --  Scrub and self-heal: verify every object's manifest and chunks against
   --  their digests and rebuild any missing or corrupt shard from parity, in
   --  place, restoring full redundancy. Needs no key (operates on cipher text).
   --  Repair rewrites bit-identical content-addressed shards, so it preserves
   --  immutability and is safe to run on a sealed vault.
   function Scrub (V : Vault_Type) return Scrub_Report;

   --  Reclaim chunks and manifests not referenced by any live object (including
   --  composite parts) or in-flight upload. Returns the number of manifests and
   --  chunk directories removed.
   function Collect_Garbage (V : in out Vault_Type) return Natural;

   --  Attempt to delete Name. Returns True iff retention permitted it (Bypass
   --  only helps in Governance mode). The outcome is recorded in the audit chain.
   function Delete_Object
     (V : in out Vault_Type; Name : String; Bypass : Boolean) return Boolean;

   --  Advance trusted time from a clock sample. A detected anomaly seals the
   --  vault and is recorded in the audit chain.
   procedure Tick_Clock
     (V            : in out Vault_Type;
      Mono         : Trusted_Time;
      Realtime     : Trusted_Time;
      Boot_Changed : Boolean);

   --  Advance trusted time by sampling the real system clocks (monotonic and
   --  realtime) through the platform boundary.
   procedure Tick_From_System (V : in out Vault_Type);

   --  Operator-initiated seal: the vault becomes read-only (air-gap seal). A
   --  clock anomaly also seals the vault. While sealed, Put_Object and
   --  Delete_Object raise Vault_Sealed. Sealing is recorded in the audit chain
   --  and persisted.
   procedure Seal (V : in out Vault_Type);

   --  Air-gap controls (all persisted):
   --   One-way ingest: data can enter but not leave; Get_Object raises
   --     Egress_Denied while enabled.
   --   Sync window: while closed, writes (store, multipart) raise Sync_Closed,
   --     so transfers happen only in an approved window the operator opens.
   procedure Set_One_Way_Ingest (V : in out Vault_Type; Enabled : Boolean);
   function  One_Way_Ingest (V : Vault_Type) return Boolean;
   procedure Open_Sync_Window  (V : in out Vault_Type);
   procedure Close_Sync_Window (V : in out Vault_Type);
   function  Sync_Window_Open  (V : Vault_Type) return Boolean;

   --  Technology break: copy the whole store to an independent destination
   --  (a different media class), yielding a self-contained, openable vault.
   procedure Export (V : Vault_Type; Dest : String);

   --  Legal hold: an indefinite hold that blocks deletion of an object
   --  regardless of its retention mode or expiry, until released. Persisted.
   procedure Set_Legal_Hold     (V : in out Vault_Type; Name : String);
   procedure Release_Legal_Hold (V : in out Vault_Type; Name : String);
   function  Has_Legal_Hold     (V : Vault_Type; Name : String) return Boolean;

   function Now    (V : Vault_Type) return Trusted_Time;

   --  True if sealed for any reason (operator seal or detected clock anomaly).
   function Sealed (V : Vault_Type) return Boolean;

   --  Audit chain: number of entries, and an independent self-verification.
   function Audit_Length   (V : Vault_Type) return Natural;
   function Audit_Verifies (V : Vault_Type) return Boolean;

   --  Sign a checkpoint over the current audit head (its seq and hash) with the
   --  vault's Ed25519 checkpoint key and write it durably to
   --  <root>/vault.checkpoint. An auditor who knows the public key can then
   --  confirm, out of band, that the persisted chain head is authentic.
   procedure Make_Checkpoint (V : Vault_Type);

   --  Hex of the Ed25519 public key used to sign checkpoints (publish once).
   function Checkpoint_Public_Key (V : Vault_Type) return String;

private

   type State;
   type State_Access is access State;

   type Vault_Type is limited record
      Self : State_Access := null;
   end record;

end Dezhan.Vault;
