--  Content-addressed store (CAS).
--
--  An object is split into fixed-size chunks; each chunk is stored on disk under
--  its SHA-256 (so identical chunks deduplicate). A manifest lists the object
--  length and the ordered chunk digests; the manifest's own SHA-256 is the
--  object id. Reads verify every chunk against its digest and the manifest
--  against the requested id, so silent corruption is detected (Merkle-style
--  integrity). Objects are immutable: a different object yields a different id.
--
--  This is regular Ada (file I/O); the hash it relies on is the SPARK-verified
--  Dezhan.Trusted_Core.Hashing.SHA256. Large-object multi-level manifests and
--  content-defined chunking are future work (see docs/NOTES.md).
with Ada.Streams; use Ada.Streams;
with Dezhan.Trusted_Core.Cipher; use Dezhan.Trusted_Core.Cipher;
package Dezhan.Storage.Cas with SPARK_Mode => Off is

   --  One chunk is one erasure block. The proven crypto/erasure core caps a
   --  block at Max_Data(8) * Max_Shard_Length(1024) = 8192 bytes and SHA-256 at
   --  Max_Message = 8192, so 8192 is the largest chunk the verified core admits.
   --  Larger chunks mean fewer chunks -> fewer shard files and erasure calls.
   Chunk_Size : constant := 8192;

   --  Object id: 64 lowercase hex characters (the manifest's SHA-256).
   subtype Object_Id is String (1 .. 64);

   --  Raised by Get/Verify when stored bytes do not match their digest.
   Corruption_Detected : exception;

   --  Raised by Get when the object's keyed authentication tag does not verify:
   --  a wrong key, a missing tag, or tampering with the stored object.
   Auth_Failed : exception;

   --  Raised by Put when the object exceeds the current single-manifest limit.
   Object_Too_Large : exception;

   --  Create the on-disk layout under Root (objects/ and manifests/).
   procedure Initialize (Root : String);

   --  Store Data encrypted at source under Key; returns its object id. Each
   --  chunk is encrypted with ChaCha20 before being hashed and written, so the
   --  bytes on disk are ciphertext. Idempotent for a given Key: the same bytes
   --  and key give the same id and reuse existing chunks.
   function Put
     (Root : String; Key : Key_256; Data : Stream_Element_Array)
      return Object_Id;

   --  Reassemble and decrypt the object for Id, verifying the manifest and every
   --  (cipher-text) chunk against its digest before decrypting.
   function Get
     (Root : String; Key : Key_256; Id : Object_Id)
      return Stream_Element_Array;

   --  Scrub: True iff the manifest and all chunks are present and intact. Checks
   --  cipher-text integrity, so it needs no key.
   function Verify (Root : String; Id : Object_Id) return Boolean;

   --  Outcome of repairing one object's redundancy.
   type Repair_Result is record
      Recoverable     : Boolean := True;  --  every blob still had >= K shards
      Shards_Repaired : Natural := 0;     --  shard files rebuilt from parity
   end record;

   --  Rebuild any missing or corrupt shard of the manifest and each chunk from
   --  the surviving shards, restoring full redundancy in place. Needs no key
   --  (operates on cipher text). Recoverable is False if any blob lost more than
   --  M shards (unrepairable); shards already intact are left untouched.
   function Repair (Root : String; Id : Object_Id) return Repair_Result;

   --  A list of live object ids (manifest ids) to retain during collection.
   type Id_List is array (Positive range <>) of Object_Id;

   --  Garbage-collect: delete every manifest and chunk not reachable from a live
   --  id. Shared chunks are retained while any live object references them.
   --  Reclaimed counts the manifests and chunk directories removed.
   procedure Collect_Garbage
     (Root : String; Live : Id_List; Reclaimed : out Natural);

end Dezhan.Storage.Cas;
