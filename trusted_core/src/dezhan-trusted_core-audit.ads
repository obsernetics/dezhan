--  Audit Chain: third unit of the SPARK trusted core.
--
--  An append-only, hash-chained log. Each entry carries the hash of the
--  previous entry, so altering any past record breaks the link to its
--  successor. This enforces the spec's mandatory invariant: "past audit records
--  cannot be altered undetected" (docs/SPEC.md, Trusted Core, Audit Chain).
--
--  Structural tamper-evidence is proved here. The proof rests on one explicit
--  cryptographic assumption (Assume_Hash_Binds): that an entry's hash binds its
--  hashed fields, i.e. equal hashes imply equal fields. That assumption folds
--  together SHA-256 collision resistance and the injectivity of the fixed-layout
--  serialization; neither is provable, both are standard. See docs/NOTES.md.
--
--  Out of scope this cycle: signed checkpoints (Ed25519 + key management), the
--  on-disk format, and the standalone independent verifier tool.
with Dezhan.Trusted_Core.Times;   use Dezhan.Trusted_Core.Times;
with Dezhan.Trusted_Core.Hashing; use Dezhan.Trusted_Core.Hashing;
package Dezhan.Trusted_Core.Audit with SPARK_Mode is

   type Audit_Event is
     (Genesis, Lock_Created, Retention_Extended, Delete_Denied,
      Delete_Allowed, Clock_Anomaly, Seal_Engaged,
      Legal_Hold_Set, Legal_Hold_Released, Object_Quarantined);

   subtype Seq_Number is Natural;

   Zero_Digest : constant Digest := (others => 0);

   type Audit_Entry is record
      Seq       : Seq_Number   := 0;
      Time      : Trusted_Time := 0;
      Kind      : Audit_Event  := Genesis;
      Subject   : Digest       := Zero_Digest;   --  identifies the object
      Detail    : Trusted_Time := 0;             --  e.g. retain-until
      Prev_Hash : Digest       := Zero_Digest;
      Hash      : Digest       := Zero_Digest;
   end record;

   --  Hash of an entry's hashed fields. The stored Hash field is deliberately
   --  NOT an input, so Compute_Hash is provably independent of it: setting an
   --  entry's Hash cannot change its computed hash. Fields are serialized in a
   --  fixed byte layout (Seq, Time, Kind, Subject, Detail, Prev_Hash) and SHA-256
   --  is taken over the result.
   function Hash_Of
     (Seq       : Seq_Number;
      Time      : Trusted_Time;
      Kind      : Audit_Event;
      Subject   : Digest;
      Detail    : Trusted_Time;
      Prev_Hash : Digest) return Digest;

   function Compute_Hash (E : Audit_Entry) return Digest is
     (Hash_Of (E.Seq, E.Time, E.Kind, E.Subject, E.Detail, E.Prev_Hash));

   --  An entry whose stored Hash matches its computed hash.
   function Self_Consistent (E : Audit_Entry) return Boolean is
     (E.Hash = Compute_Hash (E));

   --  Equality of the hashed fields (the Hash field itself excluded).
   function Hashed_Fields_Eq (A, B : Audit_Entry) return Boolean is
     (A.Seq = B.Seq and then A.Time = B.Time and then A.Kind = B.Kind
      and then A.Subject = B.Subject and then A.Detail = B.Detail
      and then A.Prev_Hash = B.Prev_Hash);

   --  A valid genesis head: sequence 0, no predecessor, correct hash.
   function Is_Genesis (E : Audit_Entry) return Boolean is
     (E.Seq = 0 and then E.Kind = Genesis
      and then E.Prev_Hash = Zero_Digest
      and then E.Hash = Compute_Hash (E));

   --  E correctly follows P in the chain.
   function Links_To (E, P : Audit_Entry) return Boolean is
     (E.Seq = P.Seq + 1
      and then E.Prev_Hash = P.Hash
      and then E.Hash = Compute_Hash (E))
     with Pre => P.Seq < Natural'Last;

   function Genesis_Entry (Time : Trusted_Time) return Audit_Entry
     with Post => Is_Genesis (Genesis_Entry'Result)
                  and then Genesis_Entry'Result.Time = Time;

   function Append
     (Prev    : Audit_Entry;
      Time    : Trusted_Time;
      Kind    : Audit_Event;
      Subject : Digest;
      Detail  : Trusted_Time) return Audit_Entry
     with Pre  => Prev.Seq < Natural'Last,
          Post => Append'Result.Seq = Prev.Seq + 1
                  and then Append'Result.Prev_Hash = Prev.Hash
                  and then Append'Result.Kind = Kind
                  and then Append'Result.Time = Time
                  and then Append'Result.Subject = Subject
                  and then Append'Result.Detail = Detail
                  and then Self_Consistent (Append'Result)
                  and then Links_To (Append'Result, Prev);

   type Chain is array (Natural range <>) of Audit_Entry;

   --  Executable whole-chain verification (used by the independent verifier and
   --  the tests): genesis head plus a valid link at every step.
   function Verify_Chain (C : Chain) return Boolean
     with Pre => C'Last < Natural'Last;

   --  The cryptographic assumption: an entry's hash binds its hashed fields.
   --  Equal hashes imply equal fields. Not provable; this is where the proof
   --  depends on SHA-256 collision resistance and serialization injectivity.
   procedure Assume_Hash_Binds (A, B : Audit_Entry)
     with Ghost,
          Global => null,
          Post => (if Compute_Hash (A) = Compute_Hash (B)
                   then Hashed_Fields_Eq (A, B));

   --  Tamper-evidence (the mandatory invariant), proved: you cannot alter a
   --  past entry without breaking the link to its successor. If P and a tampered
   --  P' are both self-consistent, P' differs from P in some hashed field, and
   --  E links to P, then E does not link to P'.
   procedure Lemma_Tamper_Breaks_Link (P, P_Tampered, E : Audit_Entry)
     with Ghost,
          Global => null,
          Pre  => P.Seq < Natural'Last
                  and then P_Tampered.Seq < Natural'Last
                  and then Self_Consistent (P)
                  and then Self_Consistent (P_Tampered)
                  and then Links_To (E, P)
                  and then not Hashed_Fields_Eq (P, P_Tampered),
          Post => not Links_To (E, P_Tampered);

end Dezhan.Trusted_Core.Audit;
