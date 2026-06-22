pragma Ada_2022;
with Ada.Text_IO;      use Ada.Text_IO;
with Ada.Command_Line; use Ada.Command_Line;
with Dezhan.Trusted_Core.Times;   use Dezhan.Trusted_Core.Times;
with Dezhan.Trusted_Core.Hashing; use Dezhan.Trusted_Core.Hashing;
with Dezhan.Trusted_Core.Audit;   use Dezhan.Trusted_Core.Audit;

--  Behavioural safety net for the Audit Chain. The per-link tamper-evidence is
--  proved by gnatprove (Lemma_Tamper_Breaks_Link); these tests demonstrate the
--  end-to-end chain behaviour, including that tampering with a past entry breaks
--  whole-chain verification.
procedure Test_Audit is

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

   function Subj (N : Byte) return Digest is
      D : Digest := (others => 0);
   begin
      D (0) := N;
      return D;
   end Subj;

   --  Build a small valid chain: genesis, a lock-created event, an extension.
   G  : constant Audit_Entry := Genesis_Entry (Time => 100);
   E1 : constant Audit_Entry :=
     Append (G,  Time => 110, Kind => Lock_Created,
             Subject => Subj (1), Detail => 1000);
   E2 : constant Audit_Entry :=
     Append (E1, Time => 120, Kind => Retention_Extended,
             Subject => Subj (1), Detail => 2000);

   Good : constant Chain := (G, E1, E2);

begin
   --  Structure of a freshly built chain.
   Check (Is_Genesis (G),            "genesis entry is a valid head");
   Check (Links_To (E1, G),          "second entry links to genesis");
   Check (Links_To (E2, E1),         "third entry links to its predecessor");
   Check (E1.Seq = 1 and E2.Seq = 2, "sequence numbers increment");
   Check (Verify_Chain (Good),       "a well-formed chain verifies");

   --  Tampering with a past entry's payload breaks verification.
   declare
      Tampered : Chain := Good;
   begin
      Tampered (1).Detail := 9999;          --  alter a hashed field of E1
      Check (not Verify_Chain (Tampered),
             "tampering with a past entry breaks chain verification");
   end;

   --  Re-hashing the tampered entry does not help: its hash changes, so the
   --  successor's Prev_Hash no longer matches.
   declare
      Tampered : Chain := Good;
   begin
      Tampered (1).Detail := 9999;
      Tampered (1).Hash := Compute_Hash (Tampered (1));  --  attacker re-hashes
      Check (Self_Consistent (Tampered (1)),
             "attacker can make the tampered entry self-consistent");
      Check (not Links_To (Tampered (2), Tampered (1)),
             "but the successor no longer links to it");
      Check (not Verify_Chain (Tampered),
             "so the chain still fails verification");
   end;

   --  A truncated or reordered chain is rejected.
   declare
      Bad : constant Chain := (E1, E2);   --  no genesis head
   begin
      Check (not Verify_Chain (Bad), "a chain without a genesis head is rejected");
   end;

   --  Distinct events hash differently.
   Check (E1.Hash /= E2.Hash, "distinct entries have distinct hashes");

   New_Line;
   if Failures = 0 then
      Put_Line ("ALL TESTS PASSED");
   else
      Put_Line ("FAILURES:" & Failures'Image);
      Set_Exit_Status (Failure);
   end if;
end Test_Audit;
