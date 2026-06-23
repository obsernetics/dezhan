--  Retention State Machine: first unit of the SPARK trusted core.
--
--  Enforces, by formal proof, the spec's mandatory retention invariants
--  (docs/SPEC.md → Trusted Core → Retention State Machine):
--
--    * A retained object can never be deleted before expiry.
--    * A retention period can never be shortened (it may be extended).
--
--  This package is pure logic: no I/O, no clock access, no heap. Time is always
--  supplied by the caller (the Clock Integrity Guard, a later module), so the
--  state machine never reads a system clock. Legal hold is supported: while held,
--  an object cannot be deleted regardless of mode, expiry, or bypass.
with Dezhan.Trusted_Core.Times; use Dezhan.Trusted_Core.Times;
package Dezhan.Trusted_Core.Retention with SPARK_Mode is

   --  Object Lock modes (S3 Object Lock semantics).
   --    Unlocked   - no retention in force.
   --    Governance - retention enforced, but an authorized, audited bypass may
   --                 permit early deletion.
   --    Compliance - retention is absolute; no bypass exists, not even for an
   --                 administrator, until expiry.
   type Lock_Mode is (Unlocked, Governance, Compliance);

   --  Trusted, monotonic time (Dezhan.Trusted_Core.Times) is supplied by the
   --  Clock Integrity Guard. This package only compares times, never adds them.

   --  Per-operation authorization. Bypass_Governance is the audited capability
   --  that, in Governance mode only, permits deletion before expiry.
   type Authorization is record
      Bypass_Governance : Boolean := False;
   end record;

   --  Immutable retention lock state for one object version.
   type Retention_Lock is record
      Mode         : Lock_Mode    := Unlocked;
      Retain_Until : Trusted_Time := 0;
      Created_At   : Trusted_Time := 0;
      Legal_Hold   : Boolean      := False;  --  indefinite hold; blocks deletion
   end record;

   --  Create a lock. The retention point must not already be in the past.
   function Create_Lock
     (Mode         : Lock_Mode;
      Retain_Until : Trusted_Time;
      Now          : Trusted_Time) return Retention_Lock
   with
     Pre  => Mode /= Unlocked and then Retain_Until >= Now,
     Post => Create_Lock'Result.Mode = Mode
             and then Create_Lock'Result.Retain_Until = Retain_Until
             and then Create_Lock'Result.Created_At = Now
             and then not Create_Lock'Result.Legal_Hold;

   --  Extend retention. By construction this CANNOT shorten retention: the new
   --  expiry is max(old, requested). The unconditional postcondition
   --  Retain_Until >= L.Retain_Until is the machine-proved "never shortened"
   --  invariant.
   function Extend_Retention
     (L         : Retention_Lock;
      New_Until : Trusted_Time) return Retention_Lock
   with
     Post => Extend_Retention'Result.Mode = L.Mode
             and then Extend_Retention'Result.Created_At = L.Created_At
             and then Extend_Retention'Result.Legal_Hold = L.Legal_Hold
             and then Extend_Retention'Result.Retain_Until >= L.Retain_Until
             and then Extend_Retention'Result.Retain_Until
                        = Trusted_Time'Max (L.Retain_Until, New_Until);

   --  Result of a requested extension: the (possibly unchanged) lock, plus
   --  whether the request actually moved the expiry forward.
   type Extension_Result is record
      Lock     : Retention_Lock;
      Accepted : Boolean;
   end record;

   function Request_Extension
     (L         : Retention_Lock;
      New_Until : Trusted_Time) return Extension_Result
   with
     Post => Request_Extension'Result.Lock = Extend_Retention (L, New_Until)
             and then Request_Extension'Result.Accepted = (New_Until > L.Retain_Until)
             and then Request_Extension'Result.Lock.Retain_Until >= L.Retain_Until;

   --  Place or release a legal hold. A held object cannot be deleted by anyone.
   function Set_Hold (L : Retention_Lock) return Retention_Lock
   with
     Post => Set_Hold'Result.Legal_Hold
             and then Set_Hold'Result.Mode = L.Mode
             and then Set_Hold'Result.Retain_Until = L.Retain_Until
             and then Set_Hold'Result.Created_At = L.Created_At;

   function Release_Hold (L : Retention_Lock) return Retention_Lock
   with
     Post => not Release_Hold'Result.Legal_Hold
             and then Release_Hold'Result.Mode = L.Mode
             and then Release_Hold'Result.Retain_Until = L.Retain_Until
             and then Release_Hold'Result.Created_At = L.Created_At;

   --  The deletion policy. Its definition IS the enforcement rule. A legal hold
   --  blocks deletion absolutely; otherwise the lock mode and expiry decide.
   function Can_Delete
     (L    : Retention_Lock;
      Now  : Trusted_Time;
      Auth : Authorization) return Boolean
   is
     (if L.Legal_Hold then False
      else (case L.Mode is
               when Unlocked   => True,
               when Compliance => Now >= L.Retain_Until,
               when Governance =>
                 Now >= L.Retain_Until or else Auth.Bypass_Governance));

   --  Proof obligation: in Compliance mode, before expiry, NO authorization can
   --  permit deletion. gnatprove discharges the postcondition from the
   --  definition of Can_Delete; the null body carries no runtime cost.
   procedure Lemma_Compliance_Is_Absolute
     (L    : Retention_Lock;
      Now  : Trusted_Time;
      Auth : Authorization)
   with
     Ghost,
     Global => null,
     Pre    => L.Mode = Compliance and then Now < L.Retain_Until,
     Post   => not Can_Delete (L, Now, Auth);

   --  Proof obligation: a legal hold blocks deletion regardless of mode, time,
   --  or authorization.
   procedure Lemma_Legal_Hold_Is_Absolute
     (L    : Retention_Lock;
      Now  : Trusted_Time;
      Auth : Authorization)
   with
     Ghost,
     Global => null,
     Pre    => L.Legal_Hold,
     Post   => not Can_Delete (L, Now, Auth);

end Dezhan.Trusted_Core.Retention;
