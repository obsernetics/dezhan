--  Clock Integrity Guard: second unit of the SPARK trusted core.
--
--  Produces the Trusted_Time consumed by the Retention State Machine while
--  enforcing the spec's mandatory invariant: "System time manipulation cannot
--  invalidate active locks." (docs/SPEC.md → Clock Integrity Guard.)
--
--  Trusted time advances ONLY by elapsed time from a monotonic source; the
--  untrusted realtime clock is used solely for anomaly detection and never
--  affects the time value that gates retention. The trusted-time value is
--  therefore provably independent of the realtime clock (see
--  Lemma_Realtime_Independent). Policy is fail-closed toward immutability: time
--  never advances past the trusted monotonic bound, and detected manipulation
--  latches a seal.
--
--  This package is pure: clock reads and durable persistence of Guard_State
--  live behind the audited, non-SPARK boundary (Dezhan.Platform.Clock).
with Dezhan.Trusted_Core.Times; use Dezhan.Trusted_Core.Times;
package Dezhan.Trusted_Core.Clock_Guard with SPARK_Mode is

   type Anomaly_Kind is (None, Monotonic_Reset, Rollback, Forward_Jump);

   type Guard_State is record
      Floor     : Trusted_Time := 0;    --  monotonic non-decreasing trusted time
      Last_Mono : Trusted_Time := 0;    --  last monotonic-source reading
      Last_Real : Trusted_Time := 0;    --  last realtime reading (detection only)
      Anomaly   : Anomaly_Kind := None;
      Sealed    : Boolean      := False;
   end record;

   --  A reading taken at the untrusted boundary. Realtime is NOT trusted.
   type Clock_Sample is record
      Mono         : Trusted_Time := 0;
      Realtime     : Trusted_Time := 0;
      Boot_Changed : Boolean      := False;  --  monotonic source reset (reboot)
   end record;

   --  Monotonic elapsed time implied by a sample. Zero across a reboot or an
   --  impossible backward monotonic reading (both handled conservatively).
   function Mono_Delta (S : Guard_State; Sample : Clock_Sample) return Trusted_Time
   is
     (if Sample.Boot_Changed or else Sample.Mono < S.Last_Mono
      then 0
      else Sample.Mono - S.Last_Mono);

   --  Trusted time after a tick: advance by the monotonic delta, saturating at
   --  'Last so no overflow can occur. Depends only on S and the monotonic
   --  inputs of Sample, never on Realtime.
   function Advanced_Floor (S : Guard_State; Sample : Clock_Sample) return Trusted_Time
   is
     (if S.Floor <= Trusted_Time'Last - Mono_Delta (S, Sample)
      then S.Floor + Mono_Delta (S, Sample)
      else Trusted_Time'Last);

   --  Initialise from the first reading. Floor starts at the epoch (0).
   function Init (Sample : Clock_Sample) return Guard_State
   with
     Post => Init'Result.Floor = 0
             and then Init'Result.Last_Mono = Sample.Mono
             and then Init'Result.Last_Real = Sample.Realtime
             and then Init'Result.Anomaly = None
             and then not Init'Result.Sealed;

   --  Process a new reading.
   function Tick
     (S         : Guard_State;
      Sample    : Clock_Sample;
      Tolerance : Trusted_Time) return Guard_State
   with
     Post =>
       --  (1) exact value: trusted time is a function of the monotonic inputs
       Tick'Result.Floor = Advanced_Floor (S, Sample)
       --  (2) monotonic non-decreasing
       and then Tick'Result.Floor >= S.Floor
       --  (3) advance bounded by the monotonic delta (realtime cannot inflate)
       and then Tick'Result.Floor - S.Floor <= Mono_Delta (S, Sample)
       --  (4) the seal latches
       and then (if S.Sealed then Tick'Result.Sealed)
       and then Tick'Result.Last_Mono = Sample.Mono
       and then Tick'Result.Last_Real = Sample.Realtime;

   function Now (S : Guard_State) return Trusted_Time is (S.Floor);

   function Is_Sealed (S : Guard_State) return Boolean is (S.Sealed);

   --  Formal statement of the mandatory invariant: the trusted-time value is
   --  independent of the untrusted realtime clock (and of Tolerance). Two
   --  samples that agree on the monotonic inputs yield the same Floor, no matter
   --  what the realtime clock says. Hence manipulating system time cannot move
   --  trusted time forward to expire a lock.
   procedure Lemma_Realtime_Independent
     (S          : Guard_State;
      A, B       : Clock_Sample;
      Tol_A, Tol_B : Trusted_Time)
   with
     Ghost,
     Global => null,
     Pre    => A.Mono = B.Mono and then A.Boot_Changed = B.Boot_Changed,
     Post   => Tick (S, A, Tol_A).Floor = Tick (S, B, Tol_B).Floor;

end Dezhan.Trusted_Core.Clock_Guard;
