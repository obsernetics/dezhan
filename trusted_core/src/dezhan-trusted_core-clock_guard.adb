package body Dezhan.Trusted_Core.Clock_Guard with SPARK_Mode is

   function Init (Sample : Clock_Sample) return Guard_State is
   begin
      return (Floor     => 0,
              Last_Mono => Sample.Mono,
              Last_Real => Sample.Realtime,
              Anomaly   => None,
              Sealed    => False);
   end Init;

   function Tick
     (S         : Guard_State;
      Sample    : Clock_Sample;
      Tolerance : Trusted_Time) return Guard_State
   is
      Delta_T  : constant Trusted_Time := Mono_Delta (S, Sample);
      Result   : Guard_State := S;
      Expected : Trusted_Time;
   begin
      --  Advance trusted time by the monotonic delta only (saturating). This is
      --  exactly Advanced_Floor; realtime never enters this computation.
      Result.Floor :=
        (if S.Floor <= Trusted_Time'Last - Delta_T
         then S.Floor + Delta_T
         else Trusted_Time'Last);
      Result.Last_Mono := Sample.Mono;
      Result.Last_Real := Sample.Realtime;

      --  Anomaly detection from the UNTRUSTED realtime clock. This affects only
      --  the Anomaly/Sealed flags, never Floor. Expected realtime is the
      --  previous realtime plus the trusted monotonic delta (saturating).
      Expected :=
        (if S.Last_Real <= Trusted_Time'Last - Delta_T
         then S.Last_Real + Delta_T
         else Trusted_Time'Last);

      if Sample.Boot_Changed then
         --  A reboot is normal; we conservatively assumed zero elapsed time.
         --  Not treated as manipulation, so it does not seal.
         Result.Anomaly := Monotonic_Reset;
      elsif Sample.Mono < S.Last_Mono then
         --  Monotonic clock went backwards: impossible without tampering.
         Result.Anomaly := Rollback;
      elsif Sample.Realtime > Expected
        and then Sample.Realtime - Expected > Tolerance
      then
         Result.Anomaly := Forward_Jump;
      elsif Sample.Realtime < Expected
        and then Expected - Sample.Realtime > Tolerance
      then
         Result.Anomaly := Rollback;
      else
         Result.Anomaly := None;
      end if;

      --  Fail-closed: active manipulation latches the seal. The seal is never
      --  cleared here once set (this tick or a prior one).
      if Result.Anomaly = Rollback or else Result.Anomaly = Forward_Jump then
         Result.Sealed := True;
      end if;
      if S.Sealed then
         Result.Sealed := True;
      end if;

      return Result;
   end Tick;

   procedure Lemma_Realtime_Independent
     (S          : Guard_State;
      A, B       : Clock_Sample;
      Tol_A, Tol_B : Trusted_Time)
   is
   begin
      --  Proof-only. Follows from Tick's postcondition (Floor = Advanced_Floor)
      --  and the fact that Advanced_Floor/Mono_Delta depend only on S and the
      --  monotonic inputs, which A and B share.
      null;
   end Lemma_Realtime_Independent;

end Dezhan.Trusted_Core.Clock_Guard;
