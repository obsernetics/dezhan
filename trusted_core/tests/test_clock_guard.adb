pragma Ada_2022;
with Ada.Text_IO;      use Ada.Text_IO;
with Ada.Command_Line; use Ada.Command_Line;
with Dezhan.Trusted_Core.Times;       use Dezhan.Trusted_Core.Times;
with Dezhan.Trusted_Core.Clock_Guard; use Dezhan.Trusted_Core.Clock_Guard;
with Dezhan.Trusted_Core.Retention;   use Dezhan.Trusted_Core.Retention;

--  Behavioural safety net for the Clock Integrity Guard. The invariants are
--  *proved* by gnatprove; these tests guard observable behaviour and document
--  the intended semantics, including the cross-module immutability guarantee.
procedure Test_Clock_Guard is

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

   Tol : constant Trusted_Time := 2;

begin
   --  Init: trusted time starts at the epoch.
   declare
      S0 : constant Guard_State :=
        Init ((Mono => 1000, Realtime => 5000, Boot_Changed => False));
   begin
      Check (Now (S0) = 0,            "init: trusted time starts at 0");
      Check (not Is_Sealed (S0),      "init: not sealed");
   end;

   --  Normal advance: trusted time tracks the monotonic delta.
   declare
      S0 : constant Guard_State :=
        Init ((Mono => 1000, Realtime => 5000, Boot_Changed => False));
      S1 : constant Guard_State :=
        Tick (S0, (Mono => 1010, Realtime => 5010, Boot_Changed => False), Tol);
   begin
      Check (Now (S1) = 10,          "normal: floor advances by monotonic delta");
      Check (S1.Anomaly = None,      "normal: no anomaly");
      Check (not Is_Sealed (S1),     "normal: not sealed");
   end;

   --  Forward jump of the UNTRUSTED realtime clock must NOT advance trusted time.
   declare
      S0 : constant Guard_State :=
        Init ((Mono => 1000, Realtime => 5000, Boot_Changed => False));
      S1 : constant Guard_State :=
        Tick (S0, (Mono => 1010, Realtime => 5010, Boot_Changed => False), Tol);
      SJ : constant Guard_State :=
        Tick (S1, (Mono => 1020, Realtime => 9_999_999, Boot_Changed => False), Tol);
   begin
      Check (Now (SJ) = 20,          "forward-jump: floor unchanged by realtime jump");
      Check (SJ.Anomaly = Forward_Jump, "forward-jump: detected");
      Check (Is_Sealed (SJ),         "forward-jump: vault sealed (fail-closed)");
   end;

   --  Realtime rollback detected and sealed.
   declare
      S0 : constant Guard_State :=
        Init ((Mono => 1000, Realtime => 5000, Boot_Changed => False));
      S1 : constant Guard_State :=
        Tick (S0, (Mono => 1010, Realtime => 5010, Boot_Changed => False), Tol);
      SR : constant Guard_State :=
        Tick (S1, (Mono => 1020, Realtime => 1, Boot_Changed => False), Tol);
   begin
      Check (Now (SR) = 20,          "rollback: floor still advances by monotonic");
      Check (SR.Anomaly = Rollback,  "rollback: detected");
      Check (Is_Sealed (SR),         "rollback: sealed");
   end;

   --  Reboot (monotonic reset): conservative zero elapsed, flagged, NOT sealed.
   declare
      S0 : constant Guard_State :=
        Init ((Mono => 1000, Realtime => 5000, Boot_Changed => False));
      S1 : constant Guard_State :=
        Tick (S0, (Mono => 1010, Realtime => 5010, Boot_Changed => False), Tol);
      SB : constant Guard_State :=
        Tick (S1, (Mono => 5, Realtime => 90_000, Boot_Changed => True), Tol);
   begin
      Check (Now (SB) = Now (S1),    "reboot: floor unchanged (assume no time passed)");
      Check (SB.Anomaly = Monotonic_Reset, "reboot: flagged as monotonic reset");
      Check (not Is_Sealed (SB),     "reboot: not sealed (reboot is normal)");
   end;

   --  Seal latches across subsequent normal ticks.
   declare
      S0 : constant Guard_State :=
        Init ((Mono => 1000, Realtime => 5000, Boot_Changed => False));
      SJ : constant Guard_State :=
        Tick (S0, (Mono => 1010, Realtime => 9_999_999, Boot_Changed => False), Tol);
      SN : constant Guard_State :=
        Tick (SJ, (Mono => 1020, Realtime => 9_999_999 + 10, Boot_Changed => False), Tol);
   begin
      Check (Is_Sealed (SJ) and then Is_Sealed (SN),
             "seal latches across later ticks");
   end;

   --  Integration: a realtime forward jump cannot expire a compliance lock.
   declare
      No_Auth : constant Authorization := (Bypass_Governance => False);
      --  Establish trusted time, create a 100s compliance lock.
      S0   : constant Guard_State :=
        Init ((Mono => 1000, Realtime => 5000, Boot_Changed => False));
      S1   : constant Guard_State :=
        Tick (S0, (Mono => 1010, Realtime => 5010, Boot_Changed => False), Tol);
      T1   : constant Trusted_Time := Now (S1);                 --  = 10
      Lock : constant Retention_Lock := Create_Lock (Compliance, T1 + 100, T1);
      --  Attacker slams the realtime clock far past the retention point...
      S2   : constant Guard_State :=
        Tick (S1, (Mono => 1015, Realtime => 10_000_000, Boot_Changed => False), Tol);
   begin
      Check (Now (S2) = 15,          "integration: trusted time ignored the clock attack");
      Check (not Can_Delete (Lock, Now (S2), No_Auth),
             "integration: compliance lock NOT deletable despite forward clock jump");
   end;

   New_Line;
   if Failures = 0 then
      Put_Line ("ALL TESTS PASSED");
   else
      Put_Line ("FAILURES:" & Failures'Image);
      Set_Exit_Status (Failure);
   end if;
end Test_Clock_Guard;
