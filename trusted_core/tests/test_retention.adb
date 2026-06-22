pragma Ada_2022;
with Ada.Text_IO;      use Ada.Text_IO;
with Ada.Command_Line; use Ada.Command_Line;
with Dezhan.Trusted_Core.Times;     use Dezhan.Trusted_Core.Times;
with Dezhan.Trusted_Core.Retention; use Dezhan.Trusted_Core.Retention;

--  Behavioural safety net for the Retention State Machine. The invariants are
--  *proved* by gnatprove; these tests guard against regressions in observable
--  behaviour and document the intended semantics.
procedure Test_Retention is

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

   No_Auth : constant Authorization := (Bypass_Governance => False);
   Bypass  : constant Authorization := (Bypass_Governance => True);

begin
   --  Create
   declare
      L : constant Retention_Lock := Create_Lock (Compliance, 1000, 100);
   begin
      Check (L.Mode = Compliance,    "create sets mode");
      Check (L.Retain_Until = 1000,  "create sets retain_until");
      Check (L.Created_At = 100,     "create sets created_at");
   end;

   --  Extend never shortens (the core invariant)
   declare
      L  : constant Retention_Lock := Create_Lock (Compliance, 1000, 100);
      E1 : constant Retention_Lock := Extend_Retention (L, 2000);
      E2 : constant Retention_Lock := Extend_Retention (L, 500);
   begin
      Check (E1.Retain_Until = 2000,        "extend forward increases expiry");
      Check (E2.Retain_Until = 1000,        "extend backward is ignored");
      Check (E2.Retain_Until >= L.Retain_Until, "retention is monotonic non-decreasing");
      Check (E1.Mode = L.Mode and E1.Created_At = L.Created_At,
                                            "extend preserves mode and created_at");
   end;

   --  Request_Extension reports acceptance correctly
   declare
      L  : constant Retention_Lock   := Create_Lock (Governance, 1000, 100);
      R1 : constant Extension_Result := Request_Extension (L, 1500);
      R2 : constant Extension_Result := Request_Extension (L, 800);
   begin
      Check (R1.Accepted and R1.Lock.Retain_Until = 1500,
             "request to extend forward is accepted");
      Check ((not R2.Accepted) and R2.Lock.Retain_Until = 1000,
             "request to shorten is rejected, lock unchanged");
   end;

   --  Compliance deletion is absolute: not even a bypass works before expiry
   declare
      L : constant Retention_Lock := Create_Lock (Compliance, 1000, 100);
   begin
      Check (not Can_Delete (L, 999, No_Auth),
             "compliance: cannot delete before expiry");
      Check (not Can_Delete (L, 999, Bypass),
             "compliance: bypass CANNOT delete before expiry");
      Check (Can_Delete (L, 1000, No_Auth),
             "compliance: can delete at expiry");
      Check (Can_Delete (L, 2000, No_Auth),
             "compliance: can delete after expiry");
   end;

   --  Governance deletion: audited bypass is permitted
   declare
      L : constant Retention_Lock := Create_Lock (Governance, 1000, 100);
   begin
      Check (not Can_Delete (L, 999, No_Auth),
             "governance: cannot delete before expiry without bypass");
      Check (Can_Delete (L, 999, Bypass),
             "governance: bypass deletes before expiry");
      Check (Can_Delete (L, 1000, No_Auth),
             "governance: can delete at expiry");
   end;

   New_Line;
   if Failures = 0 then
      Put_Line ("ALL TESTS PASSED");
   else
      Put_Line ("FAILURES:" & Failures'Image);
      Set_Exit_Status (Failure);
   end if;
end Test_Retention;
