pragma Ada_2022;
with Ada.Text_IO;      use Ada.Text_IO;
with Ada.Command_Line; use Ada.Command_Line;
with Dezhan.Sigv4;     use Dezhan.Sigv4;

--  Validates the SigV4 signing core against the AWS-documented worked example
--  (secret wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY, 20150830/us-east-1/iam).
procedure Test_Sigv4 is

   Failures : Natural := 0;
   LF       : constant String := (1 => ASCII.LF);

   procedure Check (Cond : Boolean; Msg : String) is
   begin
      if Cond then
         Put_Line ("ok   - " & Msg);
      else
         Put_Line ("FAIL - " & Msg);
         Failures := Failures + 1;
      end if;
   end Check;

   Secret : constant String := "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

   String_To_Sign : constant String :=
     "AWS4-HMAC-SHA256" & LF
     & "20150830T123600Z" & LF
     & "20150830/us-east-1/iam/aws4_request" & LF
     & "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59";

   Expected : constant String :=
     "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7";

   Got : constant String :=
     Signature (Secret, "20150830", "us-east-1", "iam", String_To_Sign);

begin
   Check (Got = Expected, "SigV4 signature matches the AWS worked example");
   if Got /= Expected then
      Put_Line ("   expected " & Expected);
      Put_Line ("   got      " & Got);
   end if;

   --  Determinism / self-consistency.
   Check (Signature (Secret, "20150830", "us-east-1", "iam", String_To_Sign) = Got,
          "signing is deterministic");
   Check (Signature (Secret, "20150830", "us-east-1", "s3", String_To_Sign) /= Got,
          "different service yields a different signature");

   New_Line;
   if Failures = 0 then
      Put_Line ("ALL TESTS PASSED");
   else
      Put_Line ("FAILURES:" & Failures'Image);
      Set_Exit_Status (Failure);
   end if;
end Test_Sigv4;
