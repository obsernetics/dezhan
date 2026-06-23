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

   --  Hex_SHA256 of the empty string (NIST vector).
   Check (Hex_SHA256 ("") =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "Hex_SHA256 of empty string matches NIST");

   --  Signature_For: deterministic, and tampering any input changes it.
   declare
      CH : constant String :=
        "host:dezhan" & ASCII.LF & "x-amz-date:20150830T123600Z" & ASCII.LF;
      S1 : constant String :=
        Signature_For (Secret, "PUT", "/v/obj", "", CH, "host;x-amz-date",
                       "UNSIGNED-PAYLOAD", "20150830T123600Z",
                       "20150830", "us-east-1", "s3");
      S2 : constant String :=
        Signature_For (Secret, "PUT", "/v/obj", "", CH, "host;x-amz-date",
                       "UNSIGNED-PAYLOAD", "20150830T123600Z",
                       "20150830", "us-east-1", "s3");
      S3 : constant String :=
        Signature_For (Secret, "DELETE", "/v/obj", "", CH, "host;x-amz-date",
                       "UNSIGNED-PAYLOAD", "20150830T123600Z",
                       "20150830", "us-east-1", "s3");
   begin
      Check (S1 = S2, "Signature_For is deterministic");
      Check (S1 /= S3, "changing the method changes the signature");
   end;

   --  Canonical query: sorted by name, names/values URI-encoded.
   Check (Canonical_Query ("uploads") = "uploads=",
          "valueless query param canonicalizes to name=");
   Check (Canonical_Query ("uploadId=abc-1") = "uploadId=abc-1",
          "simple query param round-trips");
   Check (Canonical_Query ("b=2&a=1") = "a=1&b=2",
          "query params are sorted by name");
   Check (Canonical_Query ("k=a b") = "k=a%20b",
          "query values are URI-encoded");

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
