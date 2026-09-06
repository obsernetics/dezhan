pragma Ada_2022;
--  Minimal command-line client for the dezhan server (POC). Talks plain HTTP
--  over GNAT.Sockets; no external dependency. Set DEZHAN_ADDR=host:port to point
--  elsewhere (default 127.0.0.1:8080).
--
--  Usage:
--    dezhan_cli version | --version | -v
--    dezhan_cli health
--    dezhan_cli metrics
--    dezhan_cli put <name> <data> [compliance|governance] [retain_seconds]
--    dezhan_cli sput <name> <data>          (SigV4-signed PUT)
--    dezhan_cli get <name>
--    dezhan_cli del <name> [bypass]
--
--  Exit status mirrors the server's HTTP status: 0 on a 2xx response, non-zero
--  on anything else (e.g. a 403 for a retention-blocked delete, a 404 for a
--  missing object), so a refusal is distinguishable from success in a script.
with Ada.Text_IO;          use Ada.Text_IO;
with Ada.Command_Line;     use Ada.Command_Line;
with Ada.Strings.Fixed;    use Ada.Strings.Fixed;
with Ada.Environment_Variables;
with Ada.Exceptions;       use Ada.Exceptions;
with GNAT.Sockets;         use GNAT.Sockets;
with Dezhan.Sigv4;

procedure Dezhan_Cli is

   CRLF : constant String := ASCII.CR & ASCII.LF;
   LF   : constant String := (1 => ASCII.LF);

   --  Product version, printed by `dezhan_cli version` / `--version` / `-v`.
   --  On a release build scripts/stamp-version.sh overwrites this literal with
   --  the release tag, so a released binary always reports its own version.
   Version : constant String := "1.1.0";

   Usage : constant String :=
     "usage: dezhan_cli <command>" & LF
     & "  version                                 print the client version" & LF
     & "  health                                  server health (ok / sealed)" & LF
     & "  metrics                                 Prometheus metrics" & LF
     & "  put <name> <data> [compliance|governance] [retain_s]  store an object" & LF
     & "  sput <name> <data>                      SigV4-signed put" & LF
     & "  get <name>                              retrieve an object" & LF
     & "  del <name> [bypass]                     delete if retention allows" & LF
     & "Set DEZHAN_ADDR=host:port (default 127.0.0.1:8080). Exit status mirrors"
     & " the server's HTTP status.";

   --  SigV4 credential, taken from the environment (never hardcode a secret in
   --  a client). The defaults match the server's demo credential so a local
   --  POC works out of the box; set DEZHAN_ACCESS_KEY / DEZHAN_SECRET (and
   --  optionally DEZHAN_REGION / DEZHAN_SERVICE) for any real use.
   --
   --  Region and Service are SigV4 credential-scope labels (date/region/service/
   --  aws4_request) that the signing algorithm requires; every S3 client sends
   --  them. For an on-prem vault they carry no geographic meaning, they only have
   --  to match what the signature is computed over (the server uses the values
   --  from the client's own Authorization header), so the defaults are arbitrary.
   function Env (Name, Default : String) return String is
     (if Ada.Environment_Variables.Exists (Name)
      then Ada.Environment_Variables.Value (Name) else Default);

   AKID    : constant String := Env ("DEZHAN_ACCESS_KEY", "dezhanadmin");
   Secret  : constant String := Env ("DEZHAN_SECRET", "dezhandemosecretkey0123456789");
   Region  : constant String := Env ("DEZHAN_REGION", "us-east-1");
   Service : constant String := Env ("DEZHAN_SERVICE", "s3");

   function Env_Addr return String is
     (if Ada.Environment_Variables.Exists ("DEZHAN_ADDR")
      then Ada.Environment_Variables.Value ("DEZHAN_ADDR")
      else "127.0.0.1:8080");

   --  Send Request; stream the response body to stdout and reflect the HTTP
   --  status in the process exit code. A non-2xx status (e.g. a 403 for a
   --  retention-blocked delete, or a 404 for a missing object) sets a failure
   --  exit code so scripts can tell success from a refusal. The body is
   --  streamed rather than buffered, so a large object is not truncated.
   procedure Round_Trip (Request : String) is
      Addr   : constant String  := Env_Addr;
      Colon  : constant Natural := Index (Addr, ":");
      Host   : constant String  := Addr (Addr'First .. Colon - 1);
      Port   : constant Port_Type := Port_Type'Value (Addr (Colon + 1 .. Addr'Last));
      Sock   : Socket_Type;
      Ch     : Stream_Access;
      C      : Character;
      Status  : Natural := 0;         --  parsed HTTP status code
      Line    : String (1 .. 256);    --  the status line, until first CR/LF
      LLen    : Natural := 0;
      In_Body : Boolean := False;
      Match   : Natural := 0;         --  progress matching CR,LF,CR,LF
   begin
      Create_Socket (Sock);
      Connect_Socket (Sock, (Family_Inet, Inet_Addr (Host), Port));
      Ch := Stream (Sock);
      String'Write (Ch, Request);

      begin
         loop
            Character'Read (Ch, C);
            if In_Body then
               Put (C);
            else
               --  Accumulate the status line until its terminating CR/LF, then
               --  parse the numeric code: "HTTP/1.1 200 OK" -> 200.
               if Status = 0 and then C /= ASCII.CR and then C /= ASCII.LF then
                  if LLen < Line'Last then
                     LLen := LLen + 1;
                     Line (LLen) := C;
                  end if;
               elsif Status = 0 and then LLen > 0 then
                  declare
                     S1 : constant Natural := Index (Line (1 .. LLen), " ");
                  begin
                     if S1 > 0 then
                        declare
                           Rest : constant String := Line (S1 + 1 .. LLen);
                           S2   : constant Natural := Index (Rest, " ");
                           Code : constant String :=
                             (if S2 = 0 then Rest else Rest (Rest'First .. S2 - 1));
                        begin
                           if Code'Length = 3 then
                              Status := Natural'Value (Code);
                           end if;
                        exception
                           when others => Status := 0;
                        end;
                     end if;
                  end;
               end if;

               --  End of headers is the CR LF CR LF sequence.
               case Match is
                  when 0 => Match := (if C = ASCII.CR then 1 else 0);
                  when 1 => Match := (if C = ASCII.LF then 2
                                      elsif C = ASCII.CR then 1 else 0);
                  when 2 => Match := (if C = ASCII.CR then 3 else 0);
                  when others =>
                     if C = ASCII.LF then
                        In_Body := True;
                        Match := 0;
                     else
                        Match := (if C = ASCII.CR then 1 else 0);
                     end if;
               end case;
            end if;
         end loop;
      exception
         when others => null;  --  connection closed by server
      end;
      Close_Socket (Sock);
      New_Line;

      if Status < 200 or else Status >= 300 then
         Set_Exit_Status (Failure);
      end if;
   end Round_Trip;

   function Req
     (Method, Path, Headers, Body_Text : String) return String
   is
   begin
      return Method & " " & Path & " HTTP/1.1" & CRLF
        & "Host: dezhan" & CRLF
        & "Connection: close" & CRLF
        & Headers
        & "Content-Length:" & Natural'Image (Body_Text'Length) & CRLF & CRLF
        & Body_Text;
   end Req;

begin
   if Argument_Count = 0 then
      Put_Line (Usage);
      Set_Exit_Status (Failure);
      return;
   end if;

   declare
      Cmd : constant String := Argument (1);
   begin
      if Cmd = "version" or else Cmd = "--version" or else Cmd = "-v" then
         Put_Line ("dezhan_cli " & Version);
      elsif Cmd = "help" or else Cmd = "--help" or else Cmd = "-h" then
         Put_Line (Usage);
      elsif Cmd = "health" then
         Round_Trip (Req ("GET", "/healthz", "", ""));
      elsif Cmd = "metrics" then
         Round_Trip (Req ("GET", "/metrics", "", ""));
      elsif Cmd = "get" and then Argument_Count >= 2 then
         Round_Trip (Req ("GET", "/v/" & Argument (2), "", ""));
      elsif Cmd = "put" and then Argument_Count >= 3 then
         declare
            Mode   : constant String :=
              (if Argument_Count >= 4 then Argument (4) else "compliance");
            Retain : constant String :=
              (if Argument_Count >= 5 then Argument (5) else "3600");
            Headers : constant String :=
              "X-Dezhan-Mode: " & Mode & CRLF
              & "X-Dezhan-Retain: " & Retain & CRLF;
         begin
            Round_Trip (Req ("PUT", "/v/" & Argument (2), Headers, Argument (3)));
         end;
      elsif Cmd = "sput" and then Argument_Count >= 3 then
         --  SigV4-signed PUT (for servers started with DEZHAN_REQUIRE_AUTH).
         declare
            Name     : constant String := Argument (2);
            Data     : constant String := Argument (3);
            Path     : constant String := "/v/" & Name;
            Amz_Date : constant String := "20250101T000000Z";
            S_Date   : constant String := "20250101";
            Pay_Hash : constant String := Dezhan.Sigv4.Hex_SHA256 (Data);
            Signed   : constant String := "host;x-amz-content-sha256;x-amz-date";
            Canon_H  : constant String :=
              "host:dezhan" & LF
              & "x-amz-content-sha256:" & Pay_Hash & LF
              & "x-amz-date:" & Amz_Date & LF;
            Sig      : constant String :=
              Dezhan.Sigv4.Signature_For
                (Secret, "PUT", Path, "", Canon_H, Signed, Pay_Hash,
                 Amz_Date, S_Date, Region, Service);
            Auth     : constant String :=
              "AWS4-HMAC-SHA256 Credential=" & AKID & "/" & S_Date & "/"
              & Region & "/" & Service & "/aws4_request, SignedHeaders="
              & Signed & ", Signature=" & Sig;
            Headers  : constant String :=
              "x-amz-date: " & Amz_Date & CRLF
              & "x-amz-content-sha256: " & Pay_Hash & CRLF
              & "Authorization: " & Auth & CRLF
              & "X-Dezhan-Mode: compliance" & CRLF
              & "X-Dezhan-Retain: 3600" & CRLF;
         begin
            Round_Trip (Req ("PUT", Path, Headers, Data));
         end;

      elsif Cmd = "del" and then Argument_Count >= 2 then
         declare
            Bypass : constant String :=
              (if Argument_Count >= 3 and then Argument (3) = "bypass"
               then "true" else "false");
         begin
            Round_Trip
              (Req ("DELETE", "/v/" & Argument (2),
                    "X-Dezhan-Bypass: " & Bypass & CRLF, ""));
         end;
      else
         Put_Line ("unknown or incomplete command");
         Set_Exit_Status (Failure);
      end if;
   end;
exception
   when E : others =>
      Put_Line ("error: " & Exception_Message (E));
      Set_Exit_Status (Failure);
end Dezhan_Cli;
