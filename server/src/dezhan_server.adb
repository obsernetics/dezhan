pragma Ada_2022;
--  Minimal HTTP server exposing the dezhan vault (POC). No external dependency:
--  it uses GNAT.Sockets and a hand-rolled HTTP/1.1 request reader. SigV4 auth and
--  multipart are not implemented in this POC (see docs/NOTES.md); object-lock
--  parameters are passed via X-Dezhan-* headers.
--
--  Routes:
--    GET    /healthz            liveness
--    GET    /metrics            Prometheus metrics
--    POST   /admin/tick         advance trusted time from the system clock
--    PUT    /v/<name>           store (headers X-Dezhan-Mode, X-Dezhan-Retain)
--    GET    /v/<name>           retrieve
--    HEAD   /v/<name>           existence
--    DELETE /v/<name>           delete if retention allows (X-Dezhan-Bypass)
with Ada.Text_IO;          use Ada.Text_IO;
with Ada.Command_Line;     use Ada.Command_Line;
with Ada.Strings;          use Ada.Strings;
with Ada.Strings.Fixed;    use Ada.Strings.Fixed;
with Ada.Strings.Maps.Constants;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Streams;          use Ada.Streams;
with Ada.Exceptions;       use Ada.Exceptions;
with Ada.Environment_Variables;
with GNAT.Sockets;         use GNAT.Sockets;
with Dezhan.Trusted_Core.Times;     use Dezhan.Trusted_Core.Times;
with Dezhan.Trusted_Core.Retention; use Dezhan.Trusted_Core.Retention;
with Dezhan.Trusted_Core.Cipher;    use Dezhan.Trusted_Core.Cipher;
with Dezhan.Vault;                  use Dezhan.Vault;
with Dezhan.Sigv4;

procedure Dezhan_Server is

   CRLF : constant String := ASCII.CR & ASCII.LF;

   Port : constant Port_Type :=
     (if Argument_Count >= 1 then Port_Type'Value (Argument (1)) else 8080);
   Root : constant String :=
     (if Argument_Count >= 2 then Argument (2) else "/tmp/dezhan-vault");

   --  Fixed demo key. Real key management is future work (docs/NOTES.md).
   Key : constant Key_256 := (others => 42);

   function Env (Name, Default : String) return String is
     (if Ada.Environment_Variables.Exists (Name)
      then Ada.Environment_Variables.Value (Name) else Default);

   --  SigV4 credential (single demo account) and whether unsigned requests to
   --  /v are rejected. Real multi-account credential management is future work.
   Access_Key   : constant String  := Env ("DEZHAN_ACCESS_KEY", "dezhanadmin");
   Secret_Key   : constant String  := Env ("DEZHAN_SECRET", "dezhandemosecretkey0123456789");
   Require_Auth : constant Boolean  := Ada.Environment_Variables.Exists ("DEZHAN_REQUIRE_AUTH");

   type Auth_Status is (Anon, Valid, Invalid, Missing);

   V : Vault_Type;

   --  Latest background-scrub result (for /metrics).
   Last_Scrub : Scrub_Report;
   Scrub_Runs : Natural := 0;

   LF : constant String := ASCII.LF & "";

   --  Minimal single-page UI. Uses single quotes throughout so the Ada string
   --  literal needs no escaping.
   Index_Html : constant String :=
     "<!doctype html><html><head><meta charset=utf-8><title>dezhan</title>" & LF
     & "<style>body{font-family:system-ui,sans-serif;max-width:760px;margin:2rem auto;color:#222}"
     & "section{border:1px solid #ddd;border-radius:8px;padding:1rem;margin:1rem 0}"
     & "input,textarea,select{margin:.2rem 0}pre{background:#f6f6f6;padding:.6rem;white-space:pre-wrap}"
     & "h1{font-size:1.4rem}button{cursor:pointer}</style></head><body>" & LF
     & "<h1>dezhan vault</h1>" & LF
     & "<section><h3>Store object</h3>"
     & "name <input id=n value=backup1><br>data <br><textarea id=d rows=3 cols=50>hello dezhan</textarea><br>"
     & "mode <select id=m><option>compliance</option><option>governance</option></select> "
     & "retain(s) <input id=r value=3600 size=6> "
     & "<button onclick=store()>Store</button></section>" & LF
     & "<section><h3>Fetch / Delete</h3>"
     & "name <input id=gn value=backup1> <button onclick=getObj()>Get</button> "
     & "<label><input type=checkbox id=bp> bypass</label> <button onclick=del()>Delete</button>"
     & "<pre id=out></pre></section>" & LF
     & "<section><h3>Objects</h3><button onclick=load()>Refresh</button>"
     & "<pre id=objs></pre></section>" & LF
     & "<section><h3>Metrics</h3><pre id=metrics>loading...</pre></section>" & LF
     & "<script>" & LF
     & "async function store(){const r=await fetch('/v/'+n.value,{method:'PUT',"
     & "headers:{'X-Dezhan-Mode':m.value,'X-Dezhan-Retain':r0()},body:d.value});"
     & "out.textContent=r.status+' '+await r.text();load()}" & LF
     & "function r0(){return document.getElementById('r').value}" & LF
     & "async function getObj(){const r=await fetch('/v/'+gn.value);"
     & "out.textContent=r.status+' '+await r.text()}" & LF
     & "async function del(){const r=await fetch('/v/'+gn.value,{method:'DELETE',"
     & "headers:{'X-Dezhan-Bypass':bp.checked}});out.textContent=r.status+' '+await r.text();load()}" & LF
     & "async function load(){metrics.textContent=await (await fetch('/metrics')).text();"
     & "objs.textContent=(await (await fetch('/v/')).text())||'(none)'}load()" & LF
     & "</script></body></html>" & LF;

   function To_SEA (S : String) return Stream_Element_Array is
      R : Stream_Element_Array (1 .. S'Length);
   begin
      for I in 1 .. S'Length loop
         R (Stream_Element_Offset (I)) :=
           Stream_Element (Character'Pos (S (S'First + I - 1)));
      end loop;
      return R;
   end To_SEA;

   function Read_Char (Ch : Stream_Access) return Character is
      C : Character;
   begin
      Character'Read (Ch, C);
      return C;
   end Read_Char;

   --  Read the request head (request line + headers) up to the blank line.
   function Read_Head (Ch : Stream_Access) return String is
      Buf : Unbounded_String;
      C   : Character;
   begin
      loop
         C := Read_Char (Ch);
         Append (Buf, C);
         declare
            S : constant String := To_String (Buf);
         begin
            exit when S'Length >= 4
              and then S (S'Last - 3 .. S'Last) = CRLF & CRLF;
         end;
      end loop;
      return To_String (Buf);
   end Read_Head;

   --  Case-insensitive header lookup; returns "" if absent.
   function Header (Head, Name : String) return String is
      Lower_Head : constant String := Translate (Head, Ada.Strings.Maps.Constants.Lower_Case_Map);
      Key_Str    : constant String := Translate (Name, Ada.Strings.Maps.Constants.Lower_Case_Map) & ":";
      Idx        : constant Natural := Index (Lower_Head, Key_Str);
   begin
      if Idx = 0 then
         return "";
      end if;
      declare
         From  : Natural := Idx + Key_Str'Length;
         Stop  : Natural := Index (Head (From .. Head'Last), CRLF);
         Value : constant String :=
           (if Stop = 0 then Head (From .. Head'Last) else Head (From .. Stop - 1));
      begin
         return Trim (Value, Ada.Strings.Both);
      end;
   end Header;

   procedure Send
     (Ch     : Stream_Access;
      Status : String;
      Ctype  : String;
      Payload : Stream_Element_Array)
   is
      Head : constant String :=
        "HTTP/1.1 " & Status & CRLF
        & "Content-Type: " & Ctype & CRLF
        & "Content-Length:" & Stream_Element_Offset'Image (Payload'Length) & CRLF
        & "Connection: close" & CRLF & CRLF;
   begin
      String'Write (Ch, Head);
      if Payload'Length > 0 then
         Stream_Element_Array'Write (Ch, Payload);
      end if;
   end Send;

   procedure Send_Text (Ch : Stream_Access; Status, Text : String) is
   begin
      Send (Ch, Status, "text/plain", To_SEA (Text));
   end Send_Text;

   --  N-th Sep-separated field of S ("" if absent).
   function Part (S : String; Sep : Character; N : Positive) return String is
      Count : Natural := 0;
      Start : Natural := S'First;
      I     : Natural := S'First;
   begin
      while I <= S'Last loop
         if S (I) = Sep then
            Count := Count + 1;
            if Count = N then
               return S (Start .. I - 1);
            end if;
            Start := I + 1;
         end if;
         I := I + 1;
      end loop;
      if Count + 1 = N then
         return S (Start .. S'Last);
      end if;
      return "";
   end Part;

   --  Value of "Key=..." in an Authorization header, up to the next comma.
   function Field_After (S, K : String) return String is
      I : constant Natural := Index (S, K);
   begin
      if I = 0 then
         return "";
      end if;
      declare
         From : constant Natural := I + K'Length;
         J    : Natural := From;
      begin
         while J <= S'Last and then S (J) /= ',' loop
            J := J + 1;
         end loop;
         return Trim (S (From .. J - 1), Both);
      end;
   end Field_After;

   --  Verify a SigV4 Authorization header against the request and the demo
   --  credential. Anonymous is allowed unless DEZHAN_REQUIRE_AUTH is set.
   function Check_Auth
     (Head, Method, Path, Payload_Hash : String) return Auth_Status
   is
      A : constant String := Header (Head, "Authorization");
   begin
      if A = "" then
         return (if Require_Auth then Missing else Anon);
      end if;
      if Index (A, "AWS4-HMAC-SHA256") = 0 then
         return Invalid;
      end if;
      declare
         Cred    : constant String := Field_After (A, "Credential=");
         SH      : constant String := Field_After (A, "SignedHeaders=");
         Sig     : constant String := Field_After (A, "Signature=");
         AKID    : constant String := Part (Cred, '/', 1);
         SDate   : constant String := Part (Cred, '/', 2);
         Region  : constant String := Part (Cred, '/', 3);
         Service : constant String := Part (Cred, '/', 4);
         CH      : Unbounded_String;
         N       : Natural := 1;
      begin
         if AKID /= Access_Key then
            return Invalid;
         end if;
         loop
            declare
               Name : constant String := Part (SH, ';', N);
            begin
               exit when Name = "";
               Append (CH, Name & ":" & Header (Head, Name) & ASCII.LF);
               N := N + 1;
            end;
         end loop;
         if Dezhan.Sigv4.Signature_For
              (Secret_Key, Method, Path, "", To_String (CH), SH, Payload_Hash,
               Header (Head, "x-amz-date"), SDate, Region, Service) = Sig
         then
            return Valid;
         else
            return Invalid;
         end if;
      end;
   end Check_Auth;

   procedure Handle (Ch : Stream_Access) is
      Head : constant String := Read_Head (Ch);
      SP1  : constant Natural := Index (Head, " ");
      SP2  : constant Natural :=
        (if SP1 = 0 then 0 else Index (Head (SP1 + 1 .. Head'Last), " "));
      Method : constant String :=
        (if SP1 = 0 then "" else Head (Head'First .. SP1 - 1));
      Path   : constant String :=
        (if SP1 = 0 or SP2 = 0 then "/" else Head (SP1 + 1 .. SP2 - 1));
      Len    : constant Natural :=
        (if Header (Head, "Content-Length") = "" then 0
         else Natural'Value (Header (Head, "Content-Length")));
   begin
      --  Drain the request body (if any).
      declare
         Body_Bytes : Stream_Element_Array (1 .. Stream_Element_Offset (Len));
      begin
         if Len > 0 then
            Stream_Element_Array'Read (Ch, Body_Bytes);
         end if;

         --  Keep trusted time current from the real system clock.
         Tick_From_System (V);

         --  Authenticate data-plane (/v) requests via SigV4 when present.
         if Path = "/v"
           or else (Path'Length >= 3
                    and then Path (Path'First .. Path'First + 2) = "/v/")
         then
            declare
               Payload_Hash : constant String :=
                 (if Header (Head, "x-amz-content-sha256") /= ""
                  then Header (Head, "x-amz-content-sha256")
                  else Dezhan.Sigv4.Hex_SHA256 (""));
               St : constant Auth_Status :=
                 Check_Auth (Head, Method, Path, Payload_Hash);
            begin
               if St = Missing then
                  Send_Text (Ch, "401 Unauthorized", "authentication required");
                  return;
               elsif St = Invalid then
                  Send_Text (Ch, "403 Forbidden", "invalid SigV4 signature");
                  return;
               end if;
            end;
         end if;

         if Method = "GET" and then Path = "/" then
            Send (Ch, "200 OK", "text/html", To_SEA (Index_Html));

         elsif Method = "GET" and then Path = "/healthz" then
            Send_Text (Ch, "200 OK", (if Sealed (V) then "sealed" else "ok"));

         elsif Method = "GET" and then Path = "/metrics" then
            Send_Text
              (Ch, "200 OK",
               "# HELP dezhan_objects Stored object count" & CRLF
               & "# TYPE dezhan_objects gauge" & CRLF
               & "dezhan_objects" & Natural'Image (Object_Count (V)) & CRLF
               & "# HELP dezhan_audit_entries Audit chain length" & CRLF
               & "# TYPE dezhan_audit_entries counter" & CRLF
               & "dezhan_audit_entries" & Natural'Image (Audit_Length (V)) & CRLF
               & "# HELP dezhan_sealed Vault sealed (clock anomaly)" & CRLF
               & "# TYPE dezhan_sealed gauge" & CRLF
               & "dezhan_sealed" & (if Sealed (V) then " 1" else " 0") & CRLF
               & "# HELP dezhan_trusted_time Trusted monotonic time" & CRLF
               & "# TYPE dezhan_trusted_time counter" & CRLF
               & "dezhan_trusted_time" & Trusted_Time'Image (Now (V)) & CRLF
               & "# HELP dezhan_scrub_runs Background scrub passes" & CRLF
               & "# TYPE dezhan_scrub_runs counter" & CRLF
               & "dezhan_scrub_runs" & Natural'Image (Scrub_Runs) & CRLF
               & "# HELP dezhan_scrub_corrupt Objects found corrupt in last scrub" & CRLF
               & "# TYPE dezhan_scrub_corrupt gauge" & CRLF
               & "dezhan_scrub_corrupt" & Natural'Image (Last_Scrub.Corrupt) & CRLF);

         elsif Method = "POST" and then Path = "/admin/tick" then
            Send_Text (Ch, "200 OK", "trusted_time" & Trusted_Time'Image (Now (V)));

         elsif Method = "POST" and then Path = "/admin/seal" then
            Seal (V);
            Send_Text (Ch, "200 OK", "vault sealed (read-only)");

         elsif Method = "POST" and then Path = "/admin/scrub" then
            Last_Scrub := Scrub (V);
            Scrub_Runs := Scrub_Runs + 1;
            Send_Text (Ch, "200 OK",
              "scrub total" & Natural'Image (Last_Scrub.Total)
              & " intact" & Natural'Image (Last_Scrub.Intact)
              & " corrupt" & Natural'Image (Last_Scrub.Corrupt));

         elsif Method = "GET" and then (Path = "/v" or else Path = "/v/") then
            Send_Text (Ch, "200 OK", Object_Names (V));

         elsif Path'Length > 3 and then Path (Path'First .. Path'First + 2) = "/v/" then
            declare
               Name : constant String := Path (Path'First + 3 .. Path'Last);
            begin
               if Method = "PUT" then
                  declare
                     Mode_Str : constant String := Header (Head, "X-Dezhan-Mode");
                     Mode     : constant Lock_Mode :=
                       (if Mode_Str = "governance" then Governance else Compliance);
                     Retain   : constant Trusted_Time :=
                       (if Header (Head, "X-Dezhan-Retain") = "" then 3600
                        else Trusted_Time'Value (Header (Head, "X-Dezhan-Retain")));
                  begin
                     Put_Object (V, Name, Body_Bytes, Mode, Retain);
                     Send_Text (Ch, "200 OK",
                       "stored " & Name & " mode=" & Mode'Image
                       & " retain=" & Trusted_Time'Image (Retain));
                  end;

               elsif Method = "GET" then
                  if Contains (V, Name) then
                     Send (Ch, "200 OK", "application/octet-stream",
                           Get_Object (V, Name));
                  else
                     Send_Text (Ch, "404 Not Found", "no such object");
                  end if;

               elsif Method = "HEAD" then
                  if Contains (V, Name) then
                     Send_Text (Ch, "200 OK", "");
                  else
                     Send_Text (Ch, "404 Not Found", "");
                  end if;

               elsif Method = "DELETE" then
                  if not Contains (V, Name) then
                     Send_Text (Ch, "404 Not Found", "no such object");
                  elsif Delete_Object
                          (V, Name,
                           Bypass => Header (Head, "X-Dezhan-Bypass") = "true")
                  then
                     Send_Text (Ch, "200 OK", "deleted " & Name);
                  else
                     Send_Text (Ch, "403 Forbidden",
                       "object is retained and cannot be deleted yet");
                  end if;

               else
                  Send_Text (Ch, "405 Method Not Allowed", "");
               end if;
            end;

         else
            Send_Text (Ch, "404 Not Found", "unknown route");
         end if;
      exception
         when Vault_Sealed =>
            Send_Text (Ch, "503 Service Unavailable",
                       "vault is sealed (read-only)");
         when Not_Found =>
            Send_Text (Ch, "404 Not Found", "no such object");
      end;
   end Handle;

   Server : Socket_Type;
   Sock   : Socket_Type;
   Addr   : Sock_Addr_Type;
   From   : Sock_Addr_Type;
   Sel    : Selector_Type;
   R_Set  : Socket_Set_Type;
   W_Set  : Socket_Set_Type;
   Status : Selector_Status;
begin
   Open (V, Root, Key);
   Initialize;
   Create_Socket (Server);
   Set_Socket_Option (Server, Socket_Level, (Reuse_Address, True));
   Addr.Addr := Any_Inet_Addr;
   Addr.Port := Port;
   Bind_Socket (Server, Addr);
   Listen_Socket (Server);
   Create_Selector (Sel);
   Put_Line ("dezhan server listening on port" & Port_Type'Image (Port)
             & " (root " & Root & ")");

   --  Single-threaded loop: wait up to 30s for a connection; on timeout, run a
   --  background integrity scrub. No concurrency, so no locking is needed.
   loop
      begin
         Empty (R_Set);
         Empty (W_Set);
         Set (R_Set, Server);
         Check_Selector (Sel, R_Set, W_Set, Status, Timeout => 30.0);
         if Status = Completed then
            Accept_Socket (Server, Sock, From);
            Handle (Stream (Sock));
            Close_Socket (Sock);
         else
            --  Idle: scrub all objects in the background.
            Last_Scrub := Scrub (V);
            Scrub_Runs := Scrub_Runs + 1;
            if Last_Scrub.Corrupt > 0 then
               Put_Line ("scrub: " & Natural'Image (Last_Scrub.Corrupt)
                         & " corrupt object(s) detected");
            end if;
         end if;
      exception
         when E : others =>
            Put_Line ("loop error: " & Exception_Message (E));
            begin
               Close_Socket (Sock);
            exception
               when others => null;
            end;
      end;
   end loop;
end Dezhan_Server;
