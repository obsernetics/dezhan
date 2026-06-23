pragma Ada_2022;
--  HTTP server exposing the dezhan vault. No external dependency: it uses
--  GNAT.Sockets and a hand-rolled HTTP/1.1 request reader. SigV4 authentication
--  is enforced on /v requests when an Authorization header is present (and
--  required when DEZHAN_REQUIRE_AUTH is set); multipart upload is supported.
--  Object-lock parameters are passed via X-Dezhan-* headers. Remaining S3-fidelity
--  items (query-string SigV4 canonicalization, multi-account credentials, ETags)
--  are tracked in docs/NOTES.md.
--
--  Routes:
--    GET    /                   web UI
--    GET    /healthz            liveness
--    GET    /metrics            Prometheus metrics
--    POST   /admin/tick         advance trusted time from the system clock
--    POST   /admin/seal         operator seal (read-only)
--    POST   /admin/scrub        run an integrity scrub
--    POST   /admin/gc           garbage-collect orphaned chunks/manifests
--    POST   /admin/ingest-only?on=1|0   one-way ingest (block reads)
--    POST   /admin/sync-window?open=1|0 open/close the sync window
--    POST   /admin/export?dest=<path>   technology-break export
--    POST   /admin/legal-hold?name=X&on=1|0  place/release a legal hold
--    GET    /v                  list objects
--    PUT    /v/<name>           store (headers X-Dezhan-Mode, X-Dezhan-Retain)
--    GET    /v/<name>           retrieve
--    HEAD   /v/<name>           existence
--    DELETE /v/<name>           delete if retention allows (X-Dezhan-Bypass)
--    POST   /v/<name>?uploads             begin multipart upload
--    PUT    /v/<name>?uploadId=<id>       upload a part
--    POST   /v/<name>?uploadId=<id>       complete the upload
--    DELETE /v/<name>?uploadId=<id>       abort the upload
with Ada.Text_IO;          use Ada.Text_IO;
with Ada.Command_Line;     use Ada.Command_Line;
with Ada.Strings;          use Ada.Strings;
with Ada.Strings.Fixed;    use Ada.Strings.Fixed;
with Ada.Strings.Maps.Constants;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Streams;          use Ada.Streams;
with Ada.Exceptions;       use Ada.Exceptions;
with Ada.Environment_Variables;
with Ada.Strings.Hash;
with Ada.Containers.Indefinite_Hashed_Maps;
with GNAT.Sockets;         use GNAT.Sockets;
with Dezhan.Trusted_Core.Times;     use Dezhan.Trusted_Core.Times;
with Dezhan.Trusted_Core.Retention; use Dezhan.Trusted_Core.Retention;
with Dezhan.Trusted_Core.Cipher;    use Dezhan.Trusted_Core.Cipher;
with Dezhan.Trusted_Core.Hashing;   use Dezhan.Trusted_Core.Hashing;
with Dezhan.Vault;                  use Dezhan.Vault;
with Dezhan.Sigv4;
with Dezhan.Kdf;                    use Dezhan.Kdf;
with Ada.Streams.Stream_IO;
with Ada.Directories;

procedure Dezhan_Server is

   CRLF : constant String := ASCII.CR & ASCII.LF;

   Port : constant Port_Type :=
     (if Argument_Count >= 1 then Port_Type'Value (Argument (1)) else 8080);
   Root : constant String :=
     (if Argument_Count >= 2 then Argument (2) else "/tmp/dezhan-vault");

   function Env (Name, Default : String) return String is
     (if Ada.Environment_Variables.Exists (Name)
      then Ada.Environment_Variables.Value (Name) else Default);

   --  PBKDF2 work factor. Higher means a stolen vault is proportionally more
   --  expensive to brute-force; tune for the deployment's CPU.
   KDF_Iters : constant Positive :=
     Positive'Value (Env ("DEZHAN_KDF_ITERS", "200000"));

   --  Per-vault random salt for the KDF, kept in the clear at <root>/vault.salt
   --  (a salt is not secret). Created on first start from /dev/urandom.
   function Vault_Salt (Root : String) return Byte_Array is
      package SIO renames Ada.Streams.Stream_IO;
      package Dir renames Ada.Directories;
      Path : constant String := Dir.Compose (Root, "vault.salt");
      F    : SIO.File_Type;
      SEA  : Stream_Element_Array (1 .. 16);
      Last : Stream_Element_Offset;
      R    : Byte_Array (0 .. 15);
   begin
      Dir.Create_Path (Root);
      if not Dir.Exists (Path) then
         declare
            U : SIO.File_Type;
         begin
            SIO.Open (U, SIO.In_File, "/dev/urandom");
            SIO.Read (U, SEA, Last);
            SIO.Close (U);
            SIO.Create (F, SIO.Out_File, Path);
            SIO.Write (F, SEA (1 .. Last));
            SIO.Close (F);
         end;
      end if;
      SIO.Open (F, SIO.In_File, Path);
      SIO.Read (F, SEA, Last);
      SIO.Close (F);
      for I in 0 .. Natural (Last) - 1 loop
         R (I) := Byte (SEA (Stream_Element_Offset (I + 1)));
      end loop;
      return R (0 .. Natural (Last) - 1);
   end Vault_Salt;

   --  Vault data-encryption key, derived from a passphrase (DEZHAN_VAULT_KEY)
   --  with PBKDF2-HMAC-SHA256 over the per-vault salt. The passphrase is first
   --  folded to 32 bytes with SHA-256 so any length is accepted. Wrapping/escrow
   --  of the derived key is the remaining key-management work.
   function Derive_Key (Pass, Root : String) return Key_256 is
      PB   : Byte_Array (0 .. Pass'Length - 1);
      Salt : constant Byte_Array := Vault_Salt (Root);
      PW   : Digest;
      D    : Digest;
      K    : Key_256;
   begin
      for I in 0 .. Pass'Length - 1 loop
         PB (I) := Byte (Character'Pos (Pass (Pass'First + I)));
      end loop;
      PW := SHA256 (PB);
      declare
         PWB : Byte_Array (0 .. 31);
      begin
         for I in 0 .. 31 loop
            PWB (I) := PW (I);
         end loop;
         D := PBKDF2_HMAC_SHA256 (PWB, Salt, KDF_Iters);
      end;
      for I in 0 .. 31 loop
         K (I) := D (I);
      end loop;
      return K;
   end Derive_Key;

   Key : constant Key_256 :=
     Derive_Key (Env ("DEZHAN_VAULT_KEY", "dezhan-demo-vault-key"), Root);

   --  The seeded demo SigV4 account (more can be loaded from a credentials
   --  file), and whether unsigned requests to /v are rejected.
   Access_Key   : constant String  := Env ("DEZHAN_ACCESS_KEY", "dezhanadmin");
   Secret_Key   : constant String  := Env ("DEZHAN_SECRET", "dezhandemosecretkey0123456789");
   Require_Auth : constant Boolean  := Ada.Environment_Variables.Exists ("DEZHAN_REQUIRE_AUTH");

   type Auth_Status is (Anon, Valid, Invalid, Missing);

   --  Credential store: access key id -> secret. Seeded with the demo account;
   --  more can be added via a credentials file (lines "akid secret"), path from
   --  DEZHAN_CREDENTIALS or <root>/credentials.
   package Cred_Maps is new Ada.Containers.Indefinite_Hashed_Maps
     (Key_Type => String, Element_Type => String,
      Hash => Ada.Strings.Hash, Equivalent_Keys => "=");
   Credentials : Cred_Maps.Map;

   procedure Load_Credentials (Path : String) is
      F : File_Type;
   begin
      Open (F, In_File, Path);
      while not End_Of_File (F) loop
         declare
            Line : constant String := Get_Line (F);
            Sp   : constant Natural := Index (Line, " ");
         begin
            if Sp > 0 then
               Credentials.Include
                 (Trim (Line (Line'First .. Sp - 1), Both),
                  Trim (Line (Sp + 1 .. Line'Last), Both));
            end if;
         end;
      end loop;
      Close (F);
   exception
      when others => null;  --  no/unreadable file: rely on the seeded demo cred
   end Load_Credentials;

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
         From  : constant Natural := Idx + Key_Str'Length;
         Stop  : constant Natural := Index (Head (From .. Head'Last), CRLF);
         Value : constant String :=
           (if Stop = 0 then Head (From .. Head'Last) else Head (From .. Stop - 1));
      begin
         return Trim (Value, Ada.Strings.Both);
      end;
   end Header;

   procedure Send
     (Ch      : Stream_Access;
      Status  : String;
      Ctype   : String;
      Payload : Stream_Element_Array;
      Extra   : String := "")
   is
      Head : constant String :=
        "HTTP/1.1 " & Status & CRLF
        & "Content-Type: " & Ctype & CRLF
        & "Content-Length:" & Stream_Element_Offset'Image (Payload'Length) & CRLF
        & Extra
        & "Connection: close" & CRLF & CRLF;
   begin
      String'Write (Ch, Head);
      if Payload'Length > 0 then
         Stream_Element_Array'Write (Ch, Payload);
      end if;
   end Send;

   procedure Send_Text
     (Ch : Stream_Access; Status, Text : String; Extra : String := "") is
   begin
      Send (Ch, Status, "text/plain", To_SEA (Text), Extra);
   end Send_Text;

   --  Structured (key=value) log line to stdout.
   procedure Log (Msg : String) is
   begin
      Put_Line ("ts=" & Trusted_Time'Image (Now (V)) & " " & Msg);
   end Log;

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

   --  Value of "Key=..." in a query string, up to '&' or end.
   function Q_Val (Q, K : String) return String is
      I : constant Natural := Index (Q, K);
   begin
      if I = 0 then
         return "";
      end if;
      declare
         From : constant Natural := I + K'Length;
         J    : Natural := From;
      begin
         while J <= Q'Last and then Q (J) /= '&' loop
            J := J + 1;
         end loop;
         return Q (From .. J - 1);
      end;
   end Q_Val;

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
         QPos    : constant Natural := Index (Path, "?");
         Path0   : constant String :=
           (if QPos = 0 then Path else Path (Path'First .. QPos - 1));
         Query   : constant String :=
           (if QPos = 0 then "" else Path (QPos + 1 .. Path'Last));
         CH      : Unbounded_String;
         N       : Natural := 1;
      begin
         if not Credentials.Contains (AKID) then
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
              (Credentials.Element (AKID), Method, Path0,
               Dezhan.Sigv4.Canonical_Query (Query),
               To_String (CH), SH, Payload_Hash,
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
      QMark  : constant Natural := Index (Path, "?");
      Path0  : constant String :=
        (if QMark = 0 then Path else Path (Path'First .. QMark - 1));
      PQuery : constant String :=
        (if QMark = 0 then "" else Path (QMark + 1 .. Path'Last));
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
         Log ("event=request method=" & Method & " path=" & Path0
              & " bytes=" & Natural'Image (Len));

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
               & "# HELP dezhan_quarantined Objects quarantined (unrepairable)" & CRLF
               & "# TYPE dezhan_quarantined gauge" & CRLF
               & "dezhan_quarantined" & Natural'Image (Quarantined_Count (V)) & CRLF
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
               & "dezhan_scrub_corrupt" & Natural'Image (Last_Scrub.Corrupt) & CRLF
               & "# HELP dezhan_scrub_shards_repaired Shards rebuilt in last scrub" & CRLF
               & "# TYPE dezhan_scrub_shards_repaired gauge" & CRLF
               & "dezhan_scrub_shards_repaired"
               & Natural'Image (Last_Scrub.Shards_Repaired) & CRLF);

         elsif Method = "POST" and then Path = "/admin/tick" then
            Send_Text (Ch, "200 OK", "trusted_time" & Trusted_Time'Image (Now (V)));

         elsif Method = "POST" and then Path = "/admin/seal" then
            Seal (V);
            Send_Text (Ch, "200 OK", "vault sealed (read-only)");

         elsif Method = "POST" and then Path0 = "/admin/scrub" then
            Last_Scrub := Scrub (V);
            Scrub_Runs := Scrub_Runs + 1;
            Send_Text (Ch, "200 OK",
              "scrub total" & Natural'Image (Last_Scrub.Total)
              & " intact" & Natural'Image (Last_Scrub.Intact)
              & " repaired" & Natural'Image (Last_Scrub.Repaired)
              & " corrupt" & Natural'Image (Last_Scrub.Corrupt)
              & " shards_repaired" & Natural'Image (Last_Scrub.Shards_Repaired));

         elsif Method = "POST" and then Path0 = "/admin/gc" then
            Send_Text (Ch, "200 OK",
              "reclaimed" & Natural'Image (Collect_Garbage (V)));

         elsif Method = "POST" and then Path0 = "/admin/ingest-only" then
            Set_One_Way_Ingest (V, Q_Val (PQuery, "on=") = "1");
            Send_Text (Ch, "200 OK",
              "one_way_ingest=" & (if One_Way_Ingest (V) then "on" else "off"));

         elsif Method = "POST" and then Path0 = "/admin/sync-window" then
            if Q_Val (PQuery, "open=") = "1" then
               Open_Sync_Window (V);
            else
               Close_Sync_Window (V);
            end if;
            Send_Text (Ch, "200 OK",
              "sync_window=" & (if Sync_Window_Open (V) then "open" else "closed"));

         elsif Method = "POST" and then Path0 = "/admin/legal-hold" then
            declare
               Name : constant String := Q_Val (PQuery, "name=");
            begin
               if Name = "" then
                  Send_Text (Ch, "400 Bad Request", "missing name=");
               else
                  if Q_Val (PQuery, "on=") = "1" then
                     Set_Legal_Hold (V, Name);
                  else
                     Release_Legal_Hold (V, Name);
                  end if;
                  Send_Text (Ch, "200 OK",
                    "legal_hold " & Name & "="
                    & (if Has_Legal_Hold (V, Name) then "on" else "off"));
               end if;
            end;

         elsif Method = "POST" and then Path0 = "/admin/export" then
            declare
               Dest : constant String := Q_Val (PQuery, "dest=");
            begin
               if Dest = "" then
                  Send_Text (Ch, "400 Bad Request", "missing dest=");
               else
                  Export (V, Dest);
                  Send_Text (Ch, "200 OK", "exported to " & Dest);
               end if;
            end;

         elsif Method = "GET" and then (Path = "/v" or else Path = "/v/") then
            Send_Text (Ch, "200 OK", Object_Names (V));

         elsif Path'Length > 3 and then Path (Path'First .. Path'First + 2) = "/v/" then
            declare
               Raw   : constant String := Path (Path'First + 3 .. Path'Last);
               QPos  : constant Natural := Index (Raw, "?");
               Name  : constant String :=
                 (if QPos = 0 then Raw else Raw (Raw'First .. QPos - 1));
               Query : constant String :=
                 (if QPos = 0 then "" else Raw (QPos + 1 .. Raw'Last));
               Mode  : constant Lock_Mode :=
                 (if Header (Head, "X-Dezhan-Mode") = "governance"
                  then Governance else Compliance);
               Retain : constant Trusted_Time :=
                 (if Header (Head, "X-Dezhan-Retain") = "" then 3600
                  else Trusted_Time'Value (Header (Head, "X-Dezhan-Retain")));
            begin
               if Query = "uploads" and then Method = "POST" then
                  Send_Text (Ch, "200 OK", Create_Upload (V, Name, Mode, Retain));

               elsif Q_Val (Query, "uploadId=") /= "" then
                  declare
                     Uid : constant String := Q_Val (Query, "uploadId=");
                  begin
                     if Method = "PUT" then
                        Upload_Part (V, Uid, Body_Bytes);
                        Send_Text (Ch, "200 OK", "part accepted");
                     elsif Method = "POST" then
                        Complete_Upload (V, Uid);
                        Send_Text (Ch, "200 OK", "completed " & Name);
                     elsif Method = "DELETE" then
                        Abort_Upload (V, Uid);
                        Send_Text (Ch, "200 OK", "aborted " & Uid);
                     else
                        Send_Text (Ch, "405 Method Not Allowed", "");
                     end if;
                  end;

               elsif Method = "PUT" then
                  Put_Object (V, Name, Body_Bytes, Mode, Retain);
                  Send_Text (Ch, "200 OK",
                    "stored " & Name & " mode=" & Mode'Image
                    & " retain=" & Trusted_Time'Image (Retain),
                    Extra => "ETag: " & '"' & Object_Etag (V, Name) & '"' & CRLF);

               elsif Method = "GET" then
                  if Contains (V, Name) then
                     Send (Ch, "200 OK", "application/octet-stream",
                           Get_Object (V, Name),
                           Extra => "ETag: " & '"' & Object_Etag (V, Name)
                                    & '"' & CRLF);
                  else
                     Send_Text (Ch, "404 Not Found", "no such object");
                  end if;

               elsif Method = "HEAD" then
                  if Contains (V, Name) then
                     Send_Text (Ch, "200 OK", "",
                       Extra => "ETag: " & '"' & Object_Etag (V, Name)
                                & '"' & CRLF);
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
         when No_Such_Upload =>
            Send_Text (Ch, "404 Not Found", "no such upload");
         when Egress_Denied =>
            Send_Text (Ch, "403 Forbidden", "reads are blocked (one-way ingest)");
         when Sync_Closed =>
            Send_Text (Ch, "409 Conflict", "sync window is closed");
         when Object_Quarantined =>
            Send_Text (Ch, "410 Gone",
                       "object quarantined: unrepairable data loss");
         when Auth_Failed =>
            Send_Text (Ch, "403 Forbidden",
                       "authentication failed (wrong key or tampering)");
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
   Credentials.Include (Access_Key, Secret_Key);   --  seed the demo account
   Load_Credentials (Env ("DEZHAN_CREDENTIALS", Root & "/credentials"));
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
            if Last_Scrub.Shards_Repaired > 0 then
               Put_Line ("scrub: rebuilt"
                         & Natural'Image (Last_Scrub.Shards_Repaired)
                         & " shard(s) from parity");
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
