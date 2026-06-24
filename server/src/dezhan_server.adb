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
with Dezhan.Keystore;              use Dezhan.Keystore;
with Ada.Streams.Stream_IO;
with Ada.Directories;
with Ada.Unchecked_Deallocation;
with Interfaces;                   use Interfaces;
with GNAT.OS_Lib;

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

   --  Key-encryption key from the passphrase and salt (PBKDF2-HMAC-SHA256). The
   --  passphrase is folded to 32 bytes with SHA-256 first so any length works.
   function KEK_From (Pass : String; Salt : Byte_Array; Iters : Positive)
                      return Key_256 is
      PB : Byte_Array (0 .. Pass'Length - 1);
      PW : Digest;
      D  : Digest;
      K  : Key_256;
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
         D := PBKDF2_HMAC_SHA256 (PWB, Salt, Iters);
      end;
      for I in 0 .. 31 loop
         K (I) := D (I);
      end loop;
      return K;
   end KEK_From;

   function Random_Bytes (N : Positive) return Byte_Array is
      package SIO renames Ada.Streams.Stream_IO;
      U    : SIO.File_Type;
      SEA  : Stream_Element_Array (1 .. Stream_Element_Offset (N));
      Last : Stream_Element_Offset;
      R    : Byte_Array (0 .. N - 1);
   begin
      SIO.Open (U, SIO.In_File, "/dev/urandom");
      SIO.Read (U, SEA, Last);
      SIO.Close (U);
      for I in 0 .. N - 1 loop
         R (I) := Byte (SEA (Stream_Element_Offset (I + 1)));
      end loop;
      return R;
   end Random_Bytes;

   Key_Path : constant String := Ada.Directories.Compose (Root, "vault.key");

   --  Keystore file: salt(16) | iters(4 BE) | nonce(12) | wrapped DEK(32) |
   --  tag(32) = 96 bytes. The salt and nonce are not secret; the DEK is wrapped.
   procedure Write_Keystore (Salt : Byte_Array; Iters : Positive;
                             W : Wrapped_Key) is
      package SIO renames Ada.Streams.Stream_IO;
      F   : SIO.File_Type;
      Buf : Stream_Element_Array (1 .. 96);
      P   : Stream_Element_Offset := 1;
      procedure Put_B (B : Byte) is
      begin
         Buf (P) := Stream_Element (B);
         P := P + 1;
      end Put_B;
   begin
      for I in 0 .. 15 loop
         Put_B (Salt (Salt'First + I));
      end loop;
      Put_B (Byte (Shift_Right (Unsigned_32 (Iters), 24) and 16#FF#));
      Put_B (Byte (Shift_Right (Unsigned_32 (Iters), 16) and 16#FF#));
      Put_B (Byte (Shift_Right (Unsigned_32 (Iters), 8)  and 16#FF#));
      Put_B (Byte (Unsigned_32 (Iters) and 16#FF#));
      for I in 0 .. 11 loop
         Put_B (W.Nonce (I));
      end loop;
      for I in 0 .. 31 loop
         Put_B (W.Cipher (I));
      end loop;
      for I in 0 .. 31 loop
         Put_B (W.Tag (I));
      end loop;
      SIO.Create (F, SIO.Out_File, Key_Path);
      SIO.Write (F, Buf);
      SIO.Close (F);
   end Write_Keystore;

   --  Load the data-encryption key: unwrap it on an existing vault (refusing a
   --  wrong passphrase), or generate and wrap a fresh random DEK on first run.
   --  If DEZHAN_NEW_VAULT_KEY is set, re-wrap the same DEK under the new
   --  passphrase (passphrase rotation: no data is re-encrypted).
   function Load_Or_Init_Key (Root, Pass : String) return Key_256 is
      package Dir renames Ada.Directories;
      package SIO renames Ada.Streams.Stream_IO;
   begin
      Dir.Create_Path (Root);
      if Dir.Exists (Key_Path) then
         declare
            F    : SIO.File_Type;
            Buf  : Stream_Element_Array (1 .. 96);
            Last : Stream_Element_Offset;
            function Get_B (I : Natural) return Byte is
              (Byte (Buf (Stream_Element_Offset (I + 1))));
            Salt  : Byte_Array (0 .. 15);
            Iters : Unsigned_32 := 0;
            W     : Wrapped_Key;
            DEK   : Key_256;
            Ok    : Boolean;
         begin
            SIO.Open (F, SIO.In_File, Key_Path);
            SIO.Read (F, Buf, Last);
            SIO.Close (F);
            for I in 0 .. 15 loop
               Salt (I) := Get_B (I);
            end loop;
            for I in 16 .. 19 loop
               Iters := Shift_Left (Iters, 8) or Unsigned_32 (Get_B (I));
            end loop;
            for I in 0 .. 11 loop
               W.Nonce (I) := Get_B (20 + I);
            end loop;
            for I in 0 .. 31 loop
               W.Cipher (I) := Get_B (32 + I);
            end loop;
            for I in 0 .. 31 loop
               W.Tag (I) := Get_B (64 + I);
            end loop;
            Unwrap (KEK_From (Pass, Salt, Positive (Iters)), W, DEK, Ok);
            if not Ok then
               Put_Line ("fatal: wrong vault passphrase (DEZHAN_VAULT_KEY)");
               GNAT.OS_Lib.OS_Exit (1);
            end if;
            if Ada.Environment_Variables.Exists ("DEZHAN_NEW_VAULT_KEY") then
               declare
                  NSalt : constant Byte_Array := Random_Bytes (16);
                  NNonB : constant Byte_Array := Random_Bytes (12);
                  NNon  : Nonce_96;
               begin
                  for I in 0 .. 11 loop
                     NNon (I) := NNonB (I);
                  end loop;
                  Write_Keystore
                    (NSalt, KDF_Iters,
                     Wrap (KEK_From (Env ("DEZHAN_NEW_VAULT_KEY", ""),
                                     NSalt, KDF_Iters),
                           NNon, DEK));
                  Put_Line ("vault key re-wrapped (passphrase rotated)");
               end;
            end if;
            return DEK;
         end;
      else
         declare
            DEK_B : constant Byte_Array := Random_Bytes (32);
            Salt  : constant Byte_Array := Random_Bytes (16);
            NonB  : constant Byte_Array := Random_Bytes (12);
            DEK   : Key_256;
            Nonce : Nonce_96;
         begin
            for I in 0 .. 31 loop
               DEK (I) := DEK_B (I);
            end loop;
            for I in 0 .. 11 loop
               Nonce (I) := NonB (I);
            end loop;
            Write_Keystore
              (Salt, KDF_Iters, Wrap (KEK_From (Pass, Salt, KDF_Iters),
                                      Nonce, DEK));
            return DEK;
         end;
      end if;
   end Load_Or_Init_Key;

   Key : constant Key_256 :=
     Load_Or_Init_Key (Root, Env ("DEZHAN_VAULT_KEY", "dezhan-demo-vault-key"));

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
   Last_Scrub     : Scrub_Report;
   Scrub_Runs     : Natural := 0;
   Denied_Deletes : Natural := 0;   --  deletes refused by retention/WORM

   --  Total bytes stored on disk under Path (recursive). Backs the storage
   --  capacity metric the spec's observability section calls for.
   function Dir_Bytes (Path : String) return Long_Long_Integer is
      use Ada.Directories;
      Total : Long_Long_Integer := 0;
      S     : Search_Type;
      E     : Directory_Entry_Type;
   begin
      if not Exists (Path) then
         return 0;
      end if;
      Start_Search (S, Path, "", (others => True));
      while More_Entries (S) loop
         Get_Next_Entry (S, E);
         declare
            Nm : constant String := Simple_Name (E);
         begin
            if Nm /= "." and then Nm /= ".." then
               case Kind (E) is
                  when Directory =>
                     Total := Total + Dir_Bytes (Full_Name (E));
                  when Ordinary_File =>
                     Total := Total + Long_Long_Integer (Size (Full_Name (E)));
                  when others =>
                     null;
               end case;
            end if;
         end;
      end loop;
      End_Search (S);
      return Total;
   end Dir_Bytes;

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

   function Img (N : Natural) return String is (Trim (N'Image, Ada.Strings.Both));

   --  Parse an HTTP Range value ("bytes=A-B", "bytes=A-", or "bytes=-N") against
   --  a known total length. First/Last are 0-based inclusive byte offsets; Ok is
   --  False if the spec is malformed or unsatisfiable.
   procedure Parse_Range
     (Value : String; Total : Natural;
      First, Last : out Natural; Ok : out Boolean)
   is
      Eq   : constant Natural := Index (Value, "=");
      Spec : constant String :=
        (if Eq = 0 then "" else Value (Eq + 1 .. Value'Last));
      Dash : Natural;
   begin
      First := 0;
      Last  := 0;
      Ok    := False;
      if Spec = "" or else Total = 0 then
         return;
      end if;
      Dash := Index (Spec, "-");
      if Dash = 0 then
         return;
      end if;
      if Dash = Spec'First then
         declare
            N : constant Natural := Natural'Value (Spec (Dash + 1 .. Spec'Last));
         begin
            if N = 0 then
               return;
            end if;
            First := (if N >= Total then 0 else Total - N);
            Last  := Total - 1;
         end;
      else
         First := Natural'Value (Spec (Spec'First .. Dash - 1));
         Last  := (if Dash = Spec'Last then Total - 1
                   else Natural'Value (Spec (Dash + 1 .. Spec'Last)));
         if Last > Total - 1 then
            Last := Total - 1;
         end if;
      end if;
      Ok := First <= Last and then First < Total;
   exception
      when others => Ok := False;
   end Parse_Range;

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

   ------------------------------------------------------------ S3 layer

   function Xml_Escape (S : String) return String is
      R : Unbounded_String;
   begin
      for I in S'Range loop
         case S (I) is
            when '&' => Append (R, "&amp;");
            when '<' => Append (R, "&lt;");
            when '>' => Append (R, "&gt;");
            when others => Append (R, S (I));
         end case;
      end loop;
      return To_String (R);
   end Xml_Escape;

   procedure Send_XML (Ch : Stream_Access; Status, Body_Str : String) is
   begin
      Send (Ch, Status, "application/xml", To_SEA (Body_Str));
   end Send_XML;

   --  Response head only (for HEAD): one Content-Length set to the object size,
   --  no body.
   procedure Send_Head
     (Ch : Stream_Access; Status : String; Length : Natural;
      Extra : String := ""; Ctype : String := "application/octet-stream")
   is
   begin
      String'Write (Ch,
        "HTTP/1.1 " & Status & CRLF
        & "Content-Type: " & Ctype & CRLF
        & "Content-Length:" & Natural'Image (Length) & CRLF
        & Extra & "Connection: close" & CRLF & CRLF);
   end Send_Head;

   function Pct_Decode (S : String) return String is
      R : String (1 .. S'Length);
      L : Natural := 0;
      I : Natural := S'First;
      function Nib (C : Character) return Natural is
        (case C is
            when '0' .. '9' => Character'Pos (C) - Character'Pos ('0'),
            when 'a' .. 'f' => Character'Pos (C) - Character'Pos ('a') + 10,
            when 'A' .. 'F' => Character'Pos (C) - Character'Pos ('A') + 10,
            when others     => 0);
   begin
      while I <= S'Last loop
         if S (I) = '%' and then I + 2 <= S'Last then
            L := L + 1; R (L) := Character'Val (Nib (S (I + 1)) * 16 + Nib (S (I + 2)));
            I := I + 3;
         else
            L := L + 1; R (L) := S (I); I := I + 1;
         end if;
      end loop;
      return R (1 .. L);
   end Pct_Decode;

   function Pct_Encode (S : String) return String is
      Up : constant String := "0123456789ABCDEF";
      R  : String (1 .. 3 * S'Length);
      L  : Natural := 0;
   begin
      for C of S loop
         if C in 'A' .. 'Z' | 'a' .. 'z' | '0' .. '9' | '-' | '_' | '.' | '~' | '/' then
            L := L + 1; R (L) := C;
         else
            R (L + 1) := '%'; R (L + 2) := Up (Character'Pos (C) / 16 + 1);
            R (L + 3) := Up (Character'Pos (C) mod 16 + 1); L := L + 3;
         end if;
      end loop;
      return R (1 .. L);
   end Pct_Encode;

   --  Capture Content-Type and x-amz-meta-* headers into an opaque blob:
   --  the content-type value, a LF, then the x-amz-meta-* header lines verbatim
   --  (CRLF-terminated, ready to re-emit on GET/HEAD).
   function Collect_Meta (Head : String) return String is
      CT    : constant String := Header (Head, "content-type");
      R     : Unbounded_String;
      Start : Natural := Head'First;
   begin
      for I in Head'Range loop
         if Head (I) = ASCII.LF then
            declare
               Raw  : constant String := Head (Start .. I - 1);
               Line : constant String :=
                 (if Raw'Length > 0 and then Raw (Raw'Last) = ASCII.CR
                  then Raw (Raw'First .. Raw'Last - 1) else Raw);
            begin
               if Line'Length >= 11
                 and then Translate (Line (Line'First .. Line'First + 10),
                            Ada.Strings.Maps.Constants.Lower_Case_Map) = "x-amz-meta-"
               then
                  Append (R, Line & CRLF);
               end if;
            end;
            Start := I + 1;
         end if;
      end loop;
      return CT & ASCII.LF & To_String (R);
   end Collect_Meta;

   function To_Str (D : Stream_Element_Array) return String is
      R : String (1 .. Natural (D'Length));
   begin
      for I in R'Range loop
         R (I) := Character'Val (Natural (D (D'First + Stream_Element_Offset (I - 1))));
      end loop;
      return R;
   end To_Str;

   procedure S3_Error (Ch : Stream_Access; Status, Code, Resource : String) is
   begin
      Send_XML (Ch, Status,
        "<?xml version=""1.0"" encoding=""UTF-8""?>"
        & "<Error><Code>" & Code & "</Code><Message>" & Code
        & "</Message><Resource>" & Xml_Escape (Resource) & "</Resource></Error>");
   end S3_Error;

   Epoch_Date : constant String := "1970-01-01T00:00:00.000Z";

   --  S3 ListObjectsV2 over the keys of one bucket (prefix/delimiter/max-keys/
   --  continuation-token), in <ListBucketResult> form.
   procedure List_Objects_V2
     (Ch : Stream_Access; Bucket, Query : String)
   is
      BPrefix : constant String := Bucket & "/";
      --  Query parameter values arrive percent-encoded; decode before use.
      Prefix  : constant String := Pct_Decode (Q_Val (Query, "prefix="));
      Delim   : constant String := Pct_Decode (Q_Val (Query, "delimiter="));
      Token   : constant String := Pct_Decode (Q_Val (Query, "continuation-token="));
      Max_S   : constant String := Q_Val (Query, "max-keys=");
      Enc_Url : constant Boolean := Q_Val (Query, "encoding-type=") = "url";
      Max     : constant Natural :=
        (if Max_S = "" then 1000 else Natural'Value (Max_S));
      All_Names : constant String := Object_Names (V);

      --  Honor encoding-type=url: emit keys/prefixes URL-encoded (the client
      --  decodes them back), so special characters survive the round-trip.
      function Enc (S : String) return String is
        (if Enc_Url then Pct_Encode (S) else S);
      Body_S  : Unbounded_String;
      Commons : Unbounded_String;   --  CommonPrefixes accumulator
      Count   : Natural := 0;
      Truncated : Boolean := False;
      Last_Key  : Unbounded_String;

      function Seen_Common (P : String) return Boolean is
        (Index (To_String (Commons), "<Prefix>" & Xml_Escape (P) & "</Prefix>") /= 0);

      I : Natural := All_Names'First;
   begin
      while I <= All_Names'Last loop
         --  Next line (object internal name) in All_Names.
         declare
            E : Natural := I;
         begin
            while E <= All_Names'Last and then All_Names (E) /= ASCII.LF loop
               E := E + 1;
            end loop;
            declare
               Nm : constant String := All_Names (I .. E - 1);
            begin
               if Nm'Length > BPrefix'Length
                 and then Nm (Nm'First .. Nm'First + BPrefix'Length - 1) = BPrefix
               then
                  declare
                     K : constant String := Nm (Nm'First + BPrefix'Length .. Nm'Last);
                  begin
                     if (Prefix = ""
                         or else (K'Length >= Prefix'Length
                                  and then K (K'First .. K'First + Prefix'Length - 1) = Prefix))
                       and then (Token = "" or else K > Token)
                     then
                        --  Delimiter rollup into CommonPrefixes.
                        declare
                           DPos : Natural := 0;
                        begin
                           if Delim /= "" then
                              DPos := Index (K (K'First + Prefix'Length .. K'Last), Delim);
                           end if;
                           if DPos /= 0 then
                              declare
                                 CP : constant String :=
                                   K (K'First .. DPos - 1 + Delim'Length);
                              begin
                                 if not Seen_Common (CP) then
                                    if Count >= Max then
                                       Truncated := True;
                                    else
                                       Append (Commons, "<CommonPrefixes><Prefix>"
                                         & Xml_Escape (Enc (CP)) & "</Prefix></CommonPrefixes>");
                                       Count := Count + 1;
                                       Last_Key := To_Unbounded_String (K);
                                    end if;
                                 end if;
                              end;
                           else
                              if Count >= Max then
                                 Truncated := True;
                              else
                                 Append (Body_S,
                                   "<Contents><Key>" & Xml_Escape (Enc (K))
                                   & "</Key><LastModified>" & Epoch_Date
                                   & "</LastModified><ETag>&quot;"
                                   & Object_Etag (V, Nm) & "&quot;</ETag><Size>"
                                   & Img (Object_Size (V, Nm))
                                   & "</Size><StorageClass>STANDARD</StorageClass></Contents>");
                                 Count := Count + 1;
                                 Last_Key := To_Unbounded_String (K);
                              end if;
                           end if;
                        end;
                     end if;
                  end;
               end if;
            end;
            I := E + 1;
         end;
      end loop;

      Send_XML (Ch, "200 OK",
        "<?xml version=""1.0"" encoding=""UTF-8""?>"
        & "<ListBucketResult xmlns=""http://s3.amazonaws.com/doc/2006-03-01/"">"
        & "<Name>" & Xml_Escape (Bucket) & "</Name>"
        & "<Prefix>" & Xml_Escape (Enc (Prefix)) & "</Prefix>"
        & "<KeyCount>" & Img (Count) & "</KeyCount>"
        & "<MaxKeys>" & Img (Max) & "</MaxKeys>"
        & (if Delim /= "" then "<Delimiter>" & Xml_Escape (Enc (Delim)) & "</Delimiter>" else "")
        & "<IsTruncated>" & (if Truncated then "true" else "false") & "</IsTruncated>"
        & (if Truncated then "<NextContinuationToken>"
             & Xml_Escape (Enc (To_String (Last_Key))) & "</NextContinuationToken>" else "")
        & To_String (Body_S) & To_String (Commons)
        & "</ListBucketResult>");
   end List_Objects_V2;

   procedure List_All_Buckets (Ch : Stream_Access) is
      Names : constant String := List_Buckets (V);
      Body_S : Unbounded_String;
      I : Natural := Names'First;
   begin
      while I <= Names'Last loop
         declare
            E : Natural := I;
         begin
            while E <= Names'Last and then Names (E) /= ASCII.LF loop
               E := E + 1;
            end loop;
            if E > I then
               Append (Body_S, "<Bucket><Name>" & Xml_Escape (Names (I .. E - 1))
                 & "</Name><CreationDate>" & Epoch_Date & "</CreationDate></Bucket>");
            end if;
            I := E + 1;
         end;
      end loop;
      Send_XML (Ch, "200 OK",
        "<?xml version=""1.0"" encoding=""UTF-8""?>"
        & "<ListAllMyBucketsResult xmlns=""http://s3.amazonaws.com/doc/2006-03-01/"">"
        & "<Owner><ID>dezhan</ID><DisplayName>dezhan</DisplayName></Owner>"
        & "<Buckets>" & To_String (Body_S) & "</Buckets></ListAllMyBucketsResult>");
   end List_All_Buckets;

   --  Path-style S3 dispatch for non-reserved routes: /{bucket}[/{key}].
   procedure Handle_S3
     (Ch     : Stream_Access;
      Method : String;
      Path0  : String;
      Query  : String;
      Head   : String;
      Data   : Stream_Element_Array)
   is
      Rest   : constant String :=
        (if Path0'Length >= 1 then Path0 (Path0'First + 1 .. Path0'Last) else "");
      Slash  : constant Natural := Index (Rest, "/");
      Bucket : constant String :=
        (if Slash = 0 then Rest else Rest (Rest'First .. Slash - 1));
      Key    : constant String :=
        (if Slash = 0 then "" else Rest (Slash + 1 .. Rest'Last));
      Name   : constant String := Bucket & "/" & Key;   --  internal object name
      Locked : constant Boolean := Bucket_Object_Lock (V, Bucket);
      Mode   : constant Lock_Mode :=
        (if not Locked then Governance
         elsif Header (Head, "x-amz-object-lock-mode") = "GOVERNANCE"
         then Governance else Compliance);
      Retain : constant Trusted_Time :=
        (if not Locked then 0
         elsif Header (Head, "X-Dezhan-Retain") /= ""
         then Trusted_Time'Value (Header (Head, "X-Dezhan-Retain"))
         else 3600);
      Uid    : constant String := Q_Val (Query, "uploadId=");
   begin
      if Bucket = "" then
         if Method = "GET" then
            List_All_Buckets (Ch);
         else
            S3_Error (Ch, "405 Method Not Allowed", "MethodNotAllowed", Path0);
         end if;
         return;
      end if;

      --  Bucket-level operations (no key).
      if Key = "" then
         if Method = "GET" and then Index (Query, "location") /= 0 then
            Send_XML (Ch, "200 OK",
              "<?xml version=""1.0"" encoding=""UTF-8""?>"
              & "<LocationConstraint xmlns=""http://s3.amazonaws.com/doc/2006-03-01/""/>");
            return;
         elsif Index (Query, "object-lock") /= 0 then
            if Method = "GET" then
               if Locked then
                  Send_XML (Ch, "200 OK",
                    "<?xml version=""1.0"" encoding=""UTF-8""?>"
                    & "<ObjectLockConfiguration><ObjectLockEnabled>Enabled"
                    & "</ObjectLockEnabled></ObjectLockConfiguration>");
               else
                  S3_Error (Ch, "404 Not Found",
                    "ObjectLockConfigurationNotFoundError", Path0);
               end if;
            else
               Send_Text (Ch, "200 OK", "");
            end if;
            return;
         elsif Index (Query, "versioning") /= 0 then
            if Method = "PUT" then
               Set_Versioning (V, Bucket,
                 On => Index (To_Str (Data), "<Status>Enabled</Status>") /= 0);
               Send_Text (Ch, "200 OK", "");
            else
               Send_XML (Ch, "200 OK",
                 "<?xml version=""1.0"" encoding=""UTF-8""?>"
                 & "<VersioningConfiguration xmlns="
                 & """http://s3.amazonaws.com/doc/2006-03-01/"">"
                 & (if Bucket_Versioned (V, Bucket)
                    then "<Status>Enabled</Status>" else "")
                 & "</VersioningConfiguration>");
            end if;
            return;
         elsif Method = "GET" and then Index (Query, "versions") /= 0 then
            --  ListObjectVersions.
            declare
               Lines : constant String := List_Object_Versions (V, Bucket);
               Body_S : Unbounded_String;
               I : Natural := Lines'First;
            begin
               while I <= Lines'Last loop
                  declare
                     E : Natural := I;
                  begin
                     while E <= Lines'Last and then Lines (E) /= ASCII.LF loop
                        E := E + 1;
                     end loop;
                     declare
                        Ln : constant String := Lines (I .. E - 1);
                        T1 : constant Natural := Index (Ln, (1 => ASCII.HT));
                        T2 : constant Natural :=
                          (if T1 = 0 then 0 else Index (Ln (T1 + 1 .. Ln'Last), (1 => ASCII.HT)));
                        T3 : constant Natural :=
                          (if T2 = 0 then 0 else Index (Ln (T2 + 1 .. Ln'Last), (1 => ASCII.HT)));
                     begin
                        if T1 /= 0 and then T2 /= 0 and then T3 /= 0 then
                           Append (Body_S, "<Version><Key>"
                             & Xml_Escape (Ln (Ln'First .. T1 - 1)) & "</Key><VersionId>"
                             & Ln (T1 + 1 .. T2 - 1) & "</VersionId><IsLatest>false</IsLatest>"
                             & "<LastModified>" & Epoch_Date & "</LastModified><ETag>&quot;"
                             & Ln (T3 + 1 .. Ln'Last) & "&quot;</ETag><Size>"
                             & Ln (T2 + 1 .. T3 - 1) & "</Size>"
                             & "<StorageClass>STANDARD</StorageClass></Version>");
                        end if;
                     end;
                     I := E + 1;
                  end;
               end loop;
               Send_XML (Ch, "200 OK",
                 "<?xml version=""1.0"" encoding=""UTF-8""?>"
                 & "<ListVersionsResult xmlns=""http://s3.amazonaws.com/doc/2006-03-01/"">"
                 & "<Name>" & Xml_Escape (Bucket) & "</Name>"
                 & "<IsTruncated>false</IsTruncated>"
                 & To_String (Body_S) & "</ListVersionsResult>");
            end;
            return;
         elsif Index (Query, "tagging") /= 0 then
            if Method = "GET" then
               Send_XML (Ch, "200 OK",
                 "<?xml version=""1.0"" encoding=""UTF-8""?><Tagging><TagSet/></Tagging>");
            else
               Send_Text (Ch, "204 No Content", "");
            end if;
            return;
         elsif Method = "POST" and then Index (Query, "delete") /= 0 then
            declare
               Body_S : constant String := To_Str (Data);
               Res    : Unbounded_String;
               P      : Natural := Body_S'First;
            begin
               loop
                  declare
                     A : constant Natural := Index (Body_S (P .. Body_S'Last), "<Key>");
                  begin
                     exit when A = 0;
                     declare
                        E : constant Natural :=
                          Index (Body_S (A .. Body_S'Last), "</Key>");
                     begin
                        exit when E = 0;
                        declare
                           K     : constant String := Body_S (A + 5 .. E - 1);
                           Iname : constant String := Bucket & "/" & K;
                           Done  : Boolean := True;
                        begin
                           begin
                              if Contains (V, Iname)
                                and then not Delete_Object (V, Iname, Bypass => False)
                              then
                                 Done := False;
                              end if;
                           exception
                              when others => Done := False;
                           end;
                           if Done then
                              Append (Res, "<Deleted><Key>" & Xml_Escape (K)
                                & "</Key></Deleted>");
                           else
                              Append (Res, "<Error><Key>" & Xml_Escape (K)
                                & "</Key><Code>AccessDenied</Code></Error>");
                           end if;
                        end;
                        P := E + 6;
                     end;
                  end;
               end loop;
               Send_XML (Ch, "200 OK",
                 "<?xml version=""1.0"" encoding=""UTF-8""?><DeleteResult>"
                 & To_String (Res) & "</DeleteResult>");
            end;
            return;
         end if;
         if Method = "PUT" then
            if Bucket_Exists (V, Bucket) then
               S3_Error (Ch, "409 Conflict", "BucketAlreadyOwnedByYou", Path0);
            else
               Create_Bucket (V, Bucket,
                 Object_Lock =>
                   Header (Head, "x-amz-bucket-object-lock-enabled") = "true");
               Send_Text (Ch, "200 OK", "");
            end if;
         elsif Method = "HEAD" then
            if Bucket_Exists (V, Bucket) then
               Send_Text (Ch, "200 OK", "");
            else
               Send_Text (Ch, "404 Not Found", "");
            end if;
         elsif Method = "DELETE" then
            Delete_Bucket (V, Bucket);
            Send_Text (Ch, "204 No Content", "");
         elsif Method = "GET" then
            if not Bucket_Exists (V, Bucket) then
               S3_Error (Ch, "404 Not Found", "NoSuchBucket", Path0);
            else
               List_Objects_V2 (Ch, Bucket, Query);
            end if;
         else
            S3_Error (Ch, "405 Method Not Allowed", "MethodNotAllowed", Path0);
         end if;
         return;
      end if;

      --  Object-level operations.
      if not Bucket_Exists (V, Bucket) then
         S3_Error (Ch, "404 Not Found", "NoSuchBucket", Path0);
         return;
      end if;

      if Index (Query, "tagging") /= 0 then
         if Method = "GET" then
            Send_XML (Ch, "200 OK",
              "<?xml version=""1.0"" encoding=""UTF-8""?><Tagging><TagSet/></Tagging>");
         else
            Send_Text (Ch, "204 No Content", "");
         end if;
         return;
      end if;

      --  Multipart upload sub-resources.
      if Query = "uploads" and then Method = "POST" then
         declare
            Up : constant String :=
              Create_Upload (V, Name, (if Locked then Mode else Compliance), Retain);
         begin
            Send_XML (Ch, "200 OK",
              "<?xml version=""1.0"" encoding=""UTF-8""?>"
              & "<InitiateMultipartUploadResult><Bucket>" & Xml_Escape (Bucket)
              & "</Bucket><Key>" & Xml_Escape (Key) & "</Key><UploadId>" & Up
              & "</UploadId></InitiateMultipartUploadResult>");
         end;
         return;
      elsif Uid /= "" then
         if Method = "PUT" then
            declare
               PN_S : constant String := Q_Val (Query, "partNumber=");
               PN   : constant Natural :=
                 (if PN_S = "" then 0 else Natural'Value (PN_S));
            begin
               Upload_Part (V, Uid, Data, Part_Number => PN);
               Send_Text (Ch, "200 OK", "",
                 Extra => "ETag: " & '"' & Uid & "-" & Img (PN) & '"' & CRLF);
            end;
         elsif Method = "POST" then
            Complete_Upload (V, Uid);
            Send_XML (Ch, "200 OK",
              "<?xml version=""1.0"" encoding=""UTF-8""?>"
              & "<CompleteMultipartUploadResult><Location>/" & Xml_Escape (Bucket)
              & "/" & Xml_Escape (Key) & "</Location><Bucket>" & Xml_Escape (Bucket)
              & "</Bucket><Key>" & Xml_Escape (Key) & "</Key><ETag>&quot;"
              & Object_Etag (V, Name) & "&quot;</ETag></CompleteMultipartUploadResult>");
         elsif Method = "DELETE" then
            Abort_Upload (V, Uid);
            Send_Text (Ch, "204 No Content", "");
         else
            S3_Error (Ch, "405 Method Not Allowed", "MethodNotAllowed", Path0);
         end if;
         return;
      end if;

      if Method = "PUT" then
         --  CopyObject if x-amz-copy-source is present.
         declare
            Src : constant String := Header (Head, "x-amz-copy-source");
         begin
            if Locked and then Bucket_Exists (V, Bucket)
              and then Contains (V, Name) and then not Object_Deletable (V, Name)
            then
               S3_Error (Ch, "403 Forbidden", "AccessDenied", Path0);
            elsif Src /= "" then
               declare
                  S0  : constant String :=
                    (if Src (Src'First) = '/' then Src (Src'First + 1 .. Src'Last) else Src);
                  Bytes : constant Stream_Element_Array := Get_Object (V, S0);
               begin
                  Put_Object (V, Name, Bytes, Mode, Retain,
                    User_Meta => Collect_Meta (Head));
                  Send_XML (Ch, "200 OK",
                    "<?xml version=""1.0"" encoding=""UTF-8""?>"
                    & "<CopyObjectResult><LastModified>" & Epoch_Date
                    & "</LastModified><ETag>&quot;" & Object_Etag (V, Name)
                    & "&quot;</ETag></CopyObjectResult>");
               end;
            else
               Put_Object (V, Name, Data, Mode, Retain,
                 User_Meta => Collect_Meta (Head));
               declare
                  VH : constant String :=
                    (if Bucket_Versioned (V, Bucket)
                     then "x-amz-version-id: " & Record_Version (V, Name) & CRLF
                     else "");
               begin
                  Send_Text (Ch, "200 OK", "",
                    Extra => "ETag: " & '"' & Object_Etag (V, Name) & '"' & CRLF & VH);
               end;
            end if;
         end;

      elsif Method = "GET" and then Q_Val (Query, "versionId=") /= "" then
         --  GetObject for a specific version.
         declare
            Bytes : constant Stream_Element_Array :=
              Get_Object_Version (V, Name, Q_Val (Query, "versionId="));
         begin
            Send (Ch, "200 OK", "application/octet-stream", Bytes,
              Extra => "x-amz-version-id: " & Q_Val (Query, "versionId=") & CRLF);
         end;

      elsif Method = "GET" or else Method = "HEAD" then
         if not Contains (V, Name) then
            if Method = "HEAD" then
               Send_Text (Ch, "404 Not Found", "");
            else
               S3_Error (Ch, "404 Not Found", "NoSuchKey", Path0);
            end if;
         else
            declare
               Lock_Hdr : constant String :=
                 (if Locked then "x-amz-object-lock-mode: COMPLIANCE" & CRLF else "");
               --  Stored metadata blob: content-type up to the first LF, then
               --  the x-amz-meta-* header lines to re-emit.
               Blob   : constant String := Object_Meta (V, Name);
               LF_Pos : constant Natural := Index (Blob, (1 => ASCII.LF));
               Raw_CT : constant String :=
                 (if LF_Pos = 0 then "" else Blob (Blob'First .. LF_Pos - 1));
               Meta_X : constant String :=
                 (if LF_Pos = 0 then "" else Blob (LF_Pos + 1 .. Blob'Last));
               Ctype  : constant String :=
                 (if Raw_CT = "" then "application/octet-stream" else Raw_CT);
               ETag_H : constant String :=
                 "ETag: " & '"' & Object_Etag (V, Name) & '"' & CRLF
                 & "Accept-Ranges: bytes" & CRLF & Lock_Hdr & Meta_X;
            begin
               if Method = "HEAD" then
                  Send_Head (Ch, "200 OK", Object_Size (V, Name), ETag_H, Ctype);
               else
                  declare
                     Full  : constant Stream_Element_Array := Get_Object (V, Name);
                     Rng   : constant String := Header (Head, "Range");
                     Total : constant Natural := Natural (Full'Length);
                     First, Last : Natural;
                     Ok    : Boolean;
                  begin
                     if Rng = "" then
                        Send (Ch, "200 OK", Ctype, Full, Extra => ETag_H);
                     else
                        Parse_Range (Rng, Total, First, Last, Ok);
                        if not Ok then
                           Send_Text (Ch, "416 Range Not Satisfiable", "",
                             Extra => "Content-Range: bytes */" & Img (Total) & CRLF);
                        else
                           Send (Ch, "206 Partial Content", Ctype,
                             Full (Full'First + Stream_Element_Offset (First)
                                   .. Full'First + Stream_Element_Offset (Last)),
                             Extra => ETag_H & "Content-Range: bytes " & Img (First)
                                      & "-" & Img (Last) & "/" & Img (Total) & CRLF);
                        end if;
                     end if;
                  end;
               end if;
            end;
         end if;

      elsif Method = "DELETE" then
         if not Contains (V, Name) then
            Send_Text (Ch, "204 No Content", "");   --  S3 delete is idempotent
         elsif Delete_Object (V, Name,
                 Bypass => Header (Head, "X-Dezhan-Bypass") = "true")
         then
            Send_Text (Ch, "204 No Content", "");
         else
            Denied_Deletes := Denied_Deletes + 1;
            S3_Error (Ch, "403 Forbidden", "AccessDenied", Path0);
         end if;

      else
         S3_Error (Ch, "405 Method Not Allowed", "MethodNotAllowed", Path0);
      end if;
   end Handle_S3;

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
      --  Drain the request body (if any). Heap-allocated: a multi-megabyte body
      --  (e.g. a multipart part) would overflow the stack.
      declare
         type SEA_Ptr is access Stream_Element_Array;
         procedure Free is new Ada.Unchecked_Deallocation
           (Stream_Element_Array, SEA_Ptr);
         Body_Ptr : SEA_Ptr :=
           new Stream_Element_Array (1 .. Stream_Element_Offset (Len));
      begin
       declare
         Body_Bytes : Stream_Element_Array renames Body_Ptr.all;
       begin
         if Len > 0 then
            Stream_Element_Array'Read (Ch, Body_Bytes);
         end if;

         --  Keep trusted time current from the real system clock.
         Tick_From_System (V);
         Log ("event=request method=" & Method & " path=" & Path0
              & " bytes=" & Natural'Image (Len));

         --  Authenticate data-plane requests via SigV4 when present: the legacy
         --  /v API and any S3 bucket/key path. Control routes (UI, health,
         --  metrics, admin) are exempt.
         declare
            Is_Control : constant Boolean :=
              Path0 = "/" or else Path0 = "/healthz" or else Path0 = "/metrics"
              or else (Path0'Length >= 6
                       and then Path0 (Path0'First .. Path0'First + 5) = "/admin");
         begin
         if not Is_Control then
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
         end;

         if Method = "GET" and then Path = "/" then
            --  S3 clients (signed/x-amz) get ListBuckets; browsers get the UI.
            if Header (Head, "Authorization") /= ""
              or else Header (Head, "x-amz-date") /= ""
            then
               Handle_S3 (Ch, Method, "/", "", Head, Body_Bytes);
            else
               Send (Ch, "200 OK", "text/html", To_SEA (Index_Html));
            end if;

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
               & Natural'Image (Last_Scrub.Shards_Repaired) & CRLF
               & "# HELP dezhan_storage_bytes Bytes stored on disk under the vault root" & CRLF
               & "# TYPE dezhan_storage_bytes gauge" & CRLF
               & "dezhan_storage_bytes" & Long_Long_Integer'Image (Dir_Bytes (Root)) & CRLF
               & "# HELP dezhan_retention_denied_total Deletes refused by retention/WORM" & CRLF
               & "# TYPE dezhan_retention_denied_total counter" & CRLF
               & "dezhan_retention_denied_total" & Natural'Image (Denied_Deletes) & CRLF
               & "# HELP dezhan_ingest_only One-way ingest mode (reads blocked)" & CRLF
               & "# TYPE dezhan_ingest_only gauge" & CRLF
               & "dezhan_ingest_only" & (if One_Way_Ingest (V) then " 1" else " 0") & CRLF
               & "# HELP dezhan_sync_window_open Sync window currently open" & CRLF
               & "# TYPE dezhan_sync_window_open gauge" & CRLF
               & "dezhan_sync_window_open"
               & (if Sync_Window_Open (V) then " 1" else " 0") & CRLF);

         elsif Method = "POST" and then Path = "/admin/tick" then
            Send_Text (Ch, "200 OK", "trusted_time" & Trusted_Time'Image (Now (V)));

         elsif Method = "POST" and then Path = "/admin/seal" then
            Seal (V);
            Send_Text (Ch, "200 OK", "vault sealed (read-only)");

         elsif Method = "POST" and then Path = "/admin/checkpoint" then
            Make_Checkpoint (V);
            Send_Text (Ch, "200 OK",
              "checkpoint signed; public_key=" & Checkpoint_Public_Key (V));

         elsif Method = "GET" and then Path = "/admin/checkpoint-key" then
            Send_Text (Ch, "200 OK", Checkpoint_Public_Key (V));

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
                  if not Contains (V, Name) then
                     Send_Text (Ch, "404 Not Found", "no such object");
                  else
                     declare
                        Full : constant Stream_Element_Array :=
                          Get_Object (V, Name);
                        Rng  : constant String := Header (Head, "Range");
                        Tag  : constant String :=
                          "ETag: " & '"' & Object_Etag (V, Name) & '"' & CRLF
                          & "Accept-Ranges: bytes" & CRLF;
                        Total : constant Natural := Natural (Full'Length);
                     begin
                        if Rng = "" then
                           Send (Ch, "200 OK", "application/octet-stream",
                                 Full, Extra => Tag);
                        else
                           declare
                              First, Last : Natural;
                              Ok          : Boolean;
                           begin
                              Parse_Range (Rng, Total, First, Last, Ok);
                              if not Ok then
                                 Send_Text (Ch, "416 Range Not Satisfiable", "",
                                   Extra => "Content-Range: bytes */"
                                            & Img (Total) & CRLF);
                              else
                                 Send (Ch, "206 Partial Content",
                                   "application/octet-stream",
                                   Full (Full'First + Stream_Element_Offset (First)
                                         .. Full'First + Stream_Element_Offset (Last)),
                                   Extra => Tag & "Content-Range: bytes "
                                            & Img (First) & "-" & Img (Last)
                                            & "/" & Img (Total) & CRLF);
                              end if;
                           end;
                        end if;
                     end;
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
                     Denied_Deletes := Denied_Deletes + 1;
                     Send_Text (Ch, "403 Forbidden",
                       "object is retained and cannot be deleted yet");
                  end if;

               else
                  Send_Text (Ch, "405 Method Not Allowed", "");
               end if;
            end;

         else
            --  Any non-reserved path is an S3 bucket/key request.
            Handle_S3 (Ch, Method, Path0, PQuery, Head, Body_Bytes);
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
         when Bucket_Not_Empty =>
            Send_Text (Ch, "409 Conflict", "bucket not empty");
         when Bucket_Exists_Error =>
            Send_Text (Ch, "409 Conflict", "bucket already exists");
       end;
       Free (Body_Ptr);
      exception
         when others => Free (Body_Ptr); raise;
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
