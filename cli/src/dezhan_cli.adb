pragma Ada_2022;
--  Minimal command-line client for the dezhan server (POC). Talks plain HTTP
--  over GNAT.Sockets; no external dependency. Set DEZHAN_ADDR=host:port to point
--  elsewhere (default 127.0.0.1:8080).
--
--  Usage:
--    dezhan_cli health
--    dezhan_cli metrics
--    dezhan_cli put <name> <data> [compliance|governance] [retain_seconds]
--    dezhan_cli get <name>
--    dezhan_cli del <name> [bypass]
with Ada.Text_IO;          use Ada.Text_IO;
with Ada.Command_Line;     use Ada.Command_Line;
with Ada.Strings.Fixed;    use Ada.Strings.Fixed;
with Ada.Environment_Variables;
with Ada.Exceptions;       use Ada.Exceptions;
with GNAT.Sockets;         use GNAT.Sockets;

procedure Dezhan_Cli is

   CRLF : constant String := ASCII.CR & ASCII.LF;

   function Env_Addr return String is
     (if Ada.Environment_Variables.Exists ("DEZHAN_ADDR")
      then Ada.Environment_Variables.Value ("DEZHAN_ADDR")
      else "127.0.0.1:8080");

   --  Send Request, return the full response, print only the body.
   procedure Round_Trip (Request : String) is
      Addr   : constant String  := Env_Addr;
      Colon  : constant Natural := Index (Addr, ":");
      Host   : constant String  := Addr (Addr'First .. Colon - 1);
      Port   : constant Port_Type := Port_Type'Value (Addr (Colon + 1 .. Addr'Last));
      Sock   : Socket_Type;
      Ch     : Stream_Access;
      C      : Character;
      Resp   : String (1 .. 1_000_000);
      Last   : Natural := 0;
   begin
      Create_Socket (Sock);
      Connect_Socket (Sock, (Family_Inet, Inet_Addr (Host), Port));
      Ch := Stream (Sock);
      String'Write (Ch, Request);

      begin
         loop
            Character'Read (Ch, C);
            if Last < Resp'Last then
               Last := Last + 1;
               Resp (Last) := C;
            end if;
         end loop;
      exception
         when others => null;  --  connection closed by server
      end;
      Close_Socket (Sock);

      declare
         Sep : constant Natural := Index (Resp (1 .. Last), CRLF & CRLF);
      begin
         if Sep = 0 then
            Put (Resp (1 .. Last));
         else
            Put (Resp (Sep + 4 .. Last));
         end if;
      end;
      New_Line;
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
      Put_Line ("usage: dezhan_cli health|metrics|put|get|del ...");
      Set_Exit_Status (Failure);
      return;
   end if;

   declare
      Cmd : constant String := Argument (1);
   begin
      if Cmd = "health" then
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
