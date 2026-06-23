pragma Ada_2022;
--  Test utility: deflate/inflate a file, for zlib interop checks.
--    deflate_tool def|inf <input> <output>
with Ada.Command_Line;      use Ada.Command_Line;
with Ada.Streams;           use Ada.Streams;
with Ada.Streams.Stream_IO; use Ada.Streams.Stream_IO;
with Dezhan.Storage.Deflate; use Dezhan.Storage.Deflate;

procedure Deflate_Tool is

   function Read_File (Path : String) return Buffer is
      F : File_Type;
   begin
      Open (F, In_File, Path);
      declare
         Len : constant Natural := Natural (Stream_IO.Size (F));
         SEA : Stream_Element_Array (1 .. Stream_Element_Offset (Len));
         Last : Stream_Element_Offset;
         R   : Buffer (0 .. Len - 1);
      begin
         Read (F, SEA, Last);
         Close (F);
         for I in 0 .. Natural (Last) - 1 loop
            R (I) := Octet (SEA (Stream_Element_Offset (I + 1)));
         end loop;
         return R (0 .. Natural (Last) - 1);
      end;
   end Read_File;

   procedure Write_File (Path : String; B : Buffer) is
      F : File_Type;
      SEA : Stream_Element_Array (1 .. Stream_Element_Offset (B'Length));
   begin
      for I in 0 .. B'Length - 1 loop
         SEA (Stream_Element_Offset (I + 1)) := Stream_Element (B (B'First + I));
      end loop;
      Create (F, Out_File, Path);
      Write (F, SEA);
      Close (F);
   end Write_File;

begin
   if Argument_Count /= 3 then
      Set_Exit_Status (Failure);
      return;
   end if;
   declare
      Input : constant Buffer := Read_File (Argument (2));
   begin
      if Argument (1) = "def" then
         Write_File (Argument (3), Deflate (Input));
      else
         Write_File (Argument (3), Inflate (Input));
      end if;
   end;
end Deflate_Tool;
