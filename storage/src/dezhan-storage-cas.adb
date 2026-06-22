with Interfaces;                  use Interfaces;
with Ada.Directories;             use Ada.Directories;
with Ada.Streams.Stream_IO;       use Ada.Streams.Stream_IO;
with Dezhan.Trusted_Core.Hashing; use Dezhan.Trusted_Core.Hashing;

package body Dezhan.Storage.Cas with SPARK_Mode => Off is

   Hex_Digits : constant String   := "0123456789abcdef";
   Zero_Nonce : constant Nonce_96 := (others => 0);
   Zero_Key   : constant Key_256  := (others => 0);

   --  ChaCha20 counter base for chunk C: 4096-byte chunks are 64 keystream
   --  blocks, so each chunk gets a disjoint keystream range.
   function Counter_For (C : Natural) return Unsigned_32 is
     (Unsigned_32 (C) * 64);

   function To_Hex (D : Digest) return Object_Id is
      R : Object_Id := (others => '0');
   begin
      for I in D'Range loop
         R (I * 2 + 1) := Hex_Digits (Integer (D (I) / 16) + 1);
         R (I * 2 + 2) := Hex_Digits (Integer (D (I) mod 16) + 1);
      end loop;
      return R;
   end To_Hex;

   function To_Bytes (S : Stream_Element_Array) return Byte_Array is
      R : Byte_Array (0 .. Natural (S'Length) - 1);
      J : Natural := 0;
   begin
      for I in S'Range loop
         R (J) := Byte (S (I));
         J := J + 1;
      end loop;
      return R;
   end To_Bytes;

   function To_Stream (B : Byte_Array) return Stream_Element_Array is
      R : Stream_Element_Array (1 .. Stream_Element_Offset (B'Length));
      J : Stream_Element_Offset := 1;
   begin
      for I in B'Range loop
         R (J) := Stream_Element (B (I));
         J := J + 1;
      end loop;
      return R;
   end To_Stream;

   procedure Write_File (Path : String; Data : Stream_Element_Array) is
      F : File_Type;
   begin
      Create_Path (Containing_Directory (Path));
      Create (F, Out_File, Path);
      Write (F, Data);
      Close (F);
   end Write_File;

   function Read_File (Path : String) return Stream_Element_Array is
      F    : File_Type;
      Size : constant Stream_Element_Offset :=
        Stream_Element_Offset (Ada.Directories.Size (Path));
   begin
      Open (F, In_File, Path);
      declare
         Buf  : Stream_Element_Array (1 .. Size);
         Last : Stream_Element_Offset;
      begin
         Read (F, Buf, Last);
         Close (F);
         return Buf (1 .. Last);
      end;
   end Read_File;

   function Object_Path (Root, Hex : String) return String is
     (Compose (Compose (Compose (Root, "objects"), Hex (Hex'First .. Hex'First + 1)), Hex));

   function Manifest_Path (Root, Hex : String) return String is
     (Compose (Compose (Root, "manifests"), Hex));

   procedure Initialize (Root : String) is
   begin
      Create_Path (Compose (Root, "objects"));
      Create_Path (Compose (Root, "manifests"));
   end Initialize;

   procedure Put_U64 (Into : in out Byte_Array; Off : Natural; V : Unsigned_64) is
   begin
      for I in 0 .. 7 loop
         Into (Off + I) := Byte (Shift_Right (V, 8 * (7 - I)) and 16#FF#);
      end loop;
   end Put_U64;

   function Get_U64 (From : Byte_Array; Off : Natural) return Unsigned_64 is
      V : Unsigned_64 := 0;
   begin
      for I in 0 .. 7 loop
         V := Shift_Left (V, 8) or Unsigned_64 (From (Off + I));
      end loop;
      return V;
   end Get_U64;

   function Put
     (Root : String; Key : Key_256; Data : Stream_Element_Array)
      return Object_Id
   is
      Len      : constant Natural := Natural (Data'Length);
      N_Chunks : constant Natural := (Len + Chunk_Size - 1) / Chunk_Size;
   begin
      if 8 + N_Chunks * 32 > Max_Message then
         raise Object_Too_Large;
      end if;

      declare
         Manifest : Byte_Array (0 .. 8 + N_Chunks * 32 - 1) := (others => 0);
      begin
         Put_U64 (Manifest, 0, Unsigned_64 (Len));

         for C in 0 .. N_Chunks - 1 loop
            declare
               First : constant Stream_Element_Offset :=
                 Data'First + Stream_Element_Offset (C * Chunk_Size);
               Last  : Stream_Element_Offset :=
                 First + Stream_Element_Offset (Chunk_Size) - 1;
            begin
               if Last > Data'Last then
                  Last := Data'Last;
               end if;
               declare
                  Bytes : Byte_Array := To_Bytes (Data (First .. Last));
               begin
                  --  Encrypt at source, then address and store the cipher text.
                  XCrypt (Key, Zero_Nonce, Counter_For (C), Bytes);
                  declare
                     CD   : constant Digest    := SHA256 (Bytes);
                     Hex  : constant Object_Id := To_Hex (CD);
                     Path : constant String    := Object_Path (Root, Hex);
                  begin
                     if not Exists (Path) then
                        Write_File (Path, To_Stream (Bytes));
                     end if;
                     for I in 0 .. 31 loop
                        Manifest (8 + C * 32 + I) := CD (I);
                     end loop;
                  end;
               end;
            end;
         end loop;

         declare
            MD   : constant Digest    := SHA256 (Manifest);
            MHex : constant Object_Id := To_Hex (MD);
         begin
            Write_File (Manifest_Path (Root, MHex), To_Stream (Manifest));
            return MHex;
         end;
      end;
   end Put;

   --  Shared reader for Get and Verify. Verifies the manifest and every
   --  cipher-text chunk against its digest. If Reassemble, decrypts with Key and
   --  returns the plaintext; otherwise returns an empty array. Raises
   --  Corruption_Detected on any mismatch.
   function Load
     (Root : String; Key : Key_256; Id : Object_Id; Reassemble : Boolean)
      return Stream_Element_Array
   is
      Manifest_Bytes : constant Byte_Array :=
        To_Bytes (Read_File (Manifest_Path (Root, Id)));
   begin
      if To_Hex (SHA256 (Manifest_Bytes)) /= Id then
         raise Corruption_Detected;
      end if;

      declare
         Len      : constant Natural := Natural (Get_U64 (Manifest_Bytes, 0));
         N_Chunks : constant Natural := (Len + Chunk_Size - 1) / Chunk_Size;
         Result   : Stream_Element_Array (1 .. Stream_Element_Offset (Len));
         Pos      : Stream_Element_Offset := 1;
      begin
         for C in 0 .. N_Chunks - 1 loop
            declare
               CD : Digest;
            begin
               for I in 0 .. 31 loop
                  CD (I) := Manifest_Bytes (8 + C * 32 + I);
               end loop;
               declare
                  Hex   : constant Object_Id := To_Hex (CD);
                  Bytes : Byte_Array :=
                    To_Bytes (Read_File (Object_Path (Root, Hex)));
               begin
                  if SHA256 (Bytes) /= CD then
                     raise Corruption_Detected;  --  cipher-text integrity
                  end if;
                  if Reassemble then
                     XCrypt (Key, Zero_Nonce, Counter_For (C), Bytes);  --  decrypt
                     for I in Bytes'Range loop
                        Result (Pos + Stream_Element_Offset (I)) :=
                          Stream_Element (Bytes (I));
                     end loop;
                  end if;
                  Pos := Pos + Stream_Element_Offset (Bytes'Length);
               end;
            end;
         end loop;

         if Reassemble then
            return Result;
         else
            return (1 .. 0 => 0);
         end if;
      end;
   end Load;

   function Get
     (Root : String; Key : Key_256; Id : Object_Id)
      return Stream_Element_Array is
     (Load (Root, Key, Id, Reassemble => True));

   function Verify (Root : String; Id : Object_Id) return Boolean is
   begin
      declare
         Ignored : constant Stream_Element_Array :=
           Load (Root, Zero_Key, Id, Reassemble => False);
         pragma Unreferenced (Ignored);
      begin
         return True;
      end;
   exception
      when others =>
         return False;
   end Verify;

end Dezhan.Storage.Cas;
