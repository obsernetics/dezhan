with Interfaces;                  use Interfaces;
with Ada.Strings;                 use Ada.Strings;
with Ada.Strings.Fixed;           use Ada.Strings.Fixed;
with Ada.Directories;             use Ada.Directories;
with Ada.Streams.Stream_IO;       use Ada.Streams.Stream_IO;
with Ada.Containers.Indefinite_Ordered_Sets;
with Ada.Containers.Indefinite_Vectors;
with Dezhan.Trusted_Core.Hashing; use Dezhan.Trusted_Core.Hashing;
with Dezhan.Trusted_Core.Erasure; use Dezhan.Trusted_Core.Erasure;

package body Dezhan.Storage.Cas with SPARK_Mode => Off is

   Hex_Digits : constant String   := "0123456789abcdef";
   Zero_Nonce : constant Nonce_96 := (others => 0);
   Zero_Key   : constant Key_256  := (others => 0);

   --  Reed-Solomon shard layout: a blob (chunk or manifest) is split into K data
   --  shards of EC_SL bytes (one per EC_SL of length) plus EC_M parity shards.
   --  Any K of the K+M shards reconstruct the blob, so up to EC_M lost or corrupt
   --  shards are recoverable. A full Chunk_Size chunk yields Chunk_Size/EC_SL = 4
   --  data shards; a manifest yields up to 8.
   EC_M  : constant := 2;       --  parity shards per blob
   EC_SL : constant := 1024;    --  shard length in bytes

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

   --  Shard file name within a shard directory: "1".."10", then "idx".
   function Shard_Name (S : Positive) return String is
     (Trim (S'Image, Both));

   --  Store Data in directory Dir as K data + EC_M parity shards (K = one shard
   --  per EC_SL bytes), with an "idx" file holding the length, K, M, and
   --  per-shard digests. Used for chunks and manifests alike.
   procedure Store_Shards (Dir : String; Data : Stream_Element_Array) is
      Len : constant Natural  := Natural (Data'Length);
      K   : constant Positive := Natural'Max (1, (Len + EC_SL - 1) / EC_SL);
      M   : constant Positive := EC_M;
      N   : constant Positive := K + M;
   begin
      if Exists (Dir) then
         return;  --  deduplicated
      end if;
      declare
         DB     : Data_Block := (others => (others => 0));
         Parity : Parity_Block;
         Idx    : Byte_Array (0 .. 6 + N * 32 - 1) := (others => 0);
      begin
         for I in 0 .. Len - 1 loop
            DB (I / EC_SL + 1, I mod EC_SL + 1) :=
              Symbol (Data (Data'First + Stream_Element_Offset (I)));
         end loop;
         Encode (K, M, EC_SL, DB, Parity);

         Create_Path (Dir);
         Idx (0) := Byte (Shift_Right (Unsigned_32 (Len), 24) and 16#FF#);
         Idx (1) := Byte (Shift_Right (Unsigned_32 (Len), 16) and 16#FF#);
         Idx (2) := Byte (Shift_Right (Unsigned_32 (Len), 8)  and 16#FF#);
         Idx (3) := Byte (Unsigned_32 (Len) and 16#FF#);
         Idx (4) := Byte (K);
         Idx (5) := Byte (M);

         for S in 1 .. N loop
            declare
               Shard : Stream_Element_Array (1 .. EC_SL);
            begin
               for C in 1 .. EC_SL loop
                  Shard (Stream_Element_Offset (C)) :=
                    Stream_Element
                      (if S <= K then DB (S, C) else Parity (S - K, C));
               end loop;
               Write_File (Compose (Dir, Shard_Name (S)), Shard);
               declare
                  H : constant Digest := SHA256 (To_Bytes (Shard));
               begin
                  for I in 0 .. 31 loop
                     Idx (6 + (S - 1) * 32 + I) := H (I);
                  end loop;
               end;
            end;
         end loop;
         Write_File (Compose (Dir, "idx"), To_Stream (Idx));
      end;
   end Store_Shards;

   --  Read a blob back from its shard directory, reconstructing from parity if
   --  up to M shards are missing or fail their digest. Raises Corruption_Detected
   --  if unrecoverable.
   function Read_Shards (Dir : String) return Stream_Element_Array is
      Idx : constant Byte_Array := To_Bytes (Read_File (Compose (Dir, "idx")));
      Len : constant Natural :=
        Natural (Shift_Left (Unsigned_32 (Idx (0)), 24)
                 or Shift_Left (Unsigned_32 (Idx (1)), 16)
                 or Shift_Left (Unsigned_32 (Idx (2)), 8)
                 or Unsigned_32 (Idx (3)));
      K : constant Positive := Positive (Idx (4));
      M : constant Positive := Positive (Idx (5));
      N : constant Positive := K + M;
      Present : Present_Map := (others => False);
      Shards  : Shard_Block := (others => (others => 0));
      Data    : Data_Block;
      Ok      : Boolean;
   begin
      for S in 1 .. N loop
         declare
            File : constant String := Compose (Dir, Shard_Name (S));
         begin
            if Exists (File) then
               declare
                  SB    : constant Byte_Array := To_Bytes (Read_File (File));
                  Valid : Boolean := SB'Length = EC_SL;
               begin
                  if Valid then
                     declare
                        H : constant Digest := SHA256 (SB);
                     begin
                        for I in 0 .. 31 loop
                           if H (I) /= Idx (6 + (S - 1) * 32 + I) then
                              Valid := False;
                           end if;
                        end loop;
                     end;
                  end if;
                  if Valid then
                     Present (S) := True;
                     for C in 1 .. EC_SL loop
                        Shards (S, C) := SB (C - 1);
                     end loop;
                  end if;
               end;
            end if;
         end;
      end loop;

      Reconstruct (K, M, EC_SL, Present, Shards, Data, Ok);
      if not Ok then
         raise Corruption_Detected;
      end if;

      declare
         R : Stream_Element_Array (1 .. Stream_Element_Offset (Len));
      begin
         for I in 0 .. Len - 1 loop
            R (Stream_Element_Offset (I + 1)) :=
              Stream_Element (Data (I / EC_SL + 1, I mod EC_SL + 1));
         end loop;
         return R;
      end;
   end Read_Shards;

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
                     CD  : constant Digest    := SHA256 (Bytes);
                     Hex : constant Object_Id := To_Hex (CD);
                  begin
                     Store_Shards (Object_Path (Root, Hex), To_Stream (Bytes));
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
            Store_Shards (Manifest_Path (Root, MHex), To_Stream (Manifest));
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
        To_Bytes (Read_Shards (Manifest_Path (Root, Id)));
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
                    To_Bytes (Read_Shards (Object_Path (Root, Hex)));
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

   package Hex_Sets is new Ada.Containers.Indefinite_Ordered_Sets (String);
   package Str_Vecs is new Ada.Containers.Indefinite_Vectors (Natural, String);

   procedure Collect_Garbage
     (Root : String; Live : Id_List; Reclaimed : out Natural)
   is
      Reach_M : Hex_Sets.Set;   --  reachable manifest ids
      Reach_C : Hex_Sets.Set;   --  reachable chunk hexes
      Dead_M  : Str_Vecs.Vector;  --  manifest files to delete
      Dead_C  : Str_Vecs.Vector;  --  chunk dirs to delete
   begin
      Reclaimed := 0;

      --  Mark: each live manifest and the chunks it references.
      for I in Live'Range loop
         Reach_M.Include (String (Live (I)));
         begin
            declare
               MB  : constant Byte_Array :=
                 To_Bytes (Read_Shards (Manifest_Path (Root, String (Live (I)))));
               Len : constant Natural := Natural (Get_U64 (MB, 0));
               N   : constant Natural := (Len + Chunk_Size - 1) / Chunk_Size;
            begin
               for C in 0 .. N - 1 loop
                  declare
                     CD : Digest;
                  begin
                     for J in 0 .. 31 loop
                        CD (J) := MB (8 + C * 32 + J);
                     end loop;
                     Reach_C.Include (String (To_Hex (CD)));
                  end;
               end loop;
            end;
         exception
            when others => null;  --  manifest missing/unreadable: skip
         end;
      end loop;

      --  Sweep manifests (each is now a shard directory named by its id).
      if Exists (Compose (Root, "manifests")) then
         declare
            S : Search_Type;
            E : Directory_Entry_Type;
         begin
            Start_Search (S, Compose (Root, "manifests"), "",
                          (Directory => True, others => False));
            while More_Entries (S) loop
               Get_Next_Entry (S, E);
               if Simple_Name (E) /= "." and then Simple_Name (E) /= ".."
                 and then not Reach_M.Contains (Simple_Name (E))
               then
                  Dead_M.Append (Full_Name (E));
               end if;
            end loop;
            End_Search (S);
         end;
      end if;

      --  Sweep chunk directories (objects/<2hex>/<64hex>).
      if Exists (Compose (Root, "objects")) then
         declare
            L1 : Search_Type;
            D1 : Directory_Entry_Type;
         begin
            Start_Search (L1, Compose (Root, "objects"), "",
                          (Directory => True, others => False));
            while More_Entries (L1) loop
               Get_Next_Entry (L1, D1);
               if Simple_Name (D1) /= "." and then Simple_Name (D1) /= ".." then
                  declare
                     L2 : Search_Type;
                     D2 : Directory_Entry_Type;
                  begin
                     Start_Search (L2, Full_Name (D1), "",
                                   (Directory => True, others => False));
                     while More_Entries (L2) loop
                        Get_Next_Entry (L2, D2);
                        if Simple_Name (D2) /= "."
                          and then Simple_Name (D2) /= ".."
                          and then not Reach_C.Contains (Simple_Name (D2))
                        then
                           Dead_C.Append (Full_Name (D2));
                        end if;
                     end loop;
                     End_Search (L2);
                  end;
               end if;
            end loop;
            End_Search (L1);
         end;
      end if;

      --  Delete after searching (avoid mutating dirs mid-iteration). Manifests
      --  and chunks are both shard directories now.
      for P of Dead_M loop
         Delete_Tree (P);
         Reclaimed := Reclaimed + 1;
      end loop;
      for P of Dead_C loop
         Delete_Tree (P);
         Reclaimed := Reclaimed + 1;
      end loop;
   end Collect_Garbage;

end Dezhan.Storage.Cas;
