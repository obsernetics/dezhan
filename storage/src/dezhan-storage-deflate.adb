with Interfaces;             use Interfaces;
with Ada.Containers.Vectors;
with Ada.Unchecked_Deallocation;

package body Dezhan.Storage.Deflate with SPARK_Mode => Off is

   type Int_Array is array (Natural range <>) of Integer;
   type Int_Ptr   is access Int_Array;
   procedure Free is new Ada.Unchecked_Deallocation (Int_Array, Int_Ptr);

   package Byte_Vec is new Ada.Containers.Vectors (Natural, Octet);
   use Byte_Vec;

   --  RFC 1951 length/distance base values and extra-bit counts.
   type Nat_Array is array (Natural range <>) of Natural;

   Len_Base : constant Nat_Array (0 .. 28) :=
     (3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59,
      67, 83, 99, 115, 131, 163, 195, 227, 258);
   Len_Extra : constant Nat_Array (0 .. 28) :=
     (0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3,
      4, 4, 4, 4, 5, 5, 5, 5, 0);
   Dist_Base : constant Nat_Array (0 .. 29) :=
     (1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513,
      769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577);
   Dist_Extra : constant Nat_Array (0 .. 29) :=
     (0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8,
      9, 9, 10, 10, 11, 11, 12, 12, 13, 13);

   ------------------------------------------------------------------ Inflate

   function Inflate (Data : Buffer) return Buffer is
      In_Pos  : Natural := Data'First;
      Bit_Buf : Unsigned_32 := 0;
      Bit_Cnt : Natural := 0;
      Out_V   : Vector;

      function Bits (Need : Natural) return Natural is
      begin
         while Bit_Cnt < Need loop
            if In_Pos > Data'Last then
               raise Format_Error;
            end if;
            Bit_Buf := Bit_Buf or Shift_Left (Unsigned_32 (Data (In_Pos)), Bit_Cnt);
            In_Pos  := In_Pos + 1;
            Bit_Cnt := Bit_Cnt + 8;
         end loop;
         declare
            Val : constant Unsigned_32 := Bit_Buf and (Shift_Left (1, Need) - 1);
         begin
            Bit_Buf := Shift_Right (Bit_Buf, Need);
            Bit_Cnt := Bit_Cnt - Need;
            return Natural (Val);
         end;
      end Bits;

      type Count_Array is array (0 .. 15) of Natural;
      type Sym_Array   is array (0 .. 319) of Natural;
      type Huffman is record
         Count  : Count_Array := (others => 0);
         Symbol : Sym_Array   := (others => 0);
      end record;

      procedure Construct (H : out Huffman; Lengths : Nat_Array) is
         Offs : Count_Array := (others => 0);
      begin
         H.Count := (others => 0);
         for S in Lengths'Range loop
            H.Count (Lengths (S)) := H.Count (Lengths (S)) + 1;
         end loop;
         Offs (1) := 0;
         for L in 1 .. 14 loop
            Offs (L + 1) := Offs (L) + H.Count (L);
         end loop;
         for S in Lengths'Range loop
            if Lengths (S) /= 0 then
               H.Symbol (Offs (Lengths (S))) := S - Lengths'First;
               Offs (Lengths (S)) := Offs (Lengths (S)) + 1;
            end if;
         end loop;
      end Construct;

      function Decode (H : Huffman) return Integer is
         Code  : Integer := 0;
         First : Integer := 0;
         Index : Integer := 0;
         Cnt   : Integer;
      begin
         for Len in 1 .. 15 loop
            Code := Code + Bits (1);
            Cnt  := H.Count (Len);
            if Code - Cnt < First then
               return H.Symbol (Index + (Code - First));
            end if;
            Index := Index + Cnt;
            First := First + Cnt;
            First := First * 2;
            Code  := Code * 2;
         end loop;
         raise Format_Error;
      end Decode;

      procedure Codes (Len_Code, Dist_Code : Huffman) is
         Sym  : Integer;
         Len  : Integer;
         Dist : Integer;
      begin
         loop
            Sym := Decode (Len_Code);
            if Sym = 256 then
               exit;
            elsif Sym < 256 then
               Out_V.Append (Octet (Sym));
            else
               Sym := Sym - 257;
               if Sym > 28 then
                  raise Format_Error;
               end if;
               Len := Len_Base (Sym) + Bits (Len_Extra (Sym));
               Sym := Decode (Dist_Code);
               if Sym > 29 then
                  raise Format_Error;
               end if;
               Dist := Dist_Base (Sym) + Bits (Dist_Extra (Sym));
               if Dist > Natural (Out_V.Length) then
                  raise Format_Error;
               end if;
               for I in 1 .. Len loop
                  Out_V.Append (Out_V.Element (Out_V.Last_Index - Dist + 1));
               end loop;
            end if;
         end loop;
      end Codes;

      procedure Fixed_Block is
         LL : Nat_Array (0 .. 287);
         DL : constant Nat_Array (0 .. 29) := (others => 5);
         Lit, Dist : Huffman;
      begin
         for S in 0 .. 143 loop LL (S) := 8; end loop;
         for S in 144 .. 255 loop LL (S) := 9; end loop;
         for S in 256 .. 279 loop LL (S) := 7; end loop;
         for S in 280 .. 287 loop LL (S) := 8; end loop;
         Construct (Lit, LL);
         Construct (Dist, DL);
         Codes (Lit, Dist);
      end Fixed_Block;

      procedure Dynamic_Block is
         Order : constant Nat_Array (0 .. 18) :=
           (16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15);
         HLIT  : constant Natural := Bits (5) + 257;
         HDIST : constant Natural := Bits (5) + 1;
         HCLEN : constant Natural := Bits (4) + 4;
         CL_Lengths : Nat_Array (0 .. 18) := (others => 0);
         All_Lengths : Nat_Array (0 .. HLIT + HDIST - 1) := (others => 0);
         CL_Huff : Huffman;
         Idx : Natural := 0;
      begin
         for I in 0 .. HCLEN - 1 loop
            CL_Lengths (Order (I)) := Bits (3);
         end loop;
         Construct (CL_Huff, CL_Lengths);
         while Idx < HLIT + HDIST loop
            declare
               Sym : constant Integer := Decode (CL_Huff);
               Rep : Natural;
               Val : Natural := 0;
            begin
               if Sym < 16 then
                  All_Lengths (Idx) := Natural (Sym);
                  Idx := Idx + 1;
               else
                  if Sym = 16 then
                     if Idx = 0 then raise Format_Error; end if;
                     Val := All_Lengths (Idx - 1);
                     Rep := Bits (2) + 3;
                  elsif Sym = 17 then
                     Rep := Bits (3) + 3;
                  else
                     Rep := Bits (7) + 11;
                  end if;
                  for I in 1 .. Rep loop
                     if Idx >= HLIT + HDIST then raise Format_Error; end if;
                     All_Lengths (Idx) := Val;
                     Idx := Idx + 1;
                  end loop;
               end if;
            end;
         end loop;
         declare
            Lit  : Huffman;
            Dist : Huffman;
         begin
            Construct (Lit, All_Lengths (0 .. HLIT - 1));
            Construct (Dist, All_Lengths (HLIT .. HLIT + HDIST - 1));
            Codes (Lit, Dist);
         end;
      end Dynamic_Block;

      Final : Natural;
      BType : Natural;
   begin
      loop
         Final := Bits (1);
         BType := Bits (2);
         case BType is
            when 0 =>
               Bit_Buf := 0;
               Bit_Cnt := 0;
               if In_Pos + 3 > Data'Last then
                  raise Format_Error;
               end if;
               declare
                  Len : constant Natural :=
                    Natural (Data (In_Pos)) + Natural (Data (In_Pos + 1)) * 256;
               begin
                  In_Pos := In_Pos + 4;  --  skip LEN, NLEN
                  for I in 1 .. Len loop
                     if In_Pos > Data'Last then raise Format_Error; end if;
                     Out_V.Append (Data (In_Pos));
                     In_Pos := In_Pos + 1;
                  end loop;
               end;
            when 1 =>
               Fixed_Block;
            when 2 =>
               Dynamic_Block;
            when others =>
               raise Format_Error;
         end case;
         exit when Final = 1;
      end loop;

      declare
         R : Buffer (0 .. Natural (Out_V.Length) - 1);
      begin
         for I in R'Range loop
            R (I) := Out_V.Element (I);
         end loop;
         return R;
      end;
   exception
      --  Any malformed stream (including wrong-key garbage) surfaces as
      --  Format_Error, never a stray Constraint_Error from an internal index.
      when Format_Error => raise;
      when others       => raise Format_Error;
   end Inflate;

   ------------------------------------------------------------------ Deflate

   function Deflate (Data : Buffer) return Buffer is
      Out_V : Vector;
      Acc   : Unsigned_32 := 0;
      NBits : Natural := 0;

      procedure Put_Bits (Value : Natural; Count : Natural) is
      begin
         Acc := Acc or Shift_Left (Unsigned_32 (Value), NBits);
         NBits := NBits + Count;
         while NBits >= 8 loop
            Out_V.Append (Octet (Acc and 16#FF#));
            Acc := Shift_Right (Acc, 8);
            NBits := NBits - 8;
         end loop;
      end Put_Bits;

      function Reverse_Bits (Value, Count : Natural) return Natural is
         R : Natural := 0;
         V : Natural := Value;
      begin
         for I in 1 .. Count loop
            R := R * 2 + (V mod 2);
            V := V / 2;
         end loop;
         return R;
      end Reverse_Bits;

      --  Emit a fixed-Huffman literal/length symbol (Huffman codes are MSB-first,
      --  so reverse before writing into the LSB-first bit stream).
      procedure Put_LitLen (Sym : Natural) is
      begin
         if Sym <= 143 then
            Put_Bits (Reverse_Bits (16#30# + Sym, 8), 8);
         elsif Sym <= 255 then
            Put_Bits (Reverse_Bits (16#190# + (Sym - 144), 9), 9);
         elsif Sym <= 279 then
            Put_Bits (Reverse_Bits (Sym - 256, 7), 7);
         else
            Put_Bits (Reverse_Bits (16#C0# + (Sym - 280), 8), 8);
         end if;
      end Put_Litlen;

      procedure Emit_Literal (B : Octet) is
      begin
         Put_LitLen (Natural (B));
      end Emit_Literal;

      procedure Emit_Match (Len, Dist : Natural) is
         LS : Natural := 28;
         DS : Natural := 29;
      begin
         for S in 0 .. 28 loop
            if Len <= Len_Base (S) + (2 ** Len_Extra (S) - 1)
              and then Len >= Len_Base (S)
            then
               LS := S; exit;
            end if;
         end loop;
         Put_LitLen (257 + LS);
         Put_Bits (Len - Len_Base (LS), Len_Extra (LS));
         for S in 0 .. 29 loop
            if Dist <= Dist_Base (S) + (2 ** Dist_Extra (S) - 1)
              and then Dist >= Dist_Base (S)
            then
               DS := S; exit;
            end if;
         end loop;
         Put_Bits (Reverse_Bits (DS, 5), 5);
         Put_Bits (Dist - Dist_Base (DS), Dist_Extra (DS));
      end Emit_Match;

      --  LZ77 with a hash-chain over 3-byte prefixes. Prev is sized to the input
      --  length, so it is heap-allocated: on a multi-megabyte object it would
      --  otherwise overflow the stack.
      Hash_Size  : constant := 2 ** 15;
      Max_Chain  : constant := 128;
      Head   : array (0 .. Hash_Size - 1) of Integer := (others => -1);
      Prev_P : Int_Ptr := new Int_Array'(0 .. Integer'Max (Data'Length, 1) - 1 => -1);
      Prev   : Int_Array renames Prev_P.all;

      function Hash3 (P : Natural) return Natural is
        (Natural ((Shift_Left (Unsigned_32 (Data (P)), 10)
                   xor Shift_Left (Unsigned_32 (Data (P + 1)), 5)
                   xor Unsigned_32 (Data (P + 2))) and (Hash_Size - 1)));

      Pos  : Natural := Data'First;
      --  Integer, not Natural: a null buffer (e.g. bounds 0 .. -1) has
      --  'Last = -1, which is outside Natural.
      Last : constant Integer := Data'Last;
   begin
      Put_Bits (1, 1);  --  BFINAL = 1
      Put_Bits (1, 2);  --  BTYPE  = 01 (fixed Huffman)

      while Pos <= Last loop
         declare
            Best_Len  : Natural := 0;
            Best_Dist : Natural := 0;
         begin
            if Pos + 2 <= Last then
               declare
                  H     : constant Natural := Hash3 (Pos);
                  Cand  : Integer := Head (H);
                  Chain : Natural := 0;
               begin
                  while Cand >= 0 and then Chain < Max_Chain loop
                     declare
                        Dist : constant Natural := Pos - Cand;
                        L    : Natural := 0;
                     begin
                        if Dist <= 32768 then
                           while L < 258 and then Pos + L <= Last
                             and then Data (Cand + L) = Data (Pos + L)
                           loop
                              L := L + 1;
                           end loop;
                           if L > Best_Len then
                              Best_Len := L;
                              Best_Dist := Dist;
                           end if;
                        end if;
                     end;
                     Cand := Prev (Cand - Data'First);
                     Chain := Chain + 1;
                  end loop;
               end;
            end if;

            if Best_Len >= 3 then
               Emit_Match (Best_Len, Best_Dist);
               --  Insert hashes for the matched span, then advance.
               for K in 0 .. Best_Len - 1 loop
                  if Pos + K + 2 <= Last then
                     declare
                        H : constant Natural := Hash3 (Pos + K);
                     begin
                        Prev (Pos + K - Data'First) := Head (H);
                        Head (H) := Pos + K;
                     end;
                  end if;
               end loop;
               Pos := Pos + Best_Len;
            else
               Emit_Literal (Data (Pos));
               if Pos + 2 <= Last then
                  declare
                     H : constant Natural := Hash3 (Pos);
                  begin
                     Prev (Pos - Data'First) := Head (H);
                     Head (H) := Pos;
                  end;
               end if;
               Pos := Pos + 1;
            end if;
         end;
      end loop;

      Put_LitLen (256);          --  end of block
      if NBits > 0 then          --  flush remaining bits
         Out_V.Append (Octet (Acc and 16#FF#));
      end if;

      declare
         R : Buffer (0 .. Natural (Out_V.Length) - 1);
      begin
         for I in R'Range loop
            R (I) := Out_V.Element (I);
         end loop;
         Free (Prev_P);
         return R;
      end;
   end Deflate;

end Dezhan.Storage.Deflate;
