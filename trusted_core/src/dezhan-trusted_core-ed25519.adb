with Interfaces;               use Interfaces;
with Ada.Unchecked_Conversion;
with Dezhan.Trusted_Core.SHA512; use Dezhan.Trusted_Core.SHA512;
package body Dezhan.Trusted_Core.Ed25519 with SPARK_Mode => Off is

   --  The field operations read every input fully before writing their output,
   --  so the in/out aliasing the curve formulas rely on (e.g. Sq_F (C, C),
   --  Add_F (D, D, D)) is correct. Silence GNAT's advisory aliasing warnings.
   pragma Warnings (Off, "*overlaps with actual*");
   pragma Warnings (Off, "*but value overwritten*");

   --  Local name for the hash (the package and its function share the name).
   function Hash512 (M : Byte_Array) return Digest512
     renames Dezhan.Trusted_Core.SHA512.SHA512;

   subtype I64 is Interfaces.Integer_64;
   type GF is array (0 .. 15) of I64;                 --  field element, radix 2^16
   type Point is array (0 .. 3) of GF;                --  extended coords X,Y,Z,T
   type ModL_Array is array (0 .. 63) of I64;
   subtype Bytes32 is Key_32;

   function To_U is new Ada.Unchecked_Conversion (I64, Unsigned_64);
   function To_I is new Ada.Unchecked_Conversion (Unsigned_64, I64);

   --  C-style bit ops on signed 64-bit (two's complement bit patterns).
   function Band (X, Y : I64) return I64 is (To_I (To_U (X) and To_U (Y)));
   function Bxor (X, Y : I64) return I64 is (To_I (To_U (X) xor To_U (Y)));
   function P2 (N : Natural) return I64 is (I64 (2) ** N);
   --  Arithmetic shift right (floor division by 2^N), matching C's >> on signed.
   function Shr_A (X : I64; N : Natural) return I64 is
     (if X >= 0 then X / P2 (N)
      else -(((-X) + P2 (N) - 1) / P2 (N)));
   function Shl (X : I64; N : Natural) return I64 is (X * P2 (N));

   GF0 : constant GF := (others => 0);
   GF1 : constant GF := (1, others => 0);

   Dc  : constant GF :=
     (16#78a3#, 16#1359#, 16#4dca#, 16#75eb#, 16#d8ab#, 16#4141#, 16#0a4d#,
      16#0070#, 16#e898#, 16#7779#, 16#4079#, 16#8cc7#, 16#fe73#, 16#2b6f#,
      16#6cee#, 16#5203#);
   D2c : constant GF :=
     (16#f159#, 16#26b2#, 16#9b94#, 16#ebd6#, 16#b156#, 16#8283#, 16#149a#,
      16#00e0#, 16#d130#, 16#eef3#, 16#80f2#, 16#198e#, 16#fce7#, 16#56df#,
      16#d9dc#, 16#2406#);
   Xc  : constant GF :=
     (16#d51a#, 16#8f25#, 16#2d60#, 16#c956#, 16#a7b2#, 16#9525#, 16#c760#,
      16#692c#, 16#dc5c#, 16#fdd6#, 16#e231#, 16#c0a4#, 16#53fe#, 16#cd6e#,
      16#36d3#, 16#2169#);
   Yc  : constant GF :=
     (16#6658#, 16#6666#, 16#6666#, 16#6666#, 16#6666#, 16#6666#, 16#6666#,
      16#6666#, 16#6666#, 16#6666#, 16#6666#, 16#6666#, 16#6666#, 16#6666#,
      16#6666#, 16#6666#);
   Ic  : constant GF :=
     (16#a0b0#, 16#4a0e#, 16#1b27#, 16#c4ee#, 16#e478#, 16#ad2f#, 16#1806#,
      16#2f43#, 16#d7a7#, 16#3dfb#, 16#0099#, 16#2b4d#, 16#df0b#, 16#4fc1#,
      16#2480#, 16#2b83#);

   L : constant ModL_Array :=
     (16#ed#, 16#d3#, 16#f5#, 16#5c#, 16#1a#, 16#63#, 16#12#, 16#58#,
      16#d6#, 16#9c#, 16#f7#, 16#a2#, 16#de#, 16#f9#, 16#de#, 16#14#,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16#10#,
      others => 0);

   procedure Car25519 (O : in out GF) is
      C : I64;
   begin
      for I in 0 .. 15 loop
         O (I) := O (I) + P2 (16);
         C := Shr_A (O (I), 16);
         if I = 15 then
            O (0) := O (0) + 38 * (C - 1);
         else
            O (I + 1) := O (I + 1) + (C - 1);
         end if;
         O (I) := O (I) - Shl (C, 16);
      end loop;
   end Car25519;

   procedure Sel25519 (P, Q : in out GF; B : I64) is
      C : constant I64 := (if B /= 0 then -1 else 0);
      T : I64;
   begin
      for I in 0 .. 15 loop
         T := Band (C, Bxor (P (I), Q (I)));
         P (I) := Bxor (P (I), T);
         Q (I) := Bxor (Q (I), T);
      end loop;
   end Sel25519;

   procedure Pack25519 (O : out Bytes32; N : GF) is
      M, T : GF;
      B    : I64;
   begin
      T := N;
      Car25519 (T); Car25519 (T); Car25519 (T);
      for J in 0 .. 1 loop
         M (0) := T (0) - 16#ffed#;
         for I in 1 .. 14 loop
            M (I) := T (I) - 16#ffff# - Band (Shr_A (M (I - 1), 16), 1);
            M (I - 1) := Band (M (I - 1), 16#ffff#);
         end loop;
         M (15) := T (15) - 16#7fff# - Band (Shr_A (M (14), 16), 1);
         B := Band (Shr_A (M (15), 16), 1);
         M (14) := Band (M (14), 16#ffff#);
         Sel25519 (T, M, 1 - B);
      end loop;
      for I in 0 .. 15 loop
         O (2 * I)     := Byte (Band (T (I), 16#ff#));
         O (2 * I + 1) := Byte (Band (Shr_A (T (I), 8), 16#ff#));
      end loop;
   end Pack25519;

   function Differ (A, B : GF) return Boolean is
      C, D : Bytes32;
   begin
      Pack25519 (C, A);
      Pack25519 (D, B);
      return C /= D;
   end Differ;

   function Par25519 (A : GF) return Byte is
      D : Bytes32;
   begin
      Pack25519 (D, A);
      return D (0) and 1;
   end Par25519;

   procedure Unpack25519 (O : out GF; N : Bytes32) is
   begin
      for I in 0 .. 15 loop
         O (I) := I64 (N (2 * I)) + Shl (I64 (N (2 * I + 1)), 8);
      end loop;
      O (15) := Band (O (15), 16#7fff#);
   end Unpack25519;

   procedure Add_F (O : out GF; A, B : GF) is
   begin
      for I in 0 .. 15 loop
         O (I) := A (I) + B (I);
      end loop;
   end Add_F;

   procedure Sub_F (O : out GF; A, B : GF) is
   begin
      for I in 0 .. 15 loop
         O (I) := A (I) - B (I);
      end loop;
   end Sub_F;

   procedure Mul_F (O : out GF; A, B : GF) is
      T : array (0 .. 30) of I64 := (others => 0);
   begin
      for I in 0 .. 15 loop
         for J in 0 .. 15 loop
            T (I + J) := T (I + J) + A (I) * B (J);
         end loop;
      end loop;
      for I in 0 .. 14 loop
         T (I) := T (I) + 38 * T (I + 16);
      end loop;
      for I in 0 .. 15 loop
         O (I) := T (I);
      end loop;
      Car25519 (O); Car25519 (O);
   end Mul_F;

   procedure Sq_F (O : out GF; A : GF) is
   begin
      Mul_F (O, A, A);
   end Sq_F;

   procedure Inv25519 (O : out GF; Inp : GF) is
      C : GF := Inp;
   begin
      for A in reverse 0 .. 253 loop
         Sq_F (C, C);
         if A /= 2 and then A /= 4 then
            Mul_F (C, C, Inp);
         end if;
      end loop;
      O := C;
   end Inv25519;

   procedure Pow2523 (O : out GF; Inp : GF) is
      C : GF := Inp;
   begin
      for A in reverse 0 .. 250 loop
         Sq_F (C, C);
         if A /= 1 then
            Mul_F (C, C, Inp);
         end if;
      end loop;
      O := C;
   end Pow2523;

   procedure Add_Pt (P : in out Point; Q : Point) is
      A, B, C, D, T, E, F, G, H : GF;
   begin
      Sub_F (A, P (1), P (0));
      Sub_F (T, Q (1), Q (0));
      Mul_F (A, A, T);
      Add_F (B, P (0), P (1));
      Add_F (T, Q (0), Q (1));
      Mul_F (B, B, T);
      Mul_F (C, P (3), Q (3));
      Mul_F (C, C, D2c);
      Mul_F (D, P (2), Q (2));
      Add_F (D, D, D);
      Sub_F (E, B, A);
      Sub_F (F, D, C);
      Add_F (G, D, C);
      Add_F (H, B, A);
      Mul_F (P (0), E, F);
      Mul_F (P (1), H, G);
      Mul_F (P (2), G, F);
      Mul_F (P (3), E, H);
   end Add_Pt;

   procedure Cswap (P, Q : in out Point; B : I64) is
   begin
      for I in 0 .. 3 loop
         Sel25519 (P (I), Q (I), B);
      end loop;
   end Cswap;

   procedure Pack_Point (R : out Bytes32; P : Point) is
      Tx, Ty, Zi : GF;
   begin
      Inv25519 (Zi, P (2));
      Mul_F (Tx, P (0), Zi);
      Mul_F (Ty, P (1), Zi);
      Pack25519 (R, Ty);
      R (31) := R (31) xor Shift_Left (Par25519 (Tx), 7);
   end Pack_Point;

   procedure Scalarmult (P : out Point; Q : Point; S : Bytes32) is
      QQ : Point := Q;
   begin
      P (0) := GF0; P (1) := GF1; P (2) := GF1; P (3) := GF0;
      for I in reverse 0 .. 255 loop
         declare
            B : constant I64 := Band (Shr_A (I64 (S (I / 8)), I mod 8), 1);
         begin
            Cswap (P, QQ, B);
            Add_Pt (QQ, P);
            Add_Pt (P, P);
            Cswap (P, QQ, B);
         end;
      end loop;
   end Scalarmult;

   procedure Scalarbase (P : out Point; S : Bytes32) is
      Q : Point;
   begin
      Q (0) := Xc; Q (1) := Yc; Q (2) := GF1;
      Mul_F (Q (3), Xc, Yc);
      Scalarmult (P, Q, S);
   end Scalarbase;

   procedure ModL (R : out Bytes32; X : in out ModL_Array) is
      Carry : I64;
   begin
      for I in reverse 32 .. 63 loop
         Carry := 0;
         for J in I - 32 .. I - 13 loop
            X (J) := X (J) + Carry - 16 * X (I) * L (J - (I - 32));
            Carry := Shr_A (X (J) + 128, 8);
            X (J) := X (J) - Shl (Carry, 8);
         end loop;
         X (I - 12) := X (I - 12) + Carry;
         X (I) := 0;
      end loop;
      Carry := 0;
      for J in 0 .. 31 loop
         X (J) := X (J) + Carry - Shr_A (X (31), 4) * L (J);
         Carry := Shr_A (X (J), 8);
         X (J) := Band (X (J), 255);
      end loop;
      for J in 0 .. 31 loop
         X (J) := X (J) - Carry * L (J);
      end loop;
      for I in 0 .. 31 loop
         X (I + 1) := X (I + 1) + Shr_A (X (I), 8);
         R (I) := Byte (Band (X (I), 255));
      end loop;
   end ModL;

   function Reduce (H : Digest512) return Bytes32 is
      X : ModL_Array;
      R : Bytes32;
   begin
      for I in 0 .. 63 loop
         X (I) := I64 (H (I));
      end loop;
      ModL (R, X);
      return R;
   end Reduce;

   function Unpackneg (R : out Point; P : Bytes32) return Boolean is
      Num, Den, Den2, Den4, Den6, T, Chk : GF;
   begin
      R (2) := GF1;
      Unpack25519 (R (1), P);
      Sq_F (Num, R (1));
      Mul_F (Den, Num, Dc);
      Sub_F (Num, Num, R (2));
      Add_F (Den, R (2), Den);
      Sq_F (Den2, Den);
      Sq_F (Den4, Den2);
      Mul_F (Den6, Den4, Den2);
      Mul_F (T, Den6, Num);
      Mul_F (T, T, Den);
      Pow2523 (T, T);
      Mul_F (T, T, Num);
      Mul_F (T, T, Den);
      Mul_F (T, T, Den);
      Mul_F (R (0), T, Den);
      Sq_F (Chk, R (0));
      Mul_F (Chk, Chk, Den);
      if Differ (Chk, Num) then
         Mul_F (R (0), R (0), Ic);
      end if;
      Sq_F (Chk, R (0));
      Mul_F (Chk, Chk, Den);
      if Differ (Chk, Num) then
         return False;
      end if;
      if Par25519 (R (0)) = Byte (Shift_Right (P (31), 7)) then
         Sub_F (R (0), GF0, R (0));
      end if;
      Mul_F (R (3), R (0), R (1));
      return True;
   end Unpackneg;

   function To_BA (K : Key_32) return Byte_Array is
      R : Byte_Array (0 .. 31);
   begin
      for I in 0 .. 31 loop
         R (I) := K (I);
      end loop;
      return R;
   end To_BA;

   function Expand (Seed : Key_32) return Digest512 is
      D : Digest512 := Hash512 (To_BA (Seed));
   begin
      D (0)  := D (0) and 248;
      D (31) := (D (31) and 127) or 64;
      return D;
   end Expand;

   function Public_Key (Seed : Key_32) return Key_32 is
      D : constant Digest512 := Expand (Seed);
      A : Bytes32;
      P : Point;
      R : Key_32;
   begin
      for I in 0 .. 31 loop
         A (I) := D (I);
      end loop;
      Scalarbase (P, A);
      Pack_Point (R, P);
      return R;
   end Public_Key;

   function Sign (Seed : Key_32; Msg : Byte_Array) return Sig_64 is
      D      : constant Digest512 := Expand (Seed);
      A_Pub  : constant Key_32    := Public_Key (Seed);
      N      : constant Natural   := Msg'Length;
      R_Pt   : Point;
      R_Sc   : Bytes32;
      H_Sc   : Bytes32;
      Sig    : Sig_64;
      S_Out  : Bytes32;
   begin
      --  r = reduce(SHA512(prefix || M)); R = r*B
      declare
         Buf : Byte_Array (0 .. 31 + N);
      begin
         for I in 0 .. 31 loop
            Buf (I) := D (32 + I);
         end loop;
         for I in 0 .. N - 1 loop
            Buf (32 + I) := Msg (Msg'First + I);
         end loop;
         R_Sc := Reduce (Hash512 (Buf));
      end;
      Scalarbase (R_Pt, R_Sc);
      declare
         R_Enc : Bytes32;
      begin
         Pack_Point (R_Enc, R_Pt);
         for I in 0 .. 31 loop
            Sig (I) := R_Enc (I);
         end loop;
      end;

      --  h = reduce(SHA512(R || A || M))
      declare
         Buf : Byte_Array (0 .. 63 + N);
      begin
         for I in 0 .. 31 loop
            Buf (I)      := Sig (I);
            Buf (32 + I) := A_Pub (I);
         end loop;
         for I in 0 .. N - 1 loop
            Buf (64 + I) := Msg (Msg'First + I);
         end loop;
         H_Sc := Reduce (Hash512 (Buf));
      end;

      --  S = (r + h*a) mod L
      declare
         X : ModL_Array := (others => 0);
      begin
         for I in 0 .. 31 loop
            X (I) := I64 (R_Sc (I));
         end loop;
         for I in 0 .. 31 loop
            for J in 0 .. 31 loop
               X (I + J) := X (I + J) + I64 (H_Sc (I)) * I64 (D (J));
            end loop;
         end loop;
         ModL (S_Out, X);
      end;
      for I in 0 .. 31 loop
         Sig (32 + I) := S_Out (I);
      end loop;
      return Sig;
   end Sign;

   function Verify (Public : Key_32; Msg : Byte_Array; Sig : Sig_64)
                    return Boolean
   is
      N    : constant Natural := Msg'Length;
      Q, P : Point;
      Q2   : Point;
      H_Sc : Bytes32;
      T    : Bytes32;
      R_In : Bytes32;
      S_In : Bytes32;
   begin
      for I in 0 .. 31 loop
         R_In (I) := Sig (I);
         S_In (I) := Sig (32 + I);
      end loop;
      if not Unpackneg (Q, Public) then
         return False;
      end if;
      declare
         Buf : Byte_Array (0 .. 63 + N);
      begin
         for I in 0 .. 31 loop
            Buf (I)      := R_In (I);
            Buf (32 + I) := Public (I);
         end loop;
         for I in 0 .. N - 1 loop
            Buf (64 + I) := Msg (Msg'First + I);
         end loop;
         H_Sc := Reduce (Hash512 (Buf));
      end;
      Scalarmult (P, Q, H_Sc);
      Scalarbase (Q2, S_In);
      Add_Pt (P, Q2);
      Pack_Point (T, P);
      return T = R_In;
   end Verify;

end Dezhan.Trusted_Core.Ed25519;
