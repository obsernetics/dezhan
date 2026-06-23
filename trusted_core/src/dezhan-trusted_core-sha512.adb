with Interfaces; use Interfaces;
package body Dezhan.Trusted_Core.SHA512 with SPARK_Mode is

   subtype Word is Interfaces.Unsigned_64;
   type Word_Array is array (Natural range <>) of Word;
   subtype State is Word_Array (0 .. 7);
   subtype Schedule is Word_Array (0 .. 79);

   Max_Blocks : constant := (Max_Message + 16) / 128 + 1;
   Max_Padded : constant := Max_Blocks * 128;

   H0 : constant State :=
     (16#6a09e667f3bcc908#, 16#bb67ae8584caa73b#,
      16#3c6ef372fe94f82b#, 16#a54ff53a5f1d36f1#,
      16#510e527fade682d1#, 16#9b05688c2b3e6c1f#,
      16#1f83d9abfb41bd6b#, 16#5be0cd19137e2179#);

   K : constant Schedule :=
     (16#428a2f98d728ae22#, 16#7137449123ef65cd#, 16#b5c0fbcfec4d3b2f#,
      16#e9b5dba58189dbbc#, 16#3956c25bf348b538#, 16#59f111f1b605d019#,
      16#923f82a4af194f9b#, 16#ab1c5ed5da6d8118#, 16#d807aa98a3030242#,
      16#12835b0145706fbe#, 16#243185be4ee4b28c#, 16#550c7dc3d5ffb4e2#,
      16#72be5d74f27b896f#, 16#80deb1fe3b1696b1#, 16#9bdc06a725c71235#,
      16#c19bf174cf692694#, 16#e49b69c19ef14ad2#, 16#efbe4786384f25e3#,
      16#0fc19dc68b8cd5b5#, 16#240ca1cc77ac9c65#, 16#2de92c6f592b0275#,
      16#4a7484aa6ea6e483#, 16#5cb0a9dcbd41fbd4#, 16#76f988da831153b5#,
      16#983e5152ee66dfab#, 16#a831c66d2db43210#, 16#b00327c898fb213f#,
      16#bf597fc7beef0ee4#, 16#c6e00bf33da88fc2#, 16#d5a79147930aa725#,
      16#06ca6351e003826f#, 16#142929670a0e6e70#, 16#27b70a8546d22ffc#,
      16#2e1b21385c26c926#, 16#4d2c6dfc5ac42aed#, 16#53380d139d95b3df#,
      16#650a73548baf63de#, 16#766a0abb3c77b2a8#, 16#81c2c92e47edaee6#,
      16#92722c851482353b#, 16#a2bfe8a14cf10364#, 16#a81a664bbc423001#,
      16#c24b8b70d0f89791#, 16#c76c51a30654be30#, 16#d192e819d6ef5218#,
      16#d69906245565a910#, 16#f40e35855771202a#, 16#106aa07032bbd1b8#,
      16#19a4c116b8d2d0c8#, 16#1e376c085141ab53#, 16#2748774cdf8eeb99#,
      16#34b0bcb5e19b48a8#, 16#391c0cb3c5c95a63#, 16#4ed8aa4ae3418acb#,
      16#5b9cca4f7763e373#, 16#682e6ff3d6b2b8a3#, 16#748f82ee5defb2fc#,
      16#78a5636f43172f60#, 16#84c87814a1f0ab72#, 16#8cc702081a6439ec#,
      16#90befffa23631e28#, 16#a4506cebde82bde9#, 16#bef9a3f7b2c67915#,
      16#c67178f2e372532b#, 16#ca273eceea26619c#, 16#d186b8c721c0c207#,
      16#eada7dd6cde0eb1e#, 16#f57d4f7fee6ed178#, 16#06f067aa72176fba#,
      16#0a637dc5a2c898a6#, 16#113f9804bef90dae#, 16#1b710b35131c471b#,
      16#28db77f523047d84#, 16#32caab7b40c72493#, 16#3c9ebe0a15c9bebc#,
      16#431d67c49c100d4c#, 16#4cc5d4becb3e42b6#, 16#597f299cfc657e2a#,
      16#5fcb6fab3ad6faec#, 16#6c44198c4a475817#);

   function Rotr (X : Word; N : Natural) return Word is (Rotate_Right (X, N))
     with Pre => N < 64;
   function Shr (X : Word; N : Natural) return Word is (Shift_Right (X, N))
     with Pre => N < 64;

   function Ch (X, Y, Z : Word) return Word is
     ((X and Y) xor ((not X) and Z));
   function Maj (X, Y, Z : Word) return Word is
     ((X and Y) xor (X and Z) xor (Y and Z));
   function Big_Sigma0 (X : Word) return Word is
     (Rotr (X, 28) xor Rotr (X, 34) xor Rotr (X, 39));
   function Big_Sigma1 (X : Word) return Word is
     (Rotr (X, 14) xor Rotr (X, 18) xor Rotr (X, 41));
   function Small_Sigma0 (X : Word) return Word is
     (Rotr (X, 1) xor Rotr (X, 8) xor Shr (X, 7));
   function Small_Sigma1 (X : Word) return Word is
     (Rotr (X, 19) xor Rotr (X, 61) xor Shr (X, 6));

   function SHA512 (Msg : Byte_Array) return Digest512 is
      Len     : constant Natural     := Msg'Length;
      NB      : constant Natural     := (Len + 16) / 128 + 1;
      PL      : constant Natural     := NB * 128;
      Bit_Len : constant Word        := Word (Len) * 8;
      Buf     : Byte_Array (0 .. Max_Padded - 1) := (others => 0);
      H       : State := H0;
      Result  : Digest512 := (others => 0);
   begin
      pragma Assert (NB <= Max_Blocks);
      pragma Assert (PL <= Max_Padded);

      for I in 0 .. Len - 1 loop
         Buf (I) := Msg (Msg'First + I);
      end loop;
      Buf (Len) := 16#80#;
      --  128-bit big-endian length; the high 64 bits are 0 for our sizes.
      for I in 0 .. 7 loop
         Buf (PL - 8 + I) := Byte (Shift_Right (Bit_Len, 8 * (7 - I)) and 16#FF#);
      end loop;

      for Blk in 0 .. NB - 1 loop
         pragma Loop_Invariant (Blk < Max_Blocks);
         declare
            Base : constant Natural := Blk * 128;
            W    : Schedule := (others => 0);
            A, B, C, D, E, F, G, Hh, T1, T2 : Word;
         begin
            for T in 0 .. 15 loop
               declare
                  V : Word := 0;
               begin
                  for J in 0 .. 7 loop
                     V := Shift_Left (V, 8) or Word (Buf (Base + T * 8 + J));
                  end loop;
                  W (T) := V;
               end;
            end loop;
            for T in 16 .. 79 loop
               W (T) := Small_Sigma1 (W (T - 2)) + W (T - 7)
                        + Small_Sigma0 (W (T - 15)) + W (T - 16);
            end loop;

            A := H (0); B := H (1); C := H (2); D := H (3);
            E := H (4); F := H (5); G := H (6); Hh := H (7);

            for T in 0 .. 79 loop
               T1 := Hh + Big_Sigma1 (E) + Ch (E, F, G) + K (T) + W (T);
               T2 := Big_Sigma0 (A) + Maj (A, B, C);
               Hh := G; G := F; F := E; E := D + T1;
               D := C; C := B; B := A; A := T1 + T2;
            end loop;

            H (0) := H (0) + A; H (1) := H (1) + B;
            H (2) := H (2) + C; H (3) := H (3) + D;
            H (4) := H (4) + E; H (5) := H (5) + F;
            H (6) := H (6) + G; H (7) := H (7) + Hh;
         end;
      end loop;

      for I in 0 .. 7 loop
         for J in 0 .. 7 loop
            Result (I * 8 + J) :=
              Byte (Shift_Right (H (I), 8 * (7 - J)) and 16#FF#);
         end loop;
      end loop;
      return Result;
   end SHA512;

end Dezhan.Trusted_Core.SHA512;
