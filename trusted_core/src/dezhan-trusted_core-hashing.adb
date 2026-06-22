package body Dezhan.Trusted_Core.Hashing with SPARK_Mode is

   subtype Word is Interfaces.Unsigned_32;

   type Word_Array is array (Natural range <>) of Word;
   subtype State is Word_Array (0 .. 7);
   subtype Schedule is Word_Array (0 .. 63);

   --  Padded-buffer sizing. PL (padded length) is always a multiple of 64 and
   --  never exceeds Max_Padded for any Msg with Msg'Length <= Max_Message.
   Max_Blocks : constant := (Max_Message + 8) / 64 + 1;
   Max_Padded : constant := Max_Blocks * 64;

   H0 : constant State :=
     (16#6a09e667#, 16#bb67ae85#, 16#3c6ef372#, 16#a54ff53a#,
      16#510e527f#, 16#9b05688c#, 16#1f83d9ab#, 16#5be0cd19#);

   K : constant Schedule :=
     (16#428a2f98#, 16#71374491#, 16#b5c0fbcf#, 16#e9b5dba5#,
      16#3956c25b#, 16#59f111f1#, 16#923f82a4#, 16#ab1c5ed5#,
      16#d807aa98#, 16#12835b01#, 16#243185be#, 16#550c7dc3#,
      16#72be5d74#, 16#80deb1fe#, 16#9bdc06a7#, 16#c19bf174#,
      16#e49b69c1#, 16#efbe4786#, 16#0fc19dc6#, 16#240ca1cc#,
      16#2de92c6f#, 16#4a7484aa#, 16#5cb0a9dc#, 16#76f988da#,
      16#983e5152#, 16#a831c66d#, 16#b00327c8#, 16#bf597fc7#,
      16#c6e00bf3#, 16#d5a79147#, 16#06ca6351#, 16#14292967#,
      16#27b70a85#, 16#2e1b2138#, 16#4d2c6dfc#, 16#53380d13#,
      16#650a7354#, 16#766a0abb#, 16#81c2c92e#, 16#92722c85#,
      16#a2bfe8a1#, 16#a81a664b#, 16#c24b8b70#, 16#c76c51a3#,
      16#d192e819#, 16#d6990624#, 16#f40e3585#, 16#106aa070#,
      16#19a4c116#, 16#1e376c08#, 16#2748774c#, 16#34b0bcb5#,
      16#391c0cb3#, 16#4ed8aa4a#, 16#5b9cca4f#, 16#682e6ff3#,
      16#748f82ee#, 16#78a5636f#, 16#84c87814#, 16#8cc70208#,
      16#90befffa#, 16#a4506ceb#, 16#bef9a3f7#, 16#c67178f2#);

   function Rotr (X : Word; N : Natural) return Word is
     (Rotate_Right (X, N))
     with Pre => N < 32;

   function Shr (X : Word; N : Natural) return Word is
     (Shift_Right (X, N))
     with Pre => N < 32;

   function Ch (X, Y, Z : Word) return Word is
     ((X and Y) xor ((not X) and Z));

   function Maj (X, Y, Z : Word) return Word is
     ((X and Y) xor (X and Z) xor (Y and Z));

   function Big_Sigma0 (X : Word) return Word is
     (Rotr (X, 2) xor Rotr (X, 13) xor Rotr (X, 22));

   function Big_Sigma1 (X : Word) return Word is
     (Rotr (X, 6) xor Rotr (X, 11) xor Rotr (X, 25));

   function Small_Sigma0 (X : Word) return Word is
     (Rotr (X, 7) xor Rotr (X, 18) xor Shr (X, 3));

   function Small_Sigma1 (X : Word) return Word is
     (Rotr (X, 17) xor Rotr (X, 19) xor Shr (X, 10));

   function SHA256 (Msg : Byte_Array) return Digest is
      Len     : constant Natural      := Msg'Length;
      NB      : constant Natural      := (Len + 8) / 64 + 1;
      PL      : constant Natural      := NB * 64;
      Bit_Len : constant Unsigned_64  := Unsigned_64 (Len) * 8;
      Buf     : Byte_Array (0 .. Max_Padded - 1) := (others => 0);
      H       : State := H0;
      Result  : Digest := (others => 0);
   begin
      pragma Assert (NB <= Max_Blocks);
      pragma Assert (PL <= Max_Padded);

      --  Copy the message.
      for I in 0 .. Len - 1 loop
         Buf (I) := Msg (Msg'First + I);
      end loop;

      --  Append the 0x80 terminator (Len < PL is guaranteed: PL >= Len + 9).
      Buf (Len) := 16#80#;

      --  Append the 64-bit big-endian bit length in the final 8 bytes.
      for I in 0 .. 7 loop
         Buf (PL - 8 + I) :=
           Byte (Shift_Right (Bit_Len, 8 * (7 - I)) and 16#FF#);
      end loop;

      --  Process each 64-byte block.
      for Blk in 0 .. NB - 1 loop
         pragma Loop_Invariant (Blk < Max_Blocks);
         declare
            Base : constant Natural := Blk * 64;
            W    : Schedule := (others => 0);
            A, B, C, D, E, F, G, Hh, T1, T2 : Word;
         begin
            for T in 0 .. 15 loop
               W (T) :=
                 Shift_Left (Word (Buf (Base + T * 4)),     24) or
                 Shift_Left (Word (Buf (Base + T * 4 + 1)), 16) or
                 Shift_Left (Word (Buf (Base + T * 4 + 2)), 8)  or
                 Word (Buf (Base + T * 4 + 3));
            end loop;
            for T in 16 .. 63 loop
               W (T) := Small_Sigma1 (W (T - 2)) + W (T - 7)
                        + Small_Sigma0 (W (T - 15)) + W (T - 16);
            end loop;

            A := H (0); B := H (1); C := H (2); D := H (3);
            E := H (4); F := H (5); G := H (6); Hh := H (7);

            for T in 0 .. 63 loop
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

      --  Serialize the state, big-endian.
      for I in 0 .. 7 loop
         Result (I * 4)     := Byte (Shift_Right (H (I), 24) and 16#FF#);
         Result (I * 4 + 1) := Byte (Shift_Right (H (I), 16) and 16#FF#);
         Result (I * 4 + 2) := Byte (Shift_Right (H (I), 8)  and 16#FF#);
         Result (I * 4 + 3) := Byte (H (I) and 16#FF#);
      end loop;

      return Result;
   end SHA256;

end Dezhan.Trusted_Core.Hashing;
