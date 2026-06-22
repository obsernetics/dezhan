package body Dezhan.Trusted_Core.Erasure with SPARK_Mode is

   --  ---- GF(256) arithmetic, reduction polynomial 0x11D ----

   function Mul (A, B : Symbol) return Symbol is
      P : Symbol := 0;
      X : Symbol := A;
      Y : Symbol := B;
   begin
      for I in 0 .. 7 loop
         if (Y and 1) /= 0 then
            P := P xor X;
         end if;
         declare
            High : constant Boolean := (X and 16#80#) /= 0;
         begin
            X := Shift_Left (X, 1);
            if High then
               X := X xor 16#1D#;
            end if;
         end;
         Y := Shift_Right (Y, 1);
      end loop;
      return P;
   end Mul;

   function Pow (A : Symbol; N : Natural) return Symbol is
      R    : Symbol  := 1;
      Base : Symbol  := A;
      E    : Natural := N;
   begin
      while E > 0 loop
         pragma Loop_Variant (Decreases => E);
         if E mod 2 = 1 then
            R := Mul (R, Base);
         end if;
         Base := Mul (Base, Base);
         E := E / 2;
      end loop;
      return R;
   end Pow;

   --  Total inverse: inv (0) = 0 so no precondition is needed. The construction
   --  below never inverts zero (Cauchy points are disjoint).
   function Inv (A : Symbol) return Symbol is
     (if A = 0 then 0 else Pow (A, 254));

   --  ---- Cauchy coding-matrix coefficients ----

   function X_Point (I : Positive) return Symbol is (Symbol (Max_Data + I - 1))
     with Pre => I <= Max_Parity;

   function Y_Point (J : Positive) return Symbol is (Symbol (J - 1))
     with Pre => J <= Max_Data;

   --  Parity row I, data column J.
   function Coeff (I, J : Positive) return Symbol is
     (Inv (X_Point (I) xor Y_Point (J)))
     with Pre => I <= Max_Parity and then J <= Max_Data;

   --  ---- Encoding ----

   procedure Encode
     (K, M, L : Positive;
      Data    : Data_Block;
      Parity  : out Parity_Block)
   is
   begin
      Parity := (others => (others => 0));
      for I in 1 .. M loop
         for B in 1 .. L loop
            declare
               Acc : Symbol := 0;
            begin
               for J in 1 .. K loop
                  Acc := Acc xor Mul (Coeff (I, J), Data (J, B));
               end loop;
               Parity (I, B) := Acc;
            end;
         end loop;
      end loop;
   end Encode;

   --  ---- K-by-K matrix inversion over GF(256), Gauss-Jordan ----

   type Matrix is array (Data_Range, Data_Range) of Symbol;

   procedure Invert
     (K       : Positive;
      A_In    : Matrix;
      A_Out   : out Matrix;
      Success : out Boolean)
     with Pre => K <= Max_Data
   is
      Mtx : Matrix := A_In;
      Idn : Matrix := (others => (others => 0));
   begin
      A_Out := (others => (others => 0));
      Success := True;
      for I in 1 .. K loop
         Idn (I, I) := 1;
      end loop;

      for Col in 1 .. K loop
         --  Find a non-zero pivot at or below the diagonal.
         declare
            Piv : Natural := 0;
         begin
            for R in Col .. K loop
               pragma Loop_Invariant (Piv <= K);
               if Piv = 0 and then Mtx (R, Col) /= 0 then
                  Piv := R;
               end if;
            end loop;

            if Piv = 0 then
               A_Out := (others => (others => 0));
               Success := False;
               return;
            end if;

            --  Swap the pivot row up to the diagonal.
            if Piv /= Col then
               for J in 1 .. K loop
                  declare
                     T1 : constant Symbol := Mtx (Col, J);
                     T2 : constant Symbol := Idn (Col, J);
                  begin
                     Mtx (Col, J) := Mtx (Piv, J);
                     Mtx (Piv, J) := T1;
                     Idn (Col, J) := Idn (Piv, J);
                     Idn (Piv, J) := T2;
                  end;
               end loop;
            end if;

            --  Normalize the pivot row.
            declare
               Inv_P : constant Symbol := Inv (Mtx (Col, Col));
            begin
               for J in 1 .. K loop
                  Mtx (Col, J) := Mul (Mtx (Col, J), Inv_P);
                  Idn (Col, J) := Mul (Idn (Col, J), Inv_P);
               end loop;
            end;

            --  Eliminate the column from every other row.
            for R in 1 .. K loop
               if R /= Col then
                  declare
                     Factor : constant Symbol := Mtx (R, Col);
                  begin
                     for J in 1 .. K loop
                        Mtx (R, J) := Mtx (R, J) xor Mul (Factor, Mtx (Col, J));
                        Idn (R, J) := Idn (R, J) xor Mul (Factor, Idn (Col, J));
                     end loop;
                  end;
               end if;
            end loop;
         end;
      end loop;

      A_Out := Idn;
   end Invert;

   --  ---- Reconstruction ----

   procedure Reconstruct
     (K, M, L : Positive;
      Present : Present_Map;
      Shards  : Shard_Block;
      Data    : out Data_Block;
      Success : out Boolean)
   is
      N   : constant Positive := K + M;
      Sel : array (Data_Range) of Shard_Range := (others => 1);  --  chosen rows
      Cnt : Natural := 0;
      A   : Matrix := (others => (others => 0));
      A_Inv : Matrix;
      Ok  : Boolean;
   begin
      Data := (others => (others => 0));
      Success := False;

      --  Choose the first K available shards.
      for I in 1 .. N loop
         pragma Loop_Invariant (Cnt <= K);
         pragma Loop_Invariant (for all T in 1 .. Cnt => Sel (T) <= N);
         if Present (I) and then Cnt < K then
            Cnt := Cnt + 1;
            Sel (Cnt) := I;
         end if;
      end loop;

      if Cnt < K then
         return;  --  not enough shards to reconstruct
      end if;
      pragma Assert (for all T in 1 .. K => Sel (T) <= N);

      --  Build the K-by-K submatrix of the coding matrix for the chosen rows.
      for T in 1 .. K loop
         declare
            R : constant Positive := Sel (T);
         begin
            for J in 1 .. K loop
               if R <= K then
                  A (T, J) := (if R = J then 1 else 0);
               else
                  A (T, J) := Coeff (R - K, J);
               end if;
            end loop;
         end;
      end loop;

      Invert (K, A, A_Inv, Ok);
      if not Ok then
         return;
      end if;

      --  Recover each data shard byte: Data = A_Inv * available-shard-vector.
      for J in 1 .. K loop
         for B in 1 .. L loop
            declare
               Acc : Symbol := 0;
            begin
               for T in 1 .. K loop
                  Acc := Acc xor Mul (A_Inv (J, T), Shards (Sel (T), B));
               end loop;
               Data (J, B) := Acc;
            end;
         end loop;
      end loop;

      Success := True;
   end Reconstruct;

end Dezhan.Trusted_Core.Erasure;
