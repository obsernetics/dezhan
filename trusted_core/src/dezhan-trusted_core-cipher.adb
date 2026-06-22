package body Dezhan.Trusted_Core.Cipher with SPARK_Mode is

   type Words is array (0 .. 15) of Unsigned_32;
   subtype Index_16 is Natural range 0 .. 15;
   subtype Keystream is Byte_Array (0 .. 63);

   function LE32 (B0, B1, B2, B3 : Byte) return Unsigned_32 is
     (Unsigned_32 (B0)
      or Shift_Left (Unsigned_32 (B1), 8)
      or Shift_Left (Unsigned_32 (B2), 16)
      or Shift_Left (Unsigned_32 (B3), 24));

   procedure Quarter_Round (S : in out Words; A, B, C, D : Index_16) is
   begin
      S (A) := S (A) + S (B);  S (D) := Rotate_Left (S (D) xor S (A), 16);
      S (C) := S (C) + S (D);  S (B) := Rotate_Left (S (B) xor S (C), 12);
      S (A) := S (A) + S (B);  S (D) := Rotate_Left (S (D) xor S (A), 8);
      S (C) := S (C) + S (D);  S (B) := Rotate_Left (S (B) xor S (C), 7);
   end Quarter_Round;

   function Block
     (Key     : Key_256;
      Nonce   : Nonce_96;
      Counter : Unsigned_32) return Keystream
   is
      St : Words := (others => 0);
      Wk : Words := (others => 0);
      KS : Keystream := (others => 0);
   begin
      St (0) := 16#61707865#;
      St (1) := 16#3320646e#;
      St (2) := 16#79622d32#;
      St (3) := 16#6b206574#;
      for I in 0 .. 7 loop
         St (4 + I) := LE32 (Key (I * 4), Key (I * 4 + 1),
                             Key (I * 4 + 2), Key (I * 4 + 3));
      end loop;
      St (12) := Counter;
      for I in 0 .. 2 loop
         St (13 + I) := LE32 (Nonce (I * 4), Nonce (I * 4 + 1),
                              Nonce (I * 4 + 2), Nonce (I * 4 + 3));
      end loop;

      Wk := St;
      for R in 1 .. 10 loop
         --  Column rounds.
         Quarter_Round (Wk, 0, 4, 8, 12);
         Quarter_Round (Wk, 1, 5, 9, 13);
         Quarter_Round (Wk, 2, 6, 10, 14);
         Quarter_Round (Wk, 3, 7, 11, 15);
         --  Diagonal rounds.
         Quarter_Round (Wk, 0, 5, 10, 15);
         Quarter_Round (Wk, 1, 6, 11, 12);
         Quarter_Round (Wk, 2, 7, 8, 13);
         Quarter_Round (Wk, 3, 4, 9, 14);
      end loop;

      for I in 0 .. 15 loop
         Wk (I) := Wk (I) + St (I);
      end loop;

      for I in 0 .. 15 loop
         KS (I * 4)     := Byte (Wk (I) and 16#FF#);
         KS (I * 4 + 1) := Byte (Shift_Right (Wk (I), 8) and 16#FF#);
         KS (I * 4 + 2) := Byte (Shift_Right (Wk (I), 16) and 16#FF#);
         KS (I * 4 + 3) := Byte (Shift_Right (Wk (I), 24) and 16#FF#);
      end loop;
      return KS;
   end Block;

   procedure XCrypt
     (Key     : Key_256;
      Nonce   : Nonce_96;
      Counter : Unsigned_32;
      Data    : in out Byte_Array)
   is
      Ctr : Unsigned_32 := Counter;
      Pos : Natural := Data'First;
   begin
      while Pos <= Data'Last loop
         pragma Loop_Invariant (Pos >= Data'First);
         pragma Loop_Invariant (Pos <= Data'Last);
         pragma Loop_Variant (Decreases => Data'Last - Pos);
         declare
            KS        : constant Keystream := Block (Key, Nonce, Ctr);
            Remaining : constant Natural   := Data'Last - Pos + 1;
            This      : constant Natural   :=
              (if Remaining < 64 then Remaining else 64);
         begin
            for J in 0 .. This - 1 loop
               Data (Pos + J) := Data (Pos + J) xor KS (J);
            end loop;
            Pos := Pos + This;
         end;
         Ctr := Ctr + 1;
      end loop;
   end XCrypt;

end Dezhan.Trusted_Core.Cipher;
