with Interfaces;               use Interfaces;
with Dezhan.Trusted_Core.HMAC; use Dezhan.Trusted_Core.HMAC;
package body Dezhan.Kdf with SPARK_Mode => Off is

   function PBKDF2_HMAC_SHA256
     (Password, Salt : Byte_Array; Iterations : Positive) return Digest
   is
      --  Block 1 only (dkLen = hLen): T = U_1 xor U_2 xor ... xor U_c, where
      --  U_1 = PRF(P, S || INT32BE(1)) and U_j = PRF(P, U_{j-1}).
      Msg : Byte_Array (0 .. Salt'Length + 4 - 1);
      U   : Digest;
      T   : Digest;
   begin
      for I in 0 .. Salt'Length - 1 loop
         Msg (I) := Salt (Salt'First + I);
      end loop;
      Msg (Salt'Length)     := 0;
      Msg (Salt'Length + 1) := 0;
      Msg (Salt'Length + 2) := 0;
      Msg (Salt'Length + 3) := 1;          --  big-endian block index 1

      U := HMAC_SHA256 (Password, Msg);
      T := U;
      for J in 2 .. Iterations loop
         declare
            UB : Byte_Array (0 .. 31);
         begin
            for K in 0 .. 31 loop
               UB (K) := U (K);
            end loop;
            U := HMAC_SHA256 (Password, UB);
         end;
         for K in T'Range loop
            T (K) := T (K) xor U (K);
         end loop;
      end loop;
      return T;
   end PBKDF2_HMAC_SHA256;

end Dezhan.Kdf;
