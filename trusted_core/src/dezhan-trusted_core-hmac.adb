with Interfaces; use Interfaces;

package body Dezhan.Trusted_Core.HMAC with SPARK_Mode is

   Block : constant := 64;  --  SHA-256 block size in bytes

   function HMAC_SHA256 (Key : Byte_Array; Msg : Byte_Array) return Digest is
      K0        : Byte_Array (0 .. Block - 1) := (others => 0);
      Inner_Msg : Byte_Array (0 .. Block + Msg'Length - 1) := (others => 0);
      Outer_Msg : Byte_Array (0 .. Block + 31) := (others => 0);
      Inner     : Digest;
   begin
      --  K0: the key, zero-padded to the block size; if longer than a block,
      --  hashed first.
      if Key'Length <= Block then
         for I in 0 .. Key'Length - 1 loop
            K0 (I) := Key (Key'First + I);
         end loop;
      else
         declare
            HK : constant Digest := SHA256 (Key);
         begin
            for I in 0 .. 31 loop
               K0 (I) := HK (I);
            end loop;
         end;
      end if;

      --  Inner = H((K0 xor ipad) || Msg)
      for I in 0 .. Block - 1 loop
         Inner_Msg (I) := K0 (I) xor 16#36#;
      end loop;
      for I in 0 .. Msg'Length - 1 loop
         Inner_Msg (Block + I) := Msg (Msg'First + I);
      end loop;
      Inner := SHA256 (Inner_Msg);

      --  Outer = H((K0 xor opad) || Inner)
      for I in 0 .. Block - 1 loop
         Outer_Msg (I) := K0 (I) xor 16#5C#;
      end loop;
      for I in 0 .. 31 loop
         Outer_Msg (Block + I) := Inner (I);
      end loop;
      return SHA256 (Outer_Msg);
   end HMAC_SHA256;

end Dezhan.Trusted_Core.HMAC;
