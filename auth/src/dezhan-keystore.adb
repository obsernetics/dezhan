with Interfaces;              use Interfaces;
with Dezhan.Trusted_Core.HMAC; use Dezhan.Trusted_Core.HMAC;
package body Dezhan.Keystore with SPARK_Mode => Off is

   --  Independent 256-bit subkey from KEK for a given purpose label.
   function Subkey (KEK : Key_256; Label : String) return Key_256 is
      KB : Byte_Array (0 .. 31);
      LB : Byte_Array (0 .. Label'Length - 1);
      H  : Digest;
      R  : Key_256;
   begin
      for I in 0 .. 31 loop
         KB (I) := KEK (I);
      end loop;
      for I in 0 .. Label'Length - 1 loop
         LB (I) := Byte (Character'Pos (Label (Label'First + I)));
      end loop;
      H := HMAC_SHA256 (KB, LB);
      for I in R'Range loop
         R (I) := H (I);
      end loop;
      return R;
   end Subkey;

   Enc_Label : constant String := "dezhan/wrap/enc";
   Mac_Label : constant String := "dezhan/wrap/mac";

   --  HMAC over Nonce (12) || Cipher (32).
   function Wrap_Tag (MK : Key_256; Nonce : Nonce_96; C : Key_256)
                      return Digest is
      KB : Byte_Array (0 .. 31);
      MB : Byte_Array (0 .. 43);
   begin
      for I in 0 .. 31 loop
         KB (I) := MK (I);
      end loop;
      for I in 0 .. 11 loop
         MB (I) := Nonce (I);
      end loop;
      for I in 0 .. 31 loop
         MB (12 + I) := C (I);
      end loop;
      return HMAC_SHA256 (KB, MB);
   end Wrap_Tag;

   function Wrap (KEK : Key_256; Nonce : Nonce_96; DEK : Key_256)
                  return Wrapped_Key
   is
      EK : constant Key_256 := Subkey (KEK, Enc_Label);
      MK : constant Key_256 := Subkey (KEK, Mac_Label);
      CB : Byte_Array (0 .. 31);
      W  : Wrapped_Key;
   begin
      for I in 0 .. 31 loop
         CB (I) := DEK (I);
      end loop;
      XCrypt (EK, Nonce, 0, CB);
      W.Nonce := Nonce;
      for I in 0 .. 31 loop
         W.Cipher (I) := CB (I);
      end loop;
      W.Tag := Wrap_Tag (MK, Nonce, W.Cipher);
      return W;
   end Wrap;

   procedure Unwrap (KEK : Key_256; W : Wrapped_Key;
                     DEK : out Key_256; Ok : out Boolean)
   is
      EK     : constant Key_256 := Subkey (KEK, Enc_Label);
      MK     : constant Key_256 := Subkey (KEK, Mac_Label);
      Expect : constant Digest  := Wrap_Tag (MK, W.Nonce, W.Cipher);
      DB     : Byte_Array (0 .. 31);
   begin
      DEK := (others => 0);
      Ok  := True;
      for I in 0 .. 31 loop
         if Expect (I) /= W.Tag (I) then
            Ok := False;
         end if;
      end loop;
      if not Ok then
         return;  --  wrong passphrase or tampering: leave DEK zeroed
      end if;
      for I in 0 .. 31 loop
         DB (I) := W.Cipher (I);
      end loop;
      XCrypt (EK, W.Nonce, 0, DB);   --  ChaCha20 is its own inverse
      for I in 0 .. 31 loop
         DEK (I) := DB (I);
      end loop;
   end Unwrap;

end Dezhan.Keystore;
