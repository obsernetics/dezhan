with Interfaces; use Interfaces;
package body Dezhan.Trusted_Core.Audit with SPARK_Mode is

   Serial_Length : constant := 8 + 8 + 1 + 32 + 8 + 32;  --  = 89
   subtype Serial_Bytes is Byte_Array (0 .. Serial_Length - 1);

   function Hash_Of
     (Seq       : Seq_Number;
      Time      : Trusted_Time;
      Kind      : Audit_Event;
      Subject   : Digest;
      Detail    : Trusted_Time;
      Prev_Hash : Digest) return Digest
   is
      S : Serial_Bytes := (others => 0);

      procedure Put64 (V : Unsigned_64; Off : Natural)
        with Pre => Off <= Serial_Length - 8
      is
      begin
         for I in 0 .. 7 loop
            S (Off + I) := Byte (Shift_Right (V, 8 * (7 - I)) and 16#FF#);
         end loop;
      end Put64;

   begin
      Put64 (Unsigned_64 (Seq), 0);
      Put64 (Unsigned_64 (Time), 8);
      S (16) := Byte (Audit_Event'Pos (Kind));
      for I in 0 .. 31 loop
         S (17 + I) := Subject (I);
      end loop;
      Put64 (Unsigned_64 (Detail), 49);
      for I in 0 .. 31 loop
         S (57 + I) := Prev_Hash (I);
      end loop;
      return SHA256 (S);
   end Hash_Of;

   function Genesis_Entry (Time : Trusted_Time) return Audit_Entry is
      E : Audit_Entry :=
        (Seq       => 0,
         Time      => Time,
         Kind      => Genesis,
         Subject   => Zero_Digest,
         Detail    => 0,
         Prev_Hash => Zero_Digest,
         Hash      => Zero_Digest);
   begin
      E.Hash := Compute_Hash (E);
      return E;
   end Genesis_Entry;

   function Append
     (Prev    : Audit_Entry;
      Time    : Trusted_Time;
      Kind    : Audit_Event;
      Subject : Digest;
      Detail  : Trusted_Time) return Audit_Entry
   is
      E : Audit_Entry :=
        (Seq       => Prev.Seq + 1,
         Time      => Time,
         Kind      => Kind,
         Subject   => Subject,
         Detail    => Detail,
         Prev_Hash => Prev.Hash,
         Hash      => Zero_Digest);
   begin
      E.Hash := Compute_Hash (E);
      return E;
   end Append;

   function Verify_Chain (C : Chain) return Boolean is
   begin
      if C'Length = 0 then
         return False;
      end if;
      if not Is_Genesis (C (C'First)) then
         return False;
      end if;
      for I in C'First + 1 .. C'Last loop
         if C (I - 1).Seq = Natural'Last then
            return False;
         end if;
         if not Links_To (C (I), C (I - 1)) then
            return False;
         end if;
      end loop;
      return True;
   end Verify_Chain;

   procedure Assume_Hash_Binds (A, B : Audit_Entry) is
   begin
      pragma Assume
        (if Compute_Hash (A) = Compute_Hash (B) then Hashed_Fields_Eq (A, B));
   end Assume_Hash_Binds;

   procedure Lemma_Tamper_Breaks_Link (P, P_Tampered, E : Audit_Entry) is
   begin
      --  Equal hashes would force equal fields; the fields differ, so the
      --  hashes differ. E carries P's hash as Prev_Hash, which therefore cannot
      --  equal P_Tampered's hash, so the link to P_Tampered fails.
      Assume_Hash_Binds (P, P_Tampered);
   end Lemma_Tamper_Breaks_Link;

end Dezhan.Trusted_Core.Audit;
