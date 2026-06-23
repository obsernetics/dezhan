package body Dezhan.Trusted_Core.Retention with SPARK_Mode is

   function Create_Lock
     (Mode         : Lock_Mode;
      Retain_Until : Trusted_Time;
      Now          : Trusted_Time) return Retention_Lock
   is
   begin
      return (Mode         => Mode,
              Retain_Until => Retain_Until,
              Created_At   => Now,
              Legal_Hold   => False);
   end Create_Lock;

   function Set_Hold (L : Retention_Lock) return Retention_Lock is
      Result : Retention_Lock := L;
   begin
      Result.Legal_Hold := True;
      return Result;
   end Set_Hold;

   function Release_Hold (L : Retention_Lock) return Retention_Lock is
      Result : Retention_Lock := L;
   begin
      Result.Legal_Hold := False;
      return Result;
   end Release_Hold;

   function Extend_Retention
     (L         : Retention_Lock;
      New_Until : Trusted_Time) return Retention_Lock
   is
      Result : Retention_Lock := L;
   begin
      --  Only ever move the expiry forward. Never shorten.
      if New_Until > L.Retain_Until then
         Result.Retain_Until := New_Until;
      end if;
      return Result;
   end Extend_Retention;

   function Request_Extension
     (L         : Retention_Lock;
      New_Until : Trusted_Time) return Extension_Result
   is
   begin
      return (Lock     => Extend_Retention (L, New_Until),
              Accepted => New_Until > L.Retain_Until);
   end Request_Extension;

   procedure Lemma_Compliance_Is_Absolute
     (L    : Retention_Lock;
      Now  : Trusted_Time;
      Auth : Authorization)
   is
   begin
      --  Proof-only. The postcondition follows directly from the definition of
      --  Can_Delete for Compliance mode; gnatprove discharges it.
      null;
   end Lemma_Compliance_Is_Absolute;

   procedure Lemma_Legal_Hold_Is_Absolute
     (L    : Retention_Lock;
      Now  : Trusted_Time;
      Auth : Authorization)
   is
   begin
      --  Proof-only: Can_Delete is False whenever Legal_Hold is set, by its
      --  definition; gnatprove discharges the postcondition.
      null;
   end Lemma_Legal_Hold_Is_Absolute;

end Dezhan.Trusted_Core.Retention;
