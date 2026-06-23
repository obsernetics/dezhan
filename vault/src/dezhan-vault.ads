--  Vault: the orchestration layer that turns the verified trusted-core
--  primitives into WORM behavior. It ties together:
--    * encrypted content-addressed storage (Dezhan.Storage.Cas),
--    * retention / Object Lock (Dezhan.Trusted_Core.Retention),
--    * trusted time (Dezhan.Trusted_Core.Clock_Guard), and
--    * the append-only audit chain (Dezhan.Trusted_Core.Audit).
--
--  An object stored with a Compliance lock cannot be deleted before expiry, even
--  with a bypass; every operation is recorded in the audit chain; trusted time
--  comes from the clock guard so a manipulated system clock cannot expire a lock.
--
--  Regular Ada (SPARK_Mode Off): it orchestrates verified components. Metadata is
--  in memory for the POC; durable metadata persistence is future work.
with Ada.Streams; use Ada.Streams;
with Dezhan.Trusted_Core.Times;       use Dezhan.Trusted_Core.Times;
with Dezhan.Trusted_Core.Retention;   use Dezhan.Trusted_Core.Retention;
with Dezhan.Trusted_Core.Cipher;      use Dezhan.Trusted_Core.Cipher;
package Dezhan.Vault with SPARK_Mode => Off is

   type Vault_Type is limited private;

   Not_Found     : exception;
   Invalid_Mode  : exception;
   Vault_Sealed  : exception;   --  raised by mutations while the vault is sealed

   --  Open (or create) a vault rooted at Root, encrypted under Key.
   procedure Open (V : out Vault_Type; Root : String; Key : Key_256);

   --  Store Name with a retention lock of Mode for Retain_For trusted-time
   --  units from now. Mode must be Governance or Compliance.
   procedure Put_Object
     (V          : in out Vault_Type;
      Name       : String;
      Data       : Stream_Element_Array;
      Mode       : Lock_Mode;
      Retain_For : Trusted_Time);

   function Get_Object (V : Vault_Type; Name : String) return Stream_Element_Array;

   function Contains (V : Vault_Type; Name : String) return Boolean;
   function Object_Count (V : Vault_Type) return Natural;

   --  Newline-separated list of stored object names.
   function Object_Names (V : Vault_Type) return String;

   --  Attempt to delete Name. Returns True iff retention permitted it (Bypass
   --  only helps in Governance mode). The outcome is recorded in the audit chain.
   function Delete_Object
     (V : in out Vault_Type; Name : String; Bypass : Boolean) return Boolean;

   --  Advance trusted time from a clock sample. A detected anomaly seals the
   --  vault and is recorded in the audit chain.
   procedure Tick_Clock
     (V            : in out Vault_Type;
      Mono         : Trusted_Time;
      Realtime     : Trusted_Time;
      Boot_Changed : Boolean);

   --  Advance trusted time by sampling the real system clocks (monotonic and
   --  realtime) through the platform boundary.
   procedure Tick_From_System (V : in out Vault_Type);

   --  Operator-initiated seal: the vault becomes read-only (air-gap seal). A
   --  clock anomaly also seals the vault. While sealed, Put_Object and
   --  Delete_Object raise Vault_Sealed. Sealing is recorded in the audit chain
   --  and persisted.
   procedure Seal (V : in out Vault_Type);

   function Now    (V : Vault_Type) return Trusted_Time;

   --  True if sealed for any reason (operator seal or detected clock anomaly).
   function Sealed (V : Vault_Type) return Boolean;

   --  Audit chain: number of entries, and an independent self-verification.
   function Audit_Length   (V : Vault_Type) return Natural;
   function Audit_Verifies (V : Vault_Type) return Boolean;

private

   type State;
   type State_Access is access State;

   type Vault_Type is limited record
      Self : State_Access := null;
   end record;

end Dezhan.Vault;
