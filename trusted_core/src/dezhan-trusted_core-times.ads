--  Shared trusted-time type for the trusted core.
--
--  Trusted, monotonic time in whole seconds since an opaque epoch, produced by
--  the Clock Integrity Guard and consumed by the Retention State Machine. A
--  bounded range so comparisons need no overflow reasoning; any arithmetic that
--  could overflow saturates explicitly at 'Last.
package Dezhan.Trusted_Core.Times with SPARK_Mode, Pure is

   type Trusted_Time is range 0 .. 2**63 - 1;

end Dezhan.Trusted_Core.Times;
