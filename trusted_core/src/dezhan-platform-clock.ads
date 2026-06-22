--  Untrusted clock reader (audited FFI boundary). Builds a Clock_Sample from the
--  OS monotonic (CLOCK_BOOTTIME) and realtime (CLOCK_REALTIME) clocks. The
--  realtime reading is untrusted by design; the Clock Integrity Guard validates
--  it. Within a single process there is no reboot, so Boot_Changed is always
--  False here; cross-reboot detection + durable persistence of Guard_State are
--  the caller's responsibility (they land with the storage engine).
with Dezhan.Trusted_Core.Clock_Guard;
package Dezhan.Platform.Clock with SPARK_Mode => Off is

   function Sample return Dezhan.Trusted_Core.Clock_Guard.Clock_Sample;

end Dezhan.Platform.Clock;
