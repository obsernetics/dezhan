--  Untrusted clock reader (audited FFI boundary). Builds a Clock_Sample from the
--  OS monotonic (CLOCK_BOOTTIME) and realtime (CLOCK_REALTIME) clocks, and
--  exposes the kernel boot id so callers can detect a reboot across restarts.
--  The realtime reading is untrusted by design; the Clock Integrity Guard
--  validates it. Sub-second precision is intentionally dropped (trusted time is
--  whole seconds).
with Dezhan.Trusted_Core.Clock_Guard;
package Dezhan.Platform.Clock with SPARK_Mode => Off is

   function Sample return Dezhan.Trusted_Core.Clock_Guard.Clock_Sample;

   --  The kernel boot identifier (/proc/sys/kernel/random/boot_id), or "" if
   --  unavailable. It changes on every reboot, so a change since a persisted
   --  value means the machine rebooted (the monotonic clock reset).
   function Boot_Id return String;

end Dezhan.Platform.Clock;
