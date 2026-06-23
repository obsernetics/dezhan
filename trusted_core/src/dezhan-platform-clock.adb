with Interfaces.C;
with Ada.Text_IO;
with Dezhan.Trusted_Core.Times;       use Dezhan.Trusted_Core.Times;
with Dezhan.Trusted_Core.Clock_Guard; use Dezhan.Trusted_Core.Clock_Guard;

package body Dezhan.Platform.Clock with SPARK_Mode => Off is

   use Interfaces.C;

   --  POSIX struct timespec.
   type Timespec is record
      Tv_Sec  : Interfaces.C.long;
      Tv_Nsec : Interfaces.C.long;
   end record
     with Convention => C;

   function C_Clock_Gettime
     (Clk_Id : Interfaces.C.int; Tp : access Timespec) return Interfaces.C.int
     with Import, Convention => C, External_Name => "clock_gettime";

   --  Linux clockid_t values.
   CLOCK_REALTIME : constant Interfaces.C.int := 0;
   CLOCK_BOOTTIME : constant Interfaces.C.int := 7;

   --  Whole seconds from a clock; 0 on error or negative reading. Sub-second
   --  precision is intentionally dropped (trusted time is whole seconds).
   function Seconds (Clk : Interfaces.C.int) return Trusted_Time is
      Ts  : aliased Timespec;
      Res : Interfaces.C.int;
   begin
      Res := C_Clock_Gettime (Clk, Ts'Access);
      if Res /= 0 or else Ts.Tv_Sec < 0 then
         return 0;
      end if;
      return Trusted_Time (Ts.Tv_Sec);
   end Seconds;

   function Sample return Clock_Sample is
   begin
      --  Boot_Changed is determined by the caller comparing Boot_Id across
      --  restarts; within one process the monotonic clock never resets.
      return (Mono         => Seconds (CLOCK_BOOTTIME),
              Realtime     => Seconds (CLOCK_REALTIME),
              Boot_Changed => False);
   end Sample;

   function Boot_Id return String is
      use Ada.Text_IO;
      F : File_Type;
   begin
      Open (F, In_File, "/proc/sys/kernel/random/boot_id");
      declare
         Line : constant String := Get_Line (F);
      begin
         Close (F);
         return Line;
      end;
   exception
      when others =>
         if Is_Open (F) then
            Close (F);
         end if;
         return "";
   end Boot_Id;

end Dezhan.Platform.Clock;
