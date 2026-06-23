with Interfaces.C; use Interfaces.C;
package body Dezhan.Platform.Sync with SPARK_Mode => Off is

   function C_Open (Path : char_array; Flags : int) return int
     with Import, Convention => C, External_Name => "open";
   function C_Close (Fd : int) return int
     with Import, Convention => C, External_Name => "close";
   function C_Fsync (Fd : int) return int
     with Import, Convention => C, External_Name => "fsync";
   function C_Rename (Old_Path, New_Path : char_array) return int
     with Import, Convention => C, External_Name => "rename";

   O_RDONLY : constant int := 0;

   procedure Fsync (Path : String) is
      Fd     : constant int := C_Open (To_C (Path), O_RDONLY);
      Ignore : int;
   begin
      if Fd >= 0 then
         Ignore := C_Fsync (Fd);
         Ignore := C_Close (Fd);
      end if;
   end Fsync;

   procedure Durable_Rename (Source, Target, Dir : String) is
      Ignore : int;
   begin
      Ignore := C_Rename (To_C (Source), To_C (Target));
      Fsync (Dir);
   end Durable_Rename;

end Dezhan.Platform.Sync;
