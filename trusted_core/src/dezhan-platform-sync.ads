--  Crash-safe file persistence (audited FFI boundary). Binds libc fsync/rename
--  so a written file and the rename that publishes it are flushed to stable
--  storage, surviving a power loss. Untrusted by design (regular Ada/FFI); it
--  carries no proved invariant, it just makes the platform's persistence durable.
package Dezhan.Platform.Sync with SPARK_Mode => Off is

   --  Flush the file (or directory) at Path to stable storage. Best-effort:
   --  a path that cannot be opened is silently skipped.
   procedure Fsync (Path : String);

   --  Atomically replace Target with Source (POSIX rename, which never leaves
   --  Target missing), then fsync Dir so the replacement itself is durable.
   --  Call Fsync on Source first if its contents must also be durable.
   procedure Durable_Rename (Source, Target, Dir : String);

end Dezhan.Platform.Sync;
