--  Erasure Coding: fourth unit of the SPARK trusted core.
--
--  Systematic Reed-Solomon over GF(2^8), enforcing the spec's mandatory
--  invariant: "recoverable failures must always reconstruct original content"
--  (docs/SPEC.md, Trusted Core, Erasure Coding).
--
--  Implemented in-tree with no external dependency. gnatprove proves absence of
--  run-time errors and termination; the algebraic reconstruction guarantee is
--  the Reed-Solomon / MDS property, validated by an exhaustive round-trip test
--  rather than formally proved (see docs/NOTES.md).
with Interfaces; use Interfaces;
package Dezhan.Trusted_Core.Erasure with SPARK_Mode is

   subtype Symbol is Interfaces.Unsigned_8;  --  a GF(256) element / one byte

   Max_Data         : constant := 8;
   Max_Parity       : constant := 8;
   Max_Shards       : constant := Max_Data + Max_Parity;  --  16
   Max_Shard_Length : constant := 1024;

   subtype Data_Range  is Positive range 1 .. Max_Data;
   subtype Shard_Range is Positive range 1 .. Max_Shards;
   subtype Len_Range   is Positive range 1 .. Max_Shard_Length;

   --  Fixed-capacity blocks; the first K (or M, or N) rows and first L columns
   --  are the live data, per the K, M, L parameters.
   type Data_Block   is array (Data_Range,  Len_Range) of Symbol;
   type Parity_Block is array (Data_Range,  Len_Range) of Symbol;  --  rows 1..M
   type Shard_Block  is array (Shard_Range, Len_Range) of Symbol;  --  rows 1..K+M
   type Present_Map  is array (Shard_Range) of Boolean;            --  1..K+M

   --  Compute M parity shards from the K data shards (each L bytes).
   procedure Encode
     (K, M, L : Positive;
      Data    : Data_Block;
      Parity  : out Parity_Block)
     with Pre => K <= Max_Data and then M <= Max_Parity
                 and then L <= Max_Shard_Length;

   --  Reconstruct the K data shards from any available shards. Shards holds the
   --  N = K+M shards (row i meaningful iff Present (i)); rows 1..K are data,
   --  rows K+1..K+M are parity. On Success, Data holds the K reconstructed data
   --  shards. Success is False if fewer than K shards are present.
   procedure Reconstruct
     (K, M, L : Positive;
      Present : Present_Map;
      Shards  : Shard_Block;
      Data    : out Data_Block;
      Success : out Boolean)
     with Pre => K <= Max_Data and then M <= Max_Parity
                 and then K + M <= Max_Shards
                 and then L <= Max_Shard_Length;

end Dezhan.Trusted_Core.Erasure;
