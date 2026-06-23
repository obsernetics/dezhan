--  In-tree DEFLATE (RFC 1951): raw deflate/inflate, no zlib or gzip wrapper.
--
--  Deflate uses one fixed-Huffman block with greedy LZ77 matching, so its output
--  is decodable by any standard inflate (e.g. zlib raw, wbits = -15). Inflate
--  handles stored, fixed-Huffman, and dynamic-Huffman blocks, so it can read
--  output from zlib too. Pure in-tree, no external dependency.
package Dezhan.Storage.Deflate with SPARK_Mode => Off is

   type Octet is mod 2 ** 8;
   type Buffer is array (Natural range <>) of Octet;

   --  Compress Data into a raw DEFLATE stream.
   function Deflate (Data : Buffer) return Buffer;

   --  Decompress a raw DEFLATE stream. Raises Format_Error on malformed input.
   function Inflate (Data : Buffer) return Buffer;

   Format_Error : exception;

end Dezhan.Storage.Deflate;
