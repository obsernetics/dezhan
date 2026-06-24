#!/bin/sh
# Build everything and run every unit-test driver. Fails on any build error or
# test failure. Used in CI alongside the proof gate and the smoke test.
set -eu
HERE=$(cd "$(dirname "$0")/.." && pwd)
cd "$HERE"

gprbuild -p -P dezhan.gpr        # all executables + libraries

fails=0
for d in trusted_core auth storage vault; do
   for g in "$d"/tests/*.gpr; do
      [ -f "$g" ] && gprbuild -p -q -P "$g"
   done
   for e in "$d"/tests/obj/test_*; do
      [ -x "$e" ] || continue
      if "$e" | tail -1 | grep -q "ALL TESTS PASSED"; then
         echo "PASS  $(basename "$e")"
      else
         echo "FAIL  $(basename "$e")"; fails=$((fails + 1))
      fi
   done
done
[ "$fails" -eq 0 ] || { echo "$fails test driver(s) failed"; exit 1; }
echo "All unit tests passed."
