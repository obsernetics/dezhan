#!/bin/sh
# Line coverage for the SPARK trusted core, measured by running the unit-test
# drivers against gcov-instrumented builds. The trusted core is the formally
# verified heart of the product, so its test coverage is what we report.
#
# Needs a GNAT toolchain and gcov (no lcov/gnatcov required). Run in the build
# VM, not on the host.
set -eu
HERE=$(cd "$(dirname "$0")/.." && pwd)
cd "$HERE"

CFLAGS="-fprofile-arcs -ftest-coverage"

# Instrument the core library and its test drivers, then run every driver so
# .gcda profiles are written next to the core object files.
gprbuild -f -p -q -P trusted_core/dezhan_trusted_core.gpr -cargs $CFLAGS
gprbuild -f -p -q -P trusted_core/tests/tests.gpr -cargs $CFLAGS -largs -fprofile-arcs

for e in trusted_core/tests/obj/test_*; do
   [ -x "$e" ] || continue
   "$e" >/dev/null 2>&1 || { echo "test failed: $e"; exit 1; }
done

cd trusted_core/obj
gcov -n *.gcda 2>/dev/null | awk '
   /^File .*trusted_core\/src/ { getfile=1; sub(/^File ./,""); sub(/.$/,""); name=$0; next }
   getfile && /Lines executed:/ {
      pct=$0; sub(/.*executed:/,"",pct); sub(/%.*/,"",pct)
      n=$0;   sub(/.*of /,"",n)
      ex = int(n*pct/100 + 0.5)
      tot += n; cov += ex
      printf "  %-55s %6.2f%% of %s\n", name, pct, n
      getfile=0
   }
   END {
      if (tot == 0) { print "no coverage data"; exit 2 }
      pct = 100*cov/tot
      printf "\nTRUSTED CORE LINE COVERAGE: %d/%d = %.1f%%\n", cov, tot, pct
      min = ENVIRON["COVERAGE_MIN"]; if (min == "") min = 90
      if (pct + 0.05 < min) {
         printf "FAIL: below floor of %s%%\n", min; exit 1
      }
   }
'
