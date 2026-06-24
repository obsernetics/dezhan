#!/bin/sh
# SPARK proof gate. Runs gnatprove over the trusted core and fails (non-zero
# exit) if ANY check is unproved. Used as a hard gate in CI: the build does not
# pass unless every mandatory invariant is machine-proved.
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
cd "$HERE/trusted_core"

# --checks-as-errors=on makes gnatprove return non-zero on any unproved check.
gnatprove -P dezhan_trusted_core.gpr --level=2 -j0 --counterexamples=off \
          --checks-as-errors=on --report=fail
RC=$?

# Belt and suspenders: also inspect the summary's Unproved column ("." = none).
OUT="obj/gnatprove/gnatprove.out"
UNPROVED="?"
[ -f "$OUT" ] && UNPROVED=$(awk '/^Total/ {print $NF}' "$OUT")

if [ "$RC" -ne 0 ] || { [ "$UNPROVED" != "." ] && [ "$UNPROVED" != "0" ]; }; then
   echo "SPARK PROOF GATE FAILED (gnatprove exit $RC, unproved column '$UNPROVED')"
   exit 1
fi
echo "SPARK proof gate OK: all checks proved (0 unproved)."
