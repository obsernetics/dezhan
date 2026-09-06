#!/usr/bin/env sh
# Stamp a release version into the Ada sources so a built binary reports the
# exact release. This makes the git tag the single source of truth for the
# version: release.yml and image.yml run this before building, so a
# hand-maintained literal in the source can never drift from the released tag.
# For local/dev builds the in-repo literal is used as-is.
#
# Usage: scripts/stamp-version.sh 1.2.3
set -eu

VER="${1:?usage: stamp-version.sh X.Y.Z}"
case "$VER" in
  *[!0-9.]*|'') echo "stamp-version: refusing non-numeric version '$VER'" >&2; exit 1 ;;
esac

# Server: the single numeric literal; Version is derived as "dezhan " & it.
sed -i -E \
  "s/Version_Number : constant String := \"[^\"]*\";/Version_Number : constant String := \"${VER}\";/" \
  server/src/dezhan_server.adb

# CLI: its own numeric literal.
sed -i -E \
  "s/Version : constant String := \"[^\"]*\";/Version : constant String := \"${VER}\";/" \
  cli/src/dezhan_cli.adb

echo "stamped version ${VER}"
grep -nE 'Version_Number : constant String :=' server/src/dezhan_server.adb
grep -nE '   Version : constant String :=' cli/src/dezhan_cli.adb
