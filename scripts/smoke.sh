#!/bin/sh
# End-to-end smoke test: build the server, start it (auth required, fast KDF for
# the test), run the boto3 conformance driver, and stop. Run inside the dev
# environment (needs gprbuild, a Python with boto3). Exits non-zero on failure.
set -e
HERE=$(cd "$(dirname "$0")/.." && pwd)
PORT=${PORT:-8080}
ROOT=$(mktemp -d)

gprbuild -q -P "$HERE/server/dezhan_server.gpr"

DEZHAN_REQUIRE_AUTH=1 DEZHAN_KDF_ITERS=2000 \
  "$HERE/server/obj/dezhan_server" "$PORT" "$ROOT" >"$ROOT/server.log" 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null; rm -rf "$ROOT"' EXIT
sleep 2

python3 "$HERE/scripts/smoke.py" "$PORT"
