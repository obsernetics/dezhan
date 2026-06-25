#!/usr/bin/env bash
# Use the built-in dezhan_cli (minimal client, no external deps).
# Point it at a vault with DEZHAN_ADDR=host:port (default 127.0.0.1:8080).
set -euo pipefail
export DEZHAN_ADDR="${DEZHAN_ADDR:-127.0.0.1:8080}"
CLI="${CLI:-server/obj/dezhan_cli}"   # built by: gprbuild -P dezhan.gpr

"$CLI" health                         # liveness (ok / sealed)
"$CLI" metrics                        # Prometheus metrics

# Store an object under a retention mode and period (seconds).
"$CLI" put report-2026 "quarterly numbers" compliance 86400
"$CLI" get report-2026

# Delete is refused while under retention (WORM); 'bypass' needs the privilege.
"$CLI" del report-2026 || echo "denied until retention expires (expected)"
