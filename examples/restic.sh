#!/usr/bin/env bash
# Back up a directory to dezhan with restic (treats dezhan as an S3 repo).
set -euo pipefail
ENDPOINT="${DEZHAN_ENDPOINT:-http://localhost:8080}"
export AWS_ACCESS_KEY_ID="${DEZHAN_ACCESS_KEY:-dezhanadmin}"
export AWS_SECRET_ACCESS_KEY="${DEZHAN_SECRET:-dezhandemosecretkey0123456789}"
export RESTIC_REPOSITORY="s3:${ENDPOINT}/restic-repo"
export RESTIC_PASSWORD="${RESTIC_PASSWORD:-change-me}"

restic init                       # one-time
restic backup "${1:-$HOME/documents}"
restic snapshots
# restic restore latest --target /tmp/restored
