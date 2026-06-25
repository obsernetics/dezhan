#!/usr/bin/env bash
# Use dezhan with the AWS CLI (path-style S3). Set the endpoint to your vault.
set -euo pipefail
ENDPOINT="${DEZHAN_ENDPOINT:-http://localhost:8080}"

aws configure set aws_access_key_id     "${DEZHAN_ACCESS_KEY:-dezhanadmin}"
aws configure set aws_secret_access_key "${DEZHAN_SECRET:-dezhandemosecretkey0123456789}"
aws configure set default.s3.addressing_style path

s3() { aws --endpoint-url "$ENDPOINT" --region us-east-1 "$@"; }

s3 s3 mb s3://backups                       # create a bucket
s3 s3 cp ./data.tar s3://backups/           # upload (any size; multipart handled)
s3 s3 ls s3://backups/
s3 s3 cp s3://backups/data.tar ./restored.tar

# Immutable (WORM) bucket: objects cannot be deleted before retention expires.
s3 s3api create-bucket --bucket vault --object-lock-enabled-for-bucket
s3 s3 cp important.bak s3://vault/
s3 s3 rm s3://vault/important.bak || echo "denied until retention expires (expected)"
