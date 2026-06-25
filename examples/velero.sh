#!/usr/bin/env bash
# Use dezhan as the backup target for Velero (Kubernetes backups).
# Velero speaks S3 via its AWS plugin; point it at a dezhan vault.
set -euo pipefail
ENDPOINT="${DEZHAN_ENDPOINT:-http://dezhan.default.svc:8080}"
BUCKET="${BUCKET:-velero}"

cat > /tmp/dezhan-credentials <<EOF
[default]
aws_access_key_id=${DEZHAN_ACCESS_KEY:-dezhanadmin}
aws_secret_access_key=${DEZHAN_SECRET:-dezhandemosecretkey0123456789}
EOF

velero install \
  --provider aws \
  --plugins velero/velero-plugin-for-aws:v1.10.0 \
  --bucket "$BUCKET" \
  --secret-file /tmp/dezhan-credentials \
  --use-volume-snapshots=false \
  --backup-location-config "region=us-east-1,s3ForcePathStyle=true,s3Url=${ENDPOINT}"

# velero backup create demo --include-namespaces default
# velero backup get
