#!/usr/bin/env bash
# One-shot on-prem install: build the dezhan image and run it with auth on and
# data on a persistent volume. Generates a vault key and S3 credential for you.
#
#   ./install.sh
#
# Override with env vars: DEZHAN_PORT, DEZHAN_DATA (volume name or host path),
# DEZHAN_VAULT_KEY, DEZHAN_ACCESS_KEY, DEZHAN_SECRET.
set -euo pipefail
cd "$(dirname "$0")"

PORT=${DEZHAN_PORT:-8080}
DATA=${DEZHAN_DATA:-dezhan-data}
NAME=dezhan

rand() { openssl rand -hex "$1" 2>/dev/null || head -c "$1" /dev/urandom | xxd -p | tr -d '\n'; }
KEY=${DEZHAN_VAULT_KEY:-$(rand 32)}
ACCESS=${DEZHAN_ACCESS_KEY:-dezhanadmin}
SECRET=${DEZHAN_SECRET:-$(rand 24)}

command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }

echo "Building image..."
docker build -q -t "$NAME" . >/dev/null

docker rm -f "$NAME" >/dev/null 2>&1 || true
echo "Starting dezhan..."
docker run -d --name "$NAME" --restart unless-stopped \
  -p "$PORT:8080" -v "$DATA:/data" \
  -e DEZHAN_VAULT_KEY="$KEY" \
  -e DEZHAN_REQUIRE_AUTH=1 \
  -e DEZHAN_ACCESS_KEY="$ACCESS" \
  -e DEZHAN_SECRET="$SECRET" \
  "$NAME" >/dev/null

cat <<EOF

dezhan is running.

  endpoint   http://localhost:$PORT
  access key $ACCESS
  secret key $SECRET
  vault key  $KEY

Save the vault key: it is required to decrypt data at rest. Test it:

  aws --endpoint-url http://localhost:$PORT --region us-east-1 s3 mb s3://backups
EOF
