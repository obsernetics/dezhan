#!/bin/sh
# dezhan on-prem installer. Pulls the published image and runs it with auth on
# and data on a persistent volume, generating a vault key and S3 credential.
#
#   curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/obsernetics/dezhan/main/install.sh | sh
#
# Override with env vars: DEZHAN_PORT, DEZHAN_DATA, DEZHAN_IMAGE,
# DEZHAN_VAULT_KEY, DEZHAN_ACCESS_KEY, DEZHAN_SECRET.
set -eu

IMAGE=${DEZHAN_IMAGE:-ghcr.io/obsernetics/dezhan:latest}
PORT=${DEZHAN_PORT:-8080}
DATA=${DEZHAN_DATA:-dezhan-data}
NAME=dezhan

rand() { openssl rand -hex "$1" 2>/dev/null || head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }
KEY=${DEZHAN_VAULT_KEY:-$(rand 32)}
ACCESS=${DEZHAN_ACCESS_KEY:-dezhanadmin}
SECRET=${DEZHAN_SECRET:-$(rand 24)}

command -v docker >/dev/null 2>&1 || { echo "docker is required" >&2; exit 1; }

echo "Pulling $IMAGE ..."
docker pull -q "$IMAGE" >/dev/null

docker rm -f "$NAME" >/dev/null 2>&1 || true
echo "Starting dezhan ..."
docker run -d --name "$NAME" --restart unless-stopped \
  -p "$PORT:8080" -v "$DATA:/data" \
  -e DEZHAN_VAULT_KEY="$KEY" \
  -e DEZHAN_REQUIRE_AUTH=1 \
  -e DEZHAN_ACCESS_KEY="$ACCESS" \
  -e DEZHAN_SECRET="$SECRET" \
  "$IMAGE" >/dev/null

cat <<EOF

dezhan is running.

  endpoint   http://localhost:$PORT
  access key $ACCESS
  secret key $SECRET
  vault key  $KEY

Save the vault key: it is required to decrypt data at rest. Test it:

  aws --endpoint-url http://localhost:$PORT --region us-east-1 s3 mb s3://backups
EOF
