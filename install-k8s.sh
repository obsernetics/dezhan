#!/usr/bin/env bash
# One-shot Kubernetes install: deploy the operator, create a Secret with a
# generated vault key and S3 credential, and provision a vault.
#
#   ./install-k8s.sh
#
# Override with env vars: DEZHAN_NAMESPACE, DEZHAN_VAULT_NAME, DEZHAN_STORAGE,
# DEZHAN_VAULT_KEY, DEZHAN_ACCESS_KEY, DEZHAN_SECRET.
set -euo pipefail
cd "$(dirname "$0")"

NS=${DEZHAN_NAMESPACE:-default}
NAME=${DEZHAN_VAULT_NAME:-dezhan}
STORAGE=${DEZHAN_STORAGE:-50Gi}

rand() { openssl rand -hex "$1" 2>/dev/null || head -c "$1" /dev/urandom | xxd -p | tr -d '\n'; }
KEY=${DEZHAN_VAULT_KEY:-$(rand 32)}
ACCESS=${DEZHAN_ACCESS_KEY:-dezhanadmin}
SECRET=${DEZHAN_SECRET:-$(rand 24)}

command -v kubectl >/dev/null || { echo "kubectl is required" >&2; exit 1; }

echo "Installing operator..."
kubectl apply -f operator/config/crd/
kubectl apply -f operator/config/rbac/
kubectl apply -f operator/config/manager/
kubectl -n dezhan-system rollout status deploy/dezhan-operator --timeout=120s

echo "Creating credentials secret..."
kubectl -n "$NS" create secret generic "$NAME-secrets" \
  --from-literal=DEZHAN_VAULT_KEY="$KEY" \
  --from-literal=DEZHAN_ACCESS_KEY="$ACCESS" \
  --from-literal=DEZHAN_SECRET="$SECRET" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "Provisioning vault..."
kubectl -n "$NS" apply -f - <<EOF
apiVersion: dezhan.obsernetics.io/v1alpha1
kind: DezhanVault
metadata:
  name: $NAME
spec:
  storage: $STORAGE
  requireAuth: true
  secretName: $NAME-secrets
EOF
kubectl -n "$NS" wait --for=condition=Available "dezhanvault/$NAME" --timeout=180s || true

cat <<EOF

dezhan vault '$NAME' deployed in namespace '$NS'.

  endpoint   http://$NAME.$NS.svc:8080
  access key $ACCESS
  secret key $SECRET
  vault key  $KEY   (stored in secret $NAME-secrets; save it to decrypt at rest)

  kubectl -n $NS get dezhanvaults
EOF
