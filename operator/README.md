# dezhan operator

A Kubernetes operator that runs dezhan, the immutable air-gapped S3 backup
vault, from a single custom resource. You declare a `DezhanVault`; the operator
provisions a StatefulSet, a persistent volume, and a Service, and reports
readiness back on the resource status.

## Install

```sh
# 1. CRD
kubectl apply -f config/crd/

# 2. Operator (namespace dezhan-system, RBAC, Deployment)
kubectl apply -f config/rbac/
kubectl apply -f config/manager/
```

Or, with the Makefile: `make deploy IMG=ghcr.io/obsernetics/dezhan-operator:latest`.

## Create a vault

```sh
kubectl apply -f config/samples/dezhanvault.yaml
kubectl get dezhanvaults        # READY, ENDPOINT, AGE
kubectl describe dv my-vault    # conditions
```

Minimal vault:

```yaml
apiVersion: dezhan.obsernetics.io/v1alpha1
kind: DezhanVault
metadata:
  name: my-vault
spec:
  storage: 100Gi
  requireAuth: true
  secretName: my-vault-secrets   # holds DEZHAN_VAULT_KEY, DEZHAN_SECRET, ...
```

Point any S3 client at `http://my-vault.<namespace>.svc:8080`.

## Spec

| Field | Default | Meaning |
|---|---|---|
| `image` | `ghcr.io/obsernetics/dezhan:latest` | server image |
| `port` | `8080` | listen port |
| `storage` | `50Gi` | persistent volume size (raise it to expand online) |
| `storageClassName` | cluster default | PVC storage class |
| `requireAuth` | `true` | reject unsigned requests |
| `deleteQuorum` | `0` | approver co-signatures required to delete |
| `scrubIntervalSeconds` | `0` (server default 300) | recurring verify-and-self-heal interval |
| `secretName` | none | Secret whose keys become server env vars |
| `serviceType` | `ClusterIP` | `ClusterIP` (headless) / `NodePort` / `LoadBalancer` |
| `resources` | none | container requests/limits |

Put every secret (`DEZHAN_VAULT_KEY`, `DEZHAN_SECRET`, `DEZHAN_ADMIN_TOKEN`,
`DEZHAN_APPROVERS`) in the referenced Secret. Nothing sensitive belongs in the
CR.

## Design notes

- A vault is a single writer over durable storage, so it runs as a
  one-replica StatefulSet with a `ReadWriteOnce` volume. Do not scale it; the
  immutability and audit-chain guarantees assume one writer per volume.
- The pod runs non-root, read-only root filesystem, all capabilities dropped,
  `seccomp=RuntimeDefault`; only `/data` is writable.
- Readiness and liveness use the server's `GET /healthz`.
- Deleting the `DezhanVault` removes the StatefulSet and Service but
  intentionally retains the PVC, so vault data is never destroyed by a CR
  delete. Reclaim the volume manually if you truly want the data gone.
- Reconciles are level-based and idempotent: a steady-state reconcile makes no
  API writes (no hot update loop), and owned-object changes are watched, so a
  deleted Service or StatefulSet is recreated automatically.
- Online volume expansion: raise `spec.storage` and the operator grows the PVC
  in place (the StorageClass must set `allowVolumeExpansion: true`). Shrinking is
  never attempted.

## Development

```sh
make generate   # regenerate deepcopy + CRD from kubebuilder markers
make build      # go build ./cmd
make test       # go test ./...
make docker-build IMG=...
```

`make generate` needs `controller-gen`; `go mod tidy` (to produce `go.sum`)
needs network access to the Go module proxy. Both are normal Go toolchain
steps and are intentionally not vendored into this repo.
