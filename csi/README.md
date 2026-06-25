# dezhan CSI driver

Dynamic-provisioning CSI driver that turns a dezhan vault into a Kubernetes
StorageClass: each PersistentVolumeClaim becomes a dezhan bucket, mounted on the
node with [mountpoint-s3](https://github.com/awslabs/mountpoint-s3).

It is purpose-built for **write-once / append / archival** workloads, which
match dezhan's WORM model (compliance archives, backup repositories, log
sinks). It is **not** suitable for random-write volumes such as databases:
mountpoint-s3 does not support in-place rewrites or rename, and dezhan retention
may forbid overwrites entirely.

## Install

```sh
kubectl apply -f deploy/csi/rbac.yaml
kubectl apply -f deploy/csi/csidriver.yaml
kubectl apply -f deploy/csi/controller.yaml
kubectl apply -f deploy/csi/node.yaml
# edit endpoint + credentials first:
kubectl apply -f deploy/csi/secret-example.yaml
kubectl apply -f deploy/csi/storageclass.yaml
```

## Use

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: archive
spec:
  accessModes: ["ReadWriteMany"]
  storageClassName: dezhan
  resources:
    requests:
      storage: 100Gi   # advisory; object storage is not pre-allocated
```

The provisioner creates a bucket (`pvc-<uuid>`) in dezhan; the node plugin
mounts it at the pod's volume path. Deleting the PVC (with `reclaimPolicy:
Delete`) removes the bucket.

## Architecture

- **Controller** (`--mode=controller`): `CreateVolume` creates a bucket via the
  dezhan S3 API; `DeleteVolume` removes it. Paired with the external-provisioner
  sidecar.
- **Node** (`--mode=node`): `NodePublishVolume` runs `mount-s3 <bucket> <target>
  --endpoint-url <vault>`; `NodeUnpublishVolume` unmounts. Paired with the
  node-driver-registrar sidecar.
- Credentials come from the StorageClass-referenced Secret
  (`accessKeyID` / `secretAccessKey`), never baked into the image.

## Develop

```sh
go build ./...
go vet ./...
go test ./...
docker build -t ghcr.io/obsernetics/dezhan-csi:latest .
```
