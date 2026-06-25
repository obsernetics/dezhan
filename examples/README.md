# examples

Runnable examples for using dezhan. Set `DEZHAN_ENDPOINT` (and access
key/secret) to your vault first.

| File | What it shows |
|---|---|
| `aws-cli.sh` | AWS CLI: buckets, upload/download, WORM/Object Lock |
| `cli.sh` | the built-in `dezhan_cli` (health, metrics, put/get/del) |
| `boto3_demo.py` | AWS SDK: put/get, user metadata, versioning, WORM, presigned URL |
| `restic.sh` | back up a directory with restic |
| `velero.sh` | use dezhan as the Velero backup target (Kubernetes backups) |
| `kubernetes-vault.yaml` | a `DezhanVault` custom resource for the operator |
