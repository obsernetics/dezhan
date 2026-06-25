# dezhan vs Longhorn: feature coverage

Longhorn is distributed **block storage** for Kubernetes (it provisions
PersistentVolumes). dezhan is an immutable, S3-compatible **backup vault** (it
consumes a PersistentVolume and serves an object API). They are not the same
layer, so this maps each Longhorn capability to how dezhan provides the
equivalent: by its own functionality, by delegating to Kubernetes / the
underlying StorageClass, or where it is an intentional non-goal or roadmap item.

| Longhorn capability | dezhan equivalent | Provided by |
|---|---|---|
| Synchronous replication (N replicas across nodes) | Reed-Solomon erasure coding (4+2) for shard-level redundancy inside the vault; cross-node durability comes from the PV. Run dezhan on a replicated StorageClass (Longhorn itself, Ceph, cloud block) for node-failure tolerance. | dezhan (erasure) + k8s (PV) |
| Snapshots (point-in-time) | Object versioning with delete markers, plus WORM / Object Lock with retention. Immutable point-in-time copies that an attacker or operator cannot roll back before expiry. | dezhan |
| Incremental backups to S3/NFS | dezhan **is** the S3 backup target. Content-addressed chunking deduplicates, so re-ingesting similar data is incremental by construction. | dezhan |
| Replica auto-rebuild / self-heal | Background scrubber verifies every object, rebuilds degraded shards from parity in place, and quarantines anything that lost more than M shards. Exposed as `dezhan_scrub_*` and `dezhan_quarantined`. | dezhan |
| Recurring snapshots / backups (schedules) | Scrub runs on a schedule; client backup schedules via Velero/restic pointing at the vault; retention policies are enforced by a SPARK-proved state machine. | dezhan |
| Encryption at rest | ChaCha20 with per-object keys, vault key wrapped via PBKDF2, key rotation. Always on. | dezhan |
| Volume expansion | Expand the backing PVC through a StorageClass with `allowVolumeExpansion: true`. | k8s |
| Data integrity verification | Per-object HMAC (encrypt-then-MAC), SHA-256 content addressing, and a hash-chained, Ed25519-checkpointed audit log. Stronger than block-level checksums. | dezhan |
| Health / degraded state | `GET /healthz`, the `Available` condition on the `DezhanVault`, and metrics (`dezhan_sealed`, `dezhan_quarantined`, `dezhan_scrub_corrupt`). | dezhan + operator |
| Web UI | Served at `/`. | dezhan |
| Prometheus metrics + Grafana | `/metrics`, a ServiceMonitor, a Grafana dashboard, alerting rules, and an OTel Collector bridge (see below). | dezhan + operator |
| ReadWriteMany access | dezhan is reached over the S3 HTTP API by many concurrent clients; it is not a block device, so RWX does not apply. | dezhan (API) |
| CSI driver / provisioning PVs | Non-goal: dezhan is an object store that *consumes* a PV, it does not *provide* block volumes. Pair it with Longhorn/Ceph/cloud block underneath. | n/a |
| Disaster recovery / async replication to a standby cluster | Roadmap (Phase 2 multi-site replication). Today: replicate by backing up the vault's object store, or run a second vault and dual-write from clients. | roadmap |

## Where dezhan goes beyond Longhorn

- **Provable immutability.** The retention/WORM state machine and clock-integrity
  guard are formally verified in SPARK (gnatprove, 0 unproved), not just tested.
  A tampered system clock cannot expire a lock.
- **Tamper-evident audit.** Every mutation is hash-chained and periodically
  signed; an independent verifier re-checks it offline.
- **Air-gap modes.** Operator seal (read-only), ingest-only, and timed sync
  windows are first-class.

## Observability (OTel / Prometheus / Grafana)

dezhan exposes Prometheus metrics at `/metrics`; the operator annotates each
vault Service for scraping. Manifests in
[`operator/config/observability`](../operator/config/observability):

- `servicemonitor.yaml` - Prometheus Operator scrape target.
- `prometheusrule.yaml` - alerts: vault down, sealed, corruption found,
  unrecoverable objects quarantined, scrub stalled.
- `grafana-dashboard.yaml` - auto-imported Grafana dashboard.
- `otel-collector.yaml` - OpenTelemetry Collector that scrapes `/metrics` and
  exports OTLP to any backend. This is the OTel alignment point: the trusted Ada
  core stays dependency-free and the Collector bridges to OTLP, so traces and
  metrics land in Tempo/Mimir/Grafana, Honeycomb, Datadog, etc.

Apply them with:

```sh
kubectl apply -f operator/config/observability/
```
