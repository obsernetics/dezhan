# Project Specification (LLM-Oriented)

> This file is the **authoritative specification** for dezhan. It is the source
> of truth for what we build. See `CLAUDE.md` → "Spec-driven method" for how it
> governs design and implementation. Items marked "future"/"Phase N" are OUT of
> current scope.

## Vision

Build an open-source, on-premise cyber-resilience platform for regulated organizations (banking, healthcare, government, industrial/OT) focused on immutable, air-gapped, and cryptographically verifiable data protection.

The system's primary value proposition is **provable immutability**: integrity-critical behavior is formally verified rather than merely tested.

The product must prioritize:

1. Integrity over throughput.
2. Immutability over convenience.
3. Verifiability over feature count.
4. Operational simplicity in air-gapped environments.
5. Compliance readiness for highly regulated industries.

---

## Core Product Goals

### 1. Immutable Vault (MVP)

Provide an S3-compatible object storage endpoint supporting:

* Object PUT/GET/HEAD/LIST
* Multipart uploads
* AWS Signature V4 authentication
* Object Lock / WORM semantics

The vault must be usable immediately as a target for existing backup products.

Examples:

* Veeam
* Restic
* Velero
* Bareos
* Generic S3 clients

### 2. Provable Immutability

Integrity-critical functionality must be isolated inside a small trusted core.

The trusted core is responsible for:

* Retention lock enforcement
* Lock expiration validation
* Clock integrity checks
* Append-only audit chain verification
* Erasure coding correctness

Critical invariants:

```text
A retained object can never be deleted before expiry.

A retention period can never be shortened.

Audit entries are immutable.

Clock manipulation cannot bypass retention.

Integrity verification must detect corruption.
```

These guarantees should be machine-verifiable.

---

## Architectural Principles

### Single-language implementation

Use Ada 2022 for the entire platform.

Use SPARK only for the trusted core.

External dependencies are allowed only through minimal, audited FFI boundaries.

### Layered architecture

```text
+---------------------------------------------------+
| API / Web UI / CLI / Scheduler / RBAC            |
+---------------------------------------------------+
| Movers / Dedup / Compression / Encryption        |
+---------------------------------------------------+
| Content-addressed Storage Engine                 |
+---------------------------------------------------+
| Trusted Core (SPARK verified)                    |
+---------------------------------------------------+
| Disk / Media / Filesystem                        |
+---------------------------------------------------+
```

---

## Trusted Core Responsibilities

The trusted core must remain small and stable.

Modules:

### Retention State Machine

Responsible for:

* Object lock creation
* Governance mode
* Compliance mode
* Retention expiration
* Legal hold support

Mandatory invariant:

```text
Retention may be extended.
Retention may never be shortened.
A legal hold blocks deletion absolutely, even past expiry and even under
a Governance-mode bypass, until the hold is released.
```

---

### Clock Integrity Guard

Responsible for:

* Detecting backward time movement
* Preventing clock rollback attacks
* Providing trusted timestamps

Mandatory invariant:

```text
System time manipulation cannot invalidate active locks.
```

---

### Audit Chain

Provide:

* Append-only log
* Cryptographic chaining
* Signed checkpoints
* Independent verification tool

Mandatory invariant:

```text
Past audit records cannot be altered undetected.
```

---

### Erasure Coding

Provide Reed-Solomon redundancy.

Requirements:

* Configurable data/parity layout
* Reconstruction of missing shards
* Corruption detection

Mandatory invariant:

```text
Recoverable failures must always reconstruct original content.
```

---

## Storage Engine

Implement a content-addressed immutable storage engine.

Characteristics:

```text
Object -> Chunk -> Hash -> Immutable Storage
```

Requirements:

* Deduplication
* Compression
* Encryption at source
* Integrity verification
* Background scrubbing
* Merkle manifests

Objects are immutable.

Modification creates a new object version.

No in-place updates.

---

## Security Model

Threats explicitly addressed:

### Ransomware

Attack:

```text
Backup deletion before encryption.
```

Mitigation:

```text
WORM enforcement.
Immutable retention locks.
```

---

### Malicious Administrator

Attack:

```text
Privileged insider deletes backups.
```

Mitigation:

```text
Separate authentication domain.
Quorum approvals.
Immutable audit chain.
```

---

### Clock Manipulation

Attack:

```text
Move system clock forward to expire locks.
```

Mitigation:

```text
Trusted time validation.
Monotonic time enforcement.
```

---

### Silent Corruption

Attack:

```text
Media decay or bit rot.
```

Mitigation:

```text
Merkle verification.
Periodic scrubbing.
Erasure coding.
```

---

## Authentication and Authorization

Requirements:

* Local authentication realm
* Never depend on enterprise directory availability
* Role-based access control
* Multi-person approval workflows
* API token support
* Service accounts

Future:

* OIDC
* LDAP
* Hardware-backed identities

---

## Air-Gap Features

The platform must support isolated environments.

Capabilities:

### Sync Windows

Allow data transfer only during approved periods.

### Seal Operation

Vault enters read-only mode.

No writes allowed while sealed.

### One-Way Ingest

Support environments where data can enter but never leave.

### Technology Break

Support copying between independent media classes.

Example:

```text
Disk -> Tape
Disk -> Offline appliance
Disk -> Export media
```

---

## Observability

Expose:

* Prometheus metrics
* Structured logs
* Audit events
* Health endpoints

Key metrics:

```text
Storage capacity
Object count
Scrub status
Corruption events
Retention violations
Replication lag
Air-gap status
```

---

## MVP Scope

Version 1.0 must include only:

### Required

* S3-compatible immutable vault
* Object Lock
* Retention enforcement
* SPARK-verified trusted core
* Content-addressed storage
* Encryption at rest
* Erasure coding
* Audit chain
* Background scrubbing
* CLI
* Minimal web UI

### Explicitly Excluded

* Kubernetes backup
* Native Terraform provider
* Multi-site replication
* Full enterprise IAM
* Tape support
* Database movers
* Filesystem movers

---

## General-Purpose Storage (post-MVP goal)

dezhan is primarily an immutable vault, and provable immutability remains the
headline. As a secondary, post-MVP goal it should also be usable as a
general-purpose S3 object store, by supporting two per-bucket modes:

* Immutable: Object Lock on; retention enforced by the SPARK trusted core.
* Standard: mutable objects (overwrite, delete, versioning); no retention lock.

Both modes share the same S3 API and content-addressed storage engine, and both
receive audit-chain logging and integrity scrubbing. Only immutable buckets are
governed by the retention state machine. This does not change the priority of
integrity over throughput: dezhan is not intended to match general-purpose stores
on raw throughput.

---

## Non-Functional Requirements

### Reliability

```text
No single metadata corruption event may destroy recoverability.
```

### Performance

```text
Optimize for integrity and predictability, not maximum throughput.
```

### Deployment

Must operate fully:

* On-premise
* Offline
* Air-gapped
* Without cloud dependencies

### Distribution

Provide:

* Static binaries
* Minimal runtime requirements
* Reproducible builds
* Software bill of materials

---

## Future Roadmap

Phase 2:

* Filesystem movers
* PostgreSQL protection
* MySQL protection
* Policy engine
* Scheduler

Phase 3:

* Air-gap orchestration
* Quorum workflows
* Advanced RBAC

Phase 4:

* Kubernetes protection
* CSI snapshots
* etcd backup

Phase 5:

* Compliance certifications
* FIPS support
* Independent verification of immutability claims

---

## Success Criteria

The platform succeeds if a regulated organization can state:

> "Our backups cannot be modified or deleted before their retention period expires, and this guarantee is cryptographically and formally verified."
