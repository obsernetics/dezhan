# Design: Vault orchestration + HTTP API + CLI (POC)

Date: 2026-06-23
Status: Implemented (end-to-end POC)
Spec source of truth: `docs/SPEC.md` (Immutable Vault, Security Model, MVP).

## Goal

Tie the verified trusted core and the storage engine into a working end-to-end
proof of concept that demonstrates the value proposition: backups that cannot be
modified or deleted before their retention expires, with the guarantee resting on
formally verified components.

## Layers

- **`Dezhan.Vault`** orchestrates the verified primitives:
  - stores object bytes through the encrypted content-addressed store;
  - creates a retention lock (Object Lock) via the verified Retention state
    machine, using trusted time from the verified Clock Guard;
  - records every action (store, delete allowed/denied, seal) in the verified
    append-only Audit Chain.
  Deletion is permitted only when `Can_Delete` allows it, so a compliance object
  cannot be removed before expiry even with a bypass, and a manipulated system
  clock cannot expire it (trusted time advances only by the monotonic clock).

- **`dezhan_server`** exposes the vault over HTTP using `GNAT.Sockets`
  (no external dependency, in keeping with the air-gap / single-language goals):
  `PUT/GET/HEAD/DELETE /v/<name>`, `GET /healthz`, Prometheus `GET /metrics`,
  `POST /admin/tick`, and a minimal web UI at `/`. Object-lock parameters are
  passed via `X-Dezhan-Mode` and `X-Dezhan-Retain` headers; `X-Dezhan-Bypass`
  requests a governance bypass. Trusted time is advanced from the real system
  clock (through the platform boundary) on each request.

- **`dezhan_cli`** is a thin HTTP client for the server.

## What the POC demonstrates (validated)

`test_vault` and a live server smoke test show: encrypted round-trip; a
compliance object denied deletion before expiry, including with a bypass; a
forward clock attack sealing the vault without expiring the lock; deletion
allowed only after genuine monotonic time passes; and a self-verifying audit
chain. The web UI and CLI drive the same API.

## Out of scope for the POC (tracked in docs/NOTES.md)

- AWS SigV4 authentication and multipart uploads (the API is S3-shaped, not
  S3-complete).
- Durable metadata persistence: the vault index and audit chain are in memory, so
  a server restart loses them (stored chunks remain on disk). Persistence lands
  with the durable storage work.
- Key management: the server uses a fixed demo key.
- The server is single-threaded (one request at a time) and the web UI is
  intentionally minimal.
