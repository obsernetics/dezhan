#!/bin/sh
# Generate a CycloneDX SBOM for dezhan. There are no third-party runtime
# dependencies: every cryptographic primitive (SHA-256/512, ChaCha20,
# HMAC-SHA256, Ed25519), the storage engine, and the S3 layer are in-tree. The
# only linked components are the GNAT Ada runtime and the system C library.
set -eu
VERSION=${1:-1.0}
GNAT_VER=$(gnatls --version 2>/dev/null | head -1 | sed 's/^[^0-9]*//' || echo unknown)
LIBC_VER=$(ldd --version 2>/dev/null | head -1 | awk '{print $NF}' || echo unknown)

cat <<JSON
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {
    "component": {
      "type": "application",
      "name": "dezhan",
      "version": "${VERSION}",
      "licenses": [ { "license": { "id": "Apache-2.0" } } ],
      "description": "Immutable, S3-compatible backup vault with a SPARK-verified core"
    },
    "properties": [
      { "name": "dezhan:thirdPartyRuntimeDependencies", "value": "0" },
      { "name": "dezhan:cryptoProvider", "value": "in-tree (no OpenSSL/libsodium)" }
    ]
  },
  "components": [
    {
      "type": "framework",
      "name": "gnat-runtime",
      "version": "${GNAT_VER}",
      "description": "GNAT Ada runtime library (libgnat), statically linked"
    },
    {
      "type": "library",
      "name": "glibc",
      "version": "${LIBC_VER}",
      "description": "GNU C library (open/close/fsync/rename via the Platform.Sync FFI)"
    }
  ]
}
JSON
