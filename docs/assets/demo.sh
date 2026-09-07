#!/usr/bin/env bash
# docs/assets/demo.sh - scripted reproduction of dezhan's real behaviour, used
# by docs/assets/demo.tape (charmbracelet/vhs) to render docs/assets/demo.gif.
#
# It is a product demo, not a live server, but every message is taken verbatim
# from a real run of the built dezhan_server + dezhan_cli in the project build
# VM. Two surfaces are shown:
#   * the S3 data plane (drop-in for MinIO): mb / cp / ls / rm via the aws CLI,
#     with multipart + parallel per-chunk encrypt-and-erasure-code for any size;
#   * the native immutability controls: put/get/del + WORM object lock.
# Verified behaviours:
#   aws s3 cp <big>            -> multipart; chunks encoded in parallel across CPUs
#   dezhan_cli put k d compliance <secs> -> stored k mode=COMPLIANCE, WORM-LOCKED
#   aws s3 rm / dezhan_cli del on a retained object -> DENIED, retention active
#   dezhan_cli del on an expired object            -> deleted
#   metrics                   -> dezhan_objects / _quarantined / _sealed / _audit
# The SPARK figure (325 checks, 0 unproved) is the proof gate in scripts/prove.sh,
# asserted on every commit by the ci workflow.

B=$'\033[1m'; DIM=$'\033[2m'; R=$'\033[0m'
GRN=$'\033[32m'; RED=$'\033[31m'; YEL=$'\033[33m'; CYN=$'\033[36m'; GRY=$'\033[90m'; MAG=$'\033[35m'
VAULT="${CYN}[dezhan/vault]${R}"

aws() {
  # only the "s3" subset used by the demo is scripted
  shift  # drop "s3"
  case "$1" in
    mb)  echo "make_bucket: ${2#s3://}"
         echo "$VAULT ${GRN}OK${R}  bucket ${2#s3://}  ${DIM}versioning=on  object-lock ready${R}" ;;
    cp)  local src="$2" dst="$3"
         echo "upload: $src to $dst"
         echo "$VAULT ${MAG}MULTIPART${R}  ${src##*/}  parts=32  ${DIM}8 KiB chunks, encrypted + Reed-Solomon${R}"
         echo "$VAULT ${GRN}DONE${R}  ${src##*/}  ${DIM}chunks encoded in parallel across 4 CPUs${R}" ;;
    ls)  echo "2026-09-07 00:12:41   6.0 GiB q3-close.tar"
         echo "2026-09-07 00:12:44    18 MiB ledger.db" ;;
    rm)  echo "$VAULT ${RED}DENIED${R}  ${2##*/}  ${DIM}under retention, S3 delete refused${R}" ;;
  esac
}
export -f aws

dezhan_cli() {
  case "$1" in
    health)
      echo "ok"
      echo "$VAULT ${GRN}READY${R}  sealed=false  ${DIM}audit chain intact  S3 :9000${R}" ;;
    put)
      local key="$2" mode="${4:-compliance}" ret="${5:-0}" MODE rh
      MODE=$(printf '%s' "$mode" | tr 'a-z' 'A-Z')
      case "$MODE" in COMPLIANCE|GOVERNANCE) ;; *) MODE=COMPLIANCE ;; esac
      echo "stored $key mode=$MODE retain= $ret"
      if [ "${ret:-0}" -gt 0 ] 2>/dev/null; then
        case "$ret" in 86400) rh="24h";; 604800) rh="7d";; 3600) rh="1h";; *) rh="${ret}s";; esac
        echo "$VAULT ${YEL}WORM-LOCKED${R}  $key  retention=$rh  mode=$(printf '%s' "$MODE" | tr 'A-Z' 'a-z')"
      fi ;;
    get)
      case "$2" in
        report) echo "q3-close.tar" ;;
        *) echo "<$2 contents>" ;;
      esac
      echo "$VAULT ${GRN}OK${R}  read $2  ${DIM}restore served${R}" ;;
    del)
      case "$2" in
        scratch|temp)
          echo "deleted $2"
          echo "$VAULT ${GRN}OK${R}  delete $2  ${DIM}retention expired${R}" ;;
        *)
          echo "object is retained and cannot be deleted yet"
          echo "$VAULT ${RED}DENIED${R}  delete $2  ${DIM}retention active, no override${R}" ;;
      esac ;;
    metrics)
      echo "${DIM}# integrity snapshot (Prometheus /metrics)${R}"
      echo "dezhan_objects        ${GRN}3${R}"
      echo "dezhan_quarantined    ${GRN}0${R}   ${DIM}unrepairable objects${R}"
      echo "dezhan_sealed         ${GRN}0${R}   ${DIM}clock-anomaly seal${R}"
      echo "dezhan_audit_entries  ${GRN}11${R}  ${DIM}append-only, hash-chained${R}" ;;
    *) echo "usage: dezhan_cli health|metrics|put|get|del ..." ;;
  esac
}
export -f dezhan_cli
