#!/usr/bin/env bash
# docs/assets/demo.sh - scripted reproduction of dezhan's real WORM behaviour,
# used by docs/assets/demo.tape (charmbracelet/vhs) to render docs/assets/demo.gif.
#
# It is a product demo, not a live server, but every message is taken verbatim
# from a real run of the built dezhan_server + dezhan_cli in the project build
# VM. The commands are the real CLI's subcommands (health|put|get|del|metrics).
# Verified outputs:
#   put <k> <data> compliance <secs> -> stored <k> mode=COMPLIANCE retain= <secs>
#   get <k>                          -> <data>
#   del <retained>                   -> object is retained and cannot be deleted yet
#   del <expired / retain 0>         -> deleted <k>
#   metrics                          -> dezhan_objects / _quarantined / _sealed / _audit_entries
# The SPARK figure (325 checks, 0 unproved) is the proof gate in scripts/prove.sh,
# asserted on every commit by the ci workflow.

B=$'\033[1m'; DIM=$'\033[2m'; R=$'\033[0m'
GRN=$'\033[32m'; RED=$'\033[31m'; YEL=$'\033[33m'; CYN=$'\033[36m'; GRY=$'\033[90m'
VAULT="${CYN}[dezhan/vault]${R}"

dezhan_cli() {
  case "$1" in
    health)
      echo "ok"
      echo "$VAULT ${GRN}READY${R}  sealed=false  ${DIM}audit chain intact${R}" ;;
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
      echo "dezhan_objects        ${GRN}2${R}"
      echo "dezhan_quarantined    ${GRN}0${R}   ${DIM}unrepairable objects${R}"
      echo "dezhan_sealed         ${GRN}0${R}   ${DIM}clock-anomaly seal${R}"
      echo "dezhan_audit_entries  ${GRN}8${R}   ${DIM}append-only, hash-chained${R}" ;;
    *) echo "usage: dezhan_cli health|metrics|put|get|del ..." ;;
  esac
}
export -f dezhan_cli
