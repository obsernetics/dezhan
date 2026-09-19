#!/usr/bin/env bash
# docs/assets/demo.sh - scripted reproduction of the dezhanctl CLI, used by
# docs/assets/demo.tape (charmbracelet/vhs) to render docs/assets/demo.gif.
#
# It is a product demo, not a live server, but every line is taken verbatim from
# a real run of the built dezhanctl against dezhan_server in the project VM:
#   dezhanctl health                 -> ok
#   dezhanctl put <k> --file f ...   -> stored <k> mode=COMPLIANCE retain= <secs>
#   dezhanctl stat <k>               -> name/status/content-type/etag
#   dezhanctl del <retained>         -> HTTP 403: object is retained ...
#   dezhanctl dashboard              -> the live TUI (the frame in dashboard.frame,
#                                       captured with `dezhanctl dashboard --frame`)
# The SPARK figure (325 checks, 0 unproved) is the proof gate in scripts/prove.sh.

R=$'\033[0m'; DIM=$'\033[2m'; GRN=$'\033[32m'; RED=$'\033[31m'; CYN=$'\033[36m'

dezhanctl() {
  case "$1" in
    health) echo "ok" ;;
    put)
      local key="$2"
      echo "stored $key mode=COMPLIANCE retain= 86400" ;;
    stat)
      echo "name    $2"
      echo "status  200"
      echo "content-type       application/octet-stream"
      echo "etag               \"8f14e45fceea167a5a36dedd4bea2543c8233b0f...\"" ;;
    del)
      echo "${RED}Error: delete $2: HTTP 403: object is retained and cannot be deleted yet${R}" ;;
    dashboard)
      cat dashboard.frame ;;
    *) echo "usage: dezhanctl health|put|get|stat|del|ls|metrics|dashboard|admin ..." ;;
  esac
}
export -f dezhanctl
