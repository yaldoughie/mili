# shellcheck shell=bash
# mili :: log.sh - logging, error trap, die

MILI_LOGDIR="${MILI_LOGDIR:-/var/log/mili}"
MILI_LOGFILE="${MILI_LOGFILE:-$MILI_LOGDIR/mili.log}"

_log_write() {
  local lvl="$1"; shift
  local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')
  # best-effort; never fail the caller because logging failed
  if [[ -d "$MILI_LOGDIR" ]] || mkdir -p "$MILI_LOGDIR" 2>/dev/null; then
    printf '%s [%s] %s\n' "$ts" "$lvl" "$*" >>"$MILI_LOGFILE" 2>/dev/null || true
  fi
}

log()  { _log_write INFO  "$*"; }
log_warn() { _log_write WARN "$*"; ui_warn "$*"; }
log_err()  { _log_write ERROR "$*"; ui_err  "$*" >&2; }
log_ok()   { _log_write INFO  "$*"; ui_ok   "$*"; }
log_info() { _log_write INFO  "$*"; ui_info "$*"; }

# die <msg> [code]
die() {
  local msg="$1" code="${2:-1}"
  _log_write FATAL "$msg"
  ui_err "$msg" >&2
  exit "$code"
}

# require_root - abort unless EUID 0
require_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "mili must run as root (use sudo)." 1
}

# ERR trap installer (opt-in; interactive menus do NOT use set -e)
mili_trap_on() {
  set -o pipefail
  trap '_log_write ERROR "unexpected error at ${BASH_SOURCE[0]:-?}:${LINENO} (rc=$?) cmd: ${BASH_COMMAND}"' ERR
}
