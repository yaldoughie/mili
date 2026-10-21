# shellcheck shell=bash
# mili :: sys.sh - OS/arch detect, deps, network facts, run wrapper

# run <cmd...> : single choke point for system-changing commands.
# MILI_DRYRUN=1 -> print instead of execute (golden tests, previews).
run() {
  if [[ "${MILI_DRYRUN:-0}" == 1 ]]; then
    printf '%s[dry]%s %s\n' "${C_GRY:-}" "${C_RST:-}" "$*" >&2
    return 0
  fi
  _log_write CMD "$*"
  "$@"
}

# run_q <cmd...> : like run but swallow stdout/stderr (status still matters)
run_q() {
  if [[ "${MILI_DRYRUN:-0}" == 1 ]]; then
    printf '%s[dry]%s %s\n' "${C_GRY:-}" "${C_RST:-}" "$*" >&2
    return 0
  fi
  _log_write CMD "$*"
  "$@" >/dev/null 2>&1
}

sys_detect_os() {
  MILI_OS=unknown; MILI_OS_VER=0; MILI_OS_NAME=unknown
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    MILI_OS="${ID:-unknown}"
    MILI_OS_VER="${VERSION_ID:-0}"
    MILI_OS_NAME="${PRETTY_NAME:-$ID}"
  fi
}

# verify supported distro; returns 1 (warn) if not
sys_os_supported() {
  case "$MILI_OS" in
    ubuntu) awk "BEGIN{exit !(${MILI_OS_VER%%.*} >= 20)}" 2>/dev/null ;;
    debian) awk "BEGIN{exit !(${MILI_OS_VER%%.*} >= 11)}" 2>/dev/null ;;
    *) return 1 ;;
  esac
}

sys_detect_arch() {
  local m; m=$(uname -m)
  case "$m" in
    x86_64|amd64)  MILI_ARCH=amd64 ;;
    aarch64|arm64) MILI_ARCH=arm64 ;;
    armv7l|armv7|armhf) MILI_ARCH=armv7 ;;
    *) MILI_ARCH="$m" ;;
  esac
}

sys_has() { command -v "$1" >/dev/null 2>&1; }

# ensure apt packages installed (idempotent, batched)
sys_apt_ensure() {
  local pkgs=("$@") missing=()
  local p
  for p in "${pkgs[@]}"; do
    dpkg -s "$p" >/dev/null 2>&1 || missing+=("$p")
  done
  [[ ${#missing[@]} -eq 0 ]] && return 0
  ui_info "installing deps: ${missing[*]}"
  run env DEBIAN_FRONTEND=noninteractive apt-get update -qq || log_warn "apt-get update failed (continuing)"
  run env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${missing[@]}" \
    || die "failed to install packages: ${missing[*]}"
}

# ---- network facts ---------------------------------------------------------
sys_default_iface() {
  ip -4 route show default 2>/dev/null | awk '/default/{print $5; exit}'
}
sys_default_gw() {
  ip -4 route show default 2>/dev/null | awk '/default/{print $3; exit}'
}
sys_gw_mac() {
  local gw ifc; gw=$(sys_default_gw); ifc=$(sys_default_iface)
  [[ -z "$gw" ]] && return 1
  ping -c1 -W1 "$gw" >/dev/null 2>&1 || true
  ip neigh show "$gw" dev "$ifc" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="lladdr") print $(i+1)}' | head -n1
}
sys_local_ip4() {
  local ifc; ifc=$(sys_default_iface)
  ip -4 addr show dev "$ifc" 2>/dev/null | awk '/inet /{sub(/\/.*/,"",$2); print $2; exit}'
}

# public IP via several resolvers (no single point of failure); cached per run
sys_public_ip4() {
  [[ -n "${MILI_PUBIP4:-}" ]] && { printf '%s' "$MILI_PUBIP4"; return 0; }
  local urls=(https://api.ipify.org https://ifconfig.me/ip https://ipv4.icanhazip.com)
  local u ip
  for u in "${urls[@]}"; do
    ip=$(curl -4 -fsS --max-time 5 "$u" 2>/dev/null | tr -d '[:space:]')
    [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && { MILI_PUBIP4="$ip"; printf '%s' "$ip"; return 0; }
  done
  ip="$(sys_local_ip4)"; MILI_PUBIP4="$ip"; printf '%s' "$ip"
}
sys_public_ip6() {
  [[ -n "${MILI_PUBIP6:-}" ]] && { printf '%s' "$MILI_PUBIP6"; return 0; }
  local urls=(https://api6.ipify.org https://ipv6.icanhazip.com)
  local u ip
  for u in "${urls[@]}"; do
    ip=$(curl -6 -fsS --max-time 5 "$u" 2>/dev/null | tr -d '[:space:]')
    [[ "$ip" == *:* ]] && { MILI_PUBIP6="$ip"; printf '%s' "$ip"; return 0; }
  done
  return 1
}

# validate an IPv4 literal
sys_is_ip4() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }
# validate hostname/domain (loose)
sys_is_host() { [[ "$1" =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$ ]]; }

# random hex / token helpers
sys_rand_hex() { local n="${1:-8}"; head -c "$((n*2))" /dev/urandom 2>/dev/null | od -An -tx1 | tr -d ' \n' | cut -c1-"$((n*2))"; }
sys_rand_token() { tr -dc 'A-Za-z0-9' </dev/urandom 2>/dev/null | head -c "${1:-16}"; }
sys_rand_port() { local lo="${1:-20000}" hi="${2:-29999}"; echo $(( lo + RANDOM % (hi-lo+1) )); }
