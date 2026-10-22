# shellcheck shell=bash
# mili :: ports.sh - port registry, conflict detection, allocators,
#                    inner-subnet / gre-key / route-table pools.
#
# ports.db line format:  name|proto|port|bind
#   proto = tcp|udp|both ; bind = 127.0.0.1 | 0.0.0.0 | <inner-ip>

MILI_PORTSDB="${MILI_PORTSDB:-$MILI_ETC/ports.db}"

# pools
MILI_PUB_LO=20000; MILI_PUB_HI=29999      # public tunnel ports (below ephemeral)
MILI_SOCKS_LO=10800; MILI_SOCKS_HI=10999  # loopback SOCKS
MILI_INT_LO=30000; MILI_INT_HI=30999      # internal/helper ports
MILI_RESERVED=(22 53 80 443 2053 2096 62789 11111)  # 443 confirm-only

ports_db_init() { [[ -f "$MILI_PORTSDB" ]] || { st_dir_init; : >"$MILI_PORTSDB" 2>/dev/null || true; }; }

# ---- observation sources ---------------------------------------------------
# live listening ports (tcp+udp), one per line
ports_live() {
  if sys_has ss; then
    ss -Hlntu 2>/dev/null | awk '{print $5}' | sed -E 's/.*:([0-9]+)$/\1/' | grep -E '^[0-9]+$' | sort -un
  elif sys_has netstat; then
    netstat -lntu 2>/dev/null | awk '{print $4}' | sed -E 's/.*:([0-9]+)$/\1/' | grep -E '^[0-9]+$' | sort -un
  fi
}

# x-ui inbound ports (read-only sqlite) + panel/sub port (read-only CLI)
ports_xui() {
  local db=/etc/x-ui/x-ui.db
  if [[ -r "$db" ]] && sys_has sqlite3; then
    sqlite3 -readonly "$db" 'select port from inbounds;' 2>/dev/null | grep -E '^[0-9]+$'
  fi
  if [[ -x /usr/local/x-ui/x-ui ]]; then
    /usr/local/x-ui/x-ui setting -show true 2>/dev/null \
      | grep -iE 'port' | grep -oE '[0-9]{2,5}' || true
  fi
}

# sshd listening port(s)
ports_sshd() {
  if sys_has sshd; then
    sshd -T 2>/dev/null | awk '/^port /{print $2}'
  else
    awk '/^[[:space:]]*Port[[:space:]]+[0-9]+/{print $2}' /etc/ssh/sshd_config 2>/dev/null
  fi
  echo 22
}

# mili-claimed ports (all tunnels, incl. stopped)
ports_claimed() {
  [[ -f "$MILI_PORTSDB" ]] || return 0
  awk -F'|' 'NF>=3 && $3 ~ /^[0-9]+$/ {print $3}' "$MILI_PORTSDB" | sort -un
}

# claimed ports owned by a specific tunnel
ports_claimed_by() {
  [[ -f "$MILI_PORTSDB" ]] || return 0
  awk -F'|' -v n="$1" '$1==n{print}' "$MILI_PORTSDB"
}

# ---- conflict test ---------------------------------------------------------
# ports_in_use <port> [exclude-tunnel] -> 0 if used/unavailable
ports_in_use() {
  local port="$1" excl="${2:-}"
  local p
  for p in "${MILI_RESERVED[@]}"; do [[ "$p" == "$port" ]] && return 0; done
  ports_live   | grep -qx "$port" && return 0
  ports_xui    | grep -qx "$port" && return 0
  ports_sshd   | grep -qx "$port" && return 0
  # claimed by another tunnel?
  if [[ -f "$MILI_PORTSDB" ]]; then
    awk -F'|' -v pt="$port" -v ex="$excl" '$3==pt && $1!=ex{found=1} END{exit !found}' "$MILI_PORTSDB" && return 0
  fi
  return 1
}

# allocate a free port in a range:  ports_alloc <lo> <hi> [exclude]
ports_alloc() {
  local lo="$1" hi="$2" excl="${3:-}" p
  for (( p=lo; p<=hi; p++ )); do
    ports_in_use "$p" "$excl" || { printf '%s' "$p"; return 0; }
  done
  return 1
}
ports_alloc_public()   { ports_alloc "$MILI_PUB_LO"   "$MILI_PUB_HI"   "$1"; }
ports_alloc_socks()    { ports_alloc "$MILI_SOCKS_LO" "$MILI_SOCKS_HI" "$1"; }
ports_alloc_internal() { ports_alloc "$MILI_INT_LO"   "$MILI_INT_HI"   "$1"; }

# ---- live listener helpers (wizards) ----------------------------------------
# is anything listening on tcp <port>?
ports_listening() { ss -Hltn 2>/dev/null | awk '{print $4}' | grep -qE ":$1\$"; }

# who listens on tcp <port>? prints the process name ('?' if hidden); rc 1 = free
ports_who() {
  local line who
  line="$(ss -Hltnp 2>/dev/null | awk -v p="$1" '{n = split($4, a, ":"); if (a[n] == p) { print; exit }}')"
  [[ -z "$line" ]] && return 1
  who="$(printf '%s' "$line" | grep -oE 'users:\(\("[^"]+' | head -n1 | sed 's/^users:(("//')"
  printf '%s' "${who:-?}"
}

# is <port> unavailable? prints the reason (process / x-ui / another mili tunnel).
# Listeners whose process name starts with <ignore-prefix> don't count (a core
# re-binding its own port). MILI_RESERVED is NOT consulted (callers decide).
ports_busy_reason() {  # <port> [exclude-tunnel] [ignore-prefix]
  local port="$1" excl="${2:-}" ign="${3:-}" who
  if who="$(ports_who "$port")"; then
    if [[ -z "$ign" || "$who" != "$ign"* ]]; then printf '%s' "$who"; return 0; fi
  fi
  if ports_xui 2>/dev/null | grep -qx "$port"; then printf 'x-ui'; return 0; fi
  if [[ -f "$MILI_PORTSDB" ]] && awk -F'|' -v pt="$port" -v ex="$excl" '$3==pt && $1!=ex {f=1} END {exit !f}' "$MILI_PORTSDB"; then
    printf 'another mili tunnel'; return 0
  fi
  return 1
}

# first free port in [lo, hi] that is not in <taken...>
ports_free_in() {  # <lo> <hi> [taken...]
  local lo="$1" hi="$2" p t skip; shift 2
  for (( p = lo; p <= hi; p++ )); do
    skip=0; for t in "$@"; do [[ "$t" == "$p" ]] && { skip=1; break; }; done
    (( skip )) && continue
    ports_in_use "$p" && continue
    printf '%s' "$p"; return 0
  done
  return 1
}
ports_free_public() { ports_free_in "$MILI_PUB_LO" "$MILI_PUB_HI" "$@"; }

# ---- claim / release -------------------------------------------------------
ports_claim() {   # <name> <proto> <port> <bind>
  ports_db_init
  local name="$1" proto="$2" port="$3" bind="${4:-0.0.0.0}"
  ports_release_one "$name" "$port"
  printf '%s|%s|%s|%s\n' "$name" "$proto" "$port" "$bind" >>"$MILI_PORTSDB"
  ports_sync_reserved
}
ports_release() {  # <name> : drop all claims for a tunnel
  [[ -f "$MILI_PORTSDB" ]] || return 0
  local name="$1" tmp; tmp="$(mktemp)"
  awk -F'|' -v n="$name" '$1!=n' "$MILI_PORTSDB" >"$tmp" && mv -f "$tmp" "$MILI_PORTSDB"
  ports_sync_reserved
}
ports_release_one() {  # <name> <port>
  [[ -f "$MILI_PORTSDB" ]] || return 0
  local name="$1" port="$2" tmp; tmp="$(mktemp)"
  awk -F'|' -v n="$name" -v pt="$port" '!($1==n && $3==pt)' "$MILI_PORTSDB" >"$tmp" && mv -f "$tmp" "$MILI_PORTSDB"
}

# write reserved-ports sysctl from all public/internal claims (not loopback)
ports_sync_reserved() {
  [[ -f "$MILI_PORTSDB" ]] || return 0
  local list
  list=$(awk -F'|' '$4!="127.0.0.1" && $3 ~ /^[0-9]+$/ {print $3}' "$MILI_PORTSDB" | sort -un | paste -sd, -)
  # keep BackPack's reservations too: one kernel list, the last sysctl file wins
  list="$(sysctl_ports_union "$list" "$(sysctl_backpack_reserved)")"
  sysctl_set_reserved_ports "$list"
}

# ---- audit: later clashes (user added x-ui inbound on a mili port, etc.) ---
# prints conflict lines; returns 1 if any found
ports_audit() {
  ports_db_init
  local rc=0 line name proto port bind
  local live xui
  live=$(ports_live); xui=$(ports_xui)
  while IFS='|' read -r name proto port bind; do
    [[ "$port" =~ ^[0-9]+$ ]] || continue
    # is a NON-mili listener occupying our public port?
    if [[ "$bind" != "127.0.0.1" ]] && grep -qx "$port" <<<"$xui"; then
      printf '%sCONFLICT%s port %s claimed by tunnel %s also used by x-ui inbound\n' \
        "${C_RED:-}" "${C_RST:-}" "$port" "$name"
      rc=1
    fi
  done < <(cat "$MILI_PORTSDB" 2>/dev/null)
  return $rc
}

# ---- inner subnet / gre key / route table / iface pools --------------------
# inner /30 blocks from 10.77.N.0/30 ; returns next free "10.77.N" base
pool_inner_subnet() {
  local used n base
  used=$(awk -F'|' '/^INNER/{print $2}' "$MILI_PORTSDB" 2>/dev/null)
  for (( n=0; n<=255; n++ )); do
    base="10.77.$n"
    grep -qx "$n" <<<"$used" && continue
    # also skip if that subnet is already routed on the host
    if ! ip route 2>/dev/null | grep -q "$base\." && ! ip addr 2>/dev/null | grep -q "$base\."; then
      printf '%s' "$n"; return 0
    fi
  done
  return 1
}
pool_inner_claim()  { ports_db_init; printf 'INNER|%s|%s\n' "$1" "$2" >>"$MILI_PORTSDB"; }   # <N> <name>
pool_inner_release(){ local tmp; tmp="$(mktemp)"; awk -F'|' -v n="$1" '!(/^INNER/ && $3==n)' "$MILI_PORTSDB" >"$tmp" && mv -f "$tmp" "$MILI_PORTSDB"; }

# unique gre key (uint32)
pool_gre_key() {
  local used k
  used=$(grep -E '^GREKEY' "$MILI_PORTSDB" 2>/dev/null | awk -F'|' '{print $2}')
  for k in $(seq 1 65535); do grep -qx "$k" <<<"$used" || { printf '%s' "$k"; return 0; }; done
}
# unique route table id in 7700..7799
pool_table_id() {
  local used t
  used=$(grep -E '^RTABLE' "$MILI_PORTSDB" 2>/dev/null | awk -F'|' '{print $2}')
  for (( t=7700; t<=7799; t++ )); do grep -qx "$t" <<<"$used" || { printf '%s' "$t"; return 0; }; done
}
pool_meta_claim()  { ports_db_init; printf '%s|%s|%s\n' "$1" "$2" "$3" >>"$MILI_PORTSDB"; }  # <KIND> <val> <name>
pool_meta_release(){ local tmp; tmp="$(mktemp)"; awk -F'|' -v n="$1" '!($3==n && ($1=="GREKEY"||$1=="RTABLE"||$1=="INNER"))' "$MILI_PORTSDB" >"$tmp" && mv -f "$tmp" "$MILI_PORTSDB"; }
