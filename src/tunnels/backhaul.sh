# shellcheck shell=bash
# mili :: tunnels/backhaul.sh - Musixal/Backhaul v0.7.2 (open-source core).
#
# NATIVE flow (no mili pairing code): mili asks the same questions as Musixal's
# own Backhaul installer, in the same order, every one with an Enter default.
#   IRAN    = [server] - listens on the tunnel port            (set up first)
#   FOREIGN = [client] - "Kharej", dials Iran with the values Iran shows:
#             Iran IP, tunnel port, transport, security token
#
# Usage on top of Backhaul (mili addition, asked last):
#   socks   - Iran 127.0.0.1:<iran_socks> -> foreign 127.0.0.1:<foreign_socks>,
#             where mili runs a loopback-only gost SOCKS5 (no auth, nothing to
#             carry). 3x-ui on Iran adds 127.0.0.1:<iran_socks> as an outbound.
#   forward - Musixal's ports list (Iran public ports -> foreign targets).
#
# skip_optz=true ALWAYS: Backhaul's optimizer widens ip_local_port_range to
# 1024-65535 and would collide with xray / x-ui ports.
# config: /etc/mili/engines/backhaul/<name>.toml

t_register backhaul
feature "tunnel.backhaul" free

MILI_BH_ETC="$MILI_ETC/engines/backhaul"
BH_TRANSPORTS=(tcp tcpmux ws wss wsmux wssmux udp)

t_backhaul_meta() {
  echo "id=backhaul"
  echo "title=Backhaul  (reverse mux)"
  echo "tier=free"
  echo "layer=fwd"
  echo "roles=iran foreign"
  echo "primary=iran"
  echo "pairing=native"
  echo "handoff_label=Show values for the foreign server"
  echo "first_hint=Set up the IRAN server first (it listens). Then on the FOREIGN server pick Backhaul → Foreign and type the values Iran shows."
  echo "cores=backhaul"
}

t_backhaul_unit() { echo "mili-backhaul@$1.service"; }

# ============================================================================
# pure helpers (unit-tested)
# ============================================================================
_bh_is_mux() { [[ "$1" == tcpmux || "$1" == wsmux || "$1" == wssmux ]]; }
_bh_is_ws()  { [[ "$1" == ws || "$1" == wss || "$1" == wsmux || "$1" == wssmux ]]; }
_bh_is_tls() { [[ "$1" == wss || "$1" == wssmux ]]; }
_bh_valid_transport() { local t; for t in "${BH_TRANSPORTS[@]}"; do [[ "$t" == "$1" ]] && return 0; done; return 1; }

# default SOCKS port on the foreign side, derived from the tunnel port so BOTH
# servers suggest the same number (Enter on both sides just works)
_bh_socks_default() { printf '%s' $(( 10800 + ${1:-0} % 200 )); }

# host:port, IPv6 bracketed
_bh_hostport() {  # <host> <port>
  local h="${1#[}"; h="${h%]}"
  if [[ "$h" == *:* ]]; then printf '[%s]:%s' "$h" "$2"; else printf '%s:%s' "$h" "$2"; fi
}

# a security token must be a plain TOML string (no quotes / backslashes / spaces)
_bh_valid_token() { local re='^[^"\\[:space:]]+$'; [[ -n "$1" && "$1" =~ $re ]]; }

# one item of Musixal's ports list, in the forms the v0.7.2 core accepts:
#   443   443-600   4000=5000   443-600=5201   443=1.1.1.1:5201
#   443-600=1.1.1.1:5201   127.0.0.2:443=5201   127.0.0.2:443=1.1.1.1:5201
_bh_fwd_valid() {
  local it="$1" ip='[0-9]{1,3}(\.[0-9]{1,3}){3}' host='[A-Za-z0-9.-]+'
  local local_re="^([0-9]+(-[0-9]+)?|${ip}:[0-9]+)\$"
  local remote_re="^([0-9]+|(${host}):[0-9]+)\$"
  local l r
  if [[ "$it" == *=* ]]; then
    l="${it%%=*}"; r="${it#*=}"
    [[ "$l" =~ $local_re && "$r" =~ $remote_re ]] || return 1
  else
    [[ "$it" =~ ^[0-9]+(-[0-9]+)?$ ]] || return 1
    l="$it"
  fi
  # port bounds (and a range must go up)
  local lp="${l##*:}" a b
  a="${lp%%-*}"; b="${lp##*-}"
  (( a >= 1 && a <= 65535 && b >= 1 && b <= 65535 && b >= a )) || return 1
  return 0
}

# local side of an item -> "<bind> <port-or-range>"   (bind 0.0.0.0 unless given)
_bh_fwd_local() {
  local l="${1%%=*}"
  if [[ "$l" == *:* ]]; then printf '%s %s' "${l%:*}" "${l##*:}"; else printf '0.0.0.0 %s' "$l"; fi
}

# items of a comma list, one per line
_bh_fwd_items() {
  local it; local -a _bhi=()
  IFS=',' read -ra _bhi <<<"${1// /}"
  for it in "${_bhi[@]}"; do [[ -n "$it" ]] && printf '%s\n' "$it"; done
  return 0
}

# "ports = [ ... ]" body
_bh_ports_block() {
  if [[ "${ST[mode]}" == socks ]]; then
    printf '    "127.0.0.1:%s=%s",\n' "${ST[iran_socks]}" "${ST[foreign_socks]}"
  else
    local it; while read -r it; do printf '    "%s",\n' "$it"; done < <(_bh_fwd_items "${ST[fwd]:-}")
  fi
}

# TLS cert/key for wss/wssmux: a real cert for the domain if one exists
# (3x-ui's /root/cert/<domain>/ or certbot's live dir), else mili's self-signed
_bh_tls_paths() {  # <name> -> "cert key"
  local d="${ST[domain]:-}"
  if [[ -n "$d" && -f "/root/cert/$d/fullchain.pem" && -f "/root/cert/$d/privkey.pem" ]]; then
    printf '%s %s' "/root/cert/$d/fullchain.pem" "/root/cert/$d/privkey.pem"
  elif [[ -n "$d" && -f "/etc/letsencrypt/live/$d/fullchain.pem" ]]; then
    printf '%s %s' "/etc/letsencrypt/live/$d/fullchain.pem" "/etc/letsencrypt/live/$d/privkey.pem"
  else
    printf '%s %s' "$MILI_ETC/pki/$1/cert.pem" "$MILI_ETC/pki/$1/key.pem"
  fi
}

# the TOML (Musixal installer layout). Unset keys fall back to the core's own
# defaults (e.g. mux_version 1), so tunnels created before this flow render as before.
_bh_toml() {  # <name>
  local name="$1" t="${ST[transport]:-tcp}" nd="${ST[nodelay]:-true}"
  [[ "$t" == udp ]] && nd=false
  local log="$MILI_LOGDIR/backhaul-$name.json"
  if [[ "${ST[role]}" == iran ]]; then
    printf '# mili Backhaul server (Iran) - tunnel %s\n' "$name"
    printf '[server]\n'
    printf 'bind_addr = ":%s"\n' "${ST[tunnel_port]}"
    printf 'transport = "%s"\n' "$t"
    printf 'accept_udp = %s\n' "${ST[accept_udp]:-false}"
    printf 'token = "%s"\n' "${ST[token]}"
    printf 'keepalive_period = %s\n' "${ST[keepalive]:-75}"
    printf 'nodelay = %s\n' "$nd"
    printf 'channel_size = %s\n' "${ST[channel_size]:-2048}"
    printf 'heartbeat = %s\n' "${ST[heartbeat]:-40}"
    printf 'mux_con = %s\n' "${ST[mux_con]:-8}"
    printf 'mux_version = %s\n' "${ST[mux_version]:-1}"
    printf 'mux_framesize = 32768\n'
    printf 'mux_recievebuffer = 4194304\n'
    printf 'mux_streambuffer = 2000000\n'
    printf 'sniffer = %s\n' "${ST[sniffer]:-false}"
    printf 'web_port = %s\n' "${ST[web_port]:-0}"
    printf 'sniffer_log = "%s"\n' "$log"
    printf 'log_level = "info"\n'
    printf 'proxy_protocol = %s\n' "${ST[proxy_protocol]:-false}"
    printf 'skip_optz = true\n'
    if _bh_is_tls "$t"; then
      local crt key; read -r crt key <<<"$(_bh_tls_paths "$name")"
      printf 'tls_cert = "%s"\n' "$crt"
      printf 'tls_key = "%s"\n' "$key"
    fi
    printf '\nports = [\n'
    _bh_ports_block
    printf ']\n'
  else
    printf '# mili Backhaul client (Foreign) - tunnel %s\n' "$name"
    printf '[client]\n'
    printf 'remote_addr = "%s"\n' "$(_bh_hostport "${ST[iran_ip]}" "${ST[tunnel_port]}")"
    if _bh_is_ws "$t" && [[ -n "${ST[edge_ip]:-}" ]]; then printf 'edge_ip = "%s"\n' "${ST[edge_ip]}"; fi
    printf 'transport = "%s"\n' "$t"
    printf 'token = "%s"\n' "${ST[token]}"
    printf 'connection_pool = %s\n' "${ST[conn_pool]:-8}"
    printf 'aggressive_pool = false\n'
    printf 'keepalive_period = %s\n' "${ST[keepalive]:-75}"
    printf 'nodelay = %s\n' "$nd"
    printf 'retry_interval = 3\n'
    printf 'dial_timeout = 10\n'
    printf 'mux_version = %s\n' "${ST[mux_version]:-1}"
    printf 'mux_framesize = 32768\n'
    printf 'mux_recievebuffer = 4194304\n'
    printf 'mux_streambuffer = 2000000\n'
    printf 'sniffer = %s\n' "${ST[sniffer]:-false}"
    printf 'web_port = %s\n' "${ST[web_port]:-0}"
    printf 'sniffer_log = "%s"\n' "$log"
    printf 'log_level = "info"\n'
    printf 'skip_optz = true\n'
  fi
}

# ============================================================================
# wizard (Musixal's question order)
# ============================================================================
t_backhaul_wizard() {  # <role> [level]
  if [[ "$1" == iran ]]; then _bh_wizard_iran; else _bh_wizard_foreign; fi
}

_bh_reserved() { local r; for r in "${MILI_RESERVED[@]}"; do [[ "$r" == "$1" ]] && return 0; done; return 1; }

_bh_transport_hint() {
  case "$1" in
    tcp)    printf 'plain TCP · fastest' ;;
    tcpmux) printf 'TCP + multiplexing' ;;
    ws)     printf 'WebSocket (CDN-able)' ;;
    wss)    printf 'WebSocket over TLS' ;;
    wsmux)  printf 'WebSocket + multiplexing' ;;
    wssmux) printf 'WebSocket TLS + multiplexing' ;;
    udp)    printf 'UDP (carries UDP traffic only)' ;;
  esac
}

_bh_ask_transport() {
  local -a labels=(); local i pre=0
  for i in "${!BH_TRANSPORTS[@]}"; do
    [[ "${BH_TRANSPORTS[$i]}" == "${ST[transport]:-tcp}" ]] && pre=$i
    labels+=("${BH_TRANSPORTS[$i]}"$'\t'"$(_bh_transport_hint "${BH_TRANSPORTS[$i]}")")
  done
  echo; ui_info "Transport type (must be the same on both servers):"
  ui_pick "$pre" "${labels[@]}"
  ST[transport]="${BH_TRANSPORTS[$((SEL-1))]}"
}

# ask a port for something mili will listen on; re-ask while it's taken.
# <current> = this tunnel's existing value (its own listener doesn't count)
_bh_ask_free_port() {  # <prompt> <default> <current> <min> [zero]
  local p who own
  while :; do
    p="$(ui_ask_int "$1" "$2" "$4" 65535)"
    [[ "${5:-}" == zero && "$p" == 0 ]] && { printf '0'; return 0; }
    own=0; [[ -n "$3" && "$p" == "$3" ]] && own=1
    if who="$(ports_busy_reason "$p" "${ST[name]}")"; then
      # re-using this tunnel's own port (Edit): its own backhaul/gost listener is fine
      if ! (( own )) || [[ "$who" != backhaul* && "$who" != gost* ]]; then
        ui_err "port $p is in use ($who)" >&2; continue
      fi
    fi
    printf '%s' "$p"; return 0
  done
}

_bh_ask_token() {  # <default>
  local v
  while :; do
    v="$(ui_ask '[-] Security token' "$1")"
    _bh_valid_token "$v" && { printf '%s' "$v"; return 0; }
    ui_err "enter the token (no spaces, quotes or backslashes)" >&2
  done
}

_bh_ports_help() {
  echo; ui_info "Supported port formats:"
  ui_note "443                   listen on 443, forward to the foreign server's 443"
  ui_note "443-600               listen on every port 443..600 (same port on foreign)"
  ui_note "4000=5000             listen on 4000, forward to foreign port 5000"
  ui_note "443-600=5201          listen on 443..600, forward all to foreign 5201"
  ui_note "443=1.1.1.1:5201      listen on 443, the foreign side dials 1.1.1.1:5201"
  ui_note "127.0.0.2:443=5201    bind a specific local IP"
}

# validate a whole ports list: formats + Iran-side listen ports free
_bh_fwd_check() {  # <list>
  local it bind lp a b p who n=0 own
  while read -r it; do
    ((n++))
    _bh_fwd_valid "$it" || { ui_err "invalid port mapping: $it"; return 1; }
    read -r bind lp <<<"$(_bh_fwd_local "$it")"
    a="${lp%%-*}"; b="${lp##*-}"
    own=0; [[ ",${ST[fwd]:-}," == *",$it,"* ]] && own=1     # unchanged item on Edit
    for (( p = a; p <= b; p++ )); do
      if [[ "$p" == "${ST[tunnel_port]}" || "$p" == "${ST[web_port]:-0}" ]]; then
        ui_err "port $p is the tunnel/web port - pick other listen ports"; return 1
      fi
      (( b - a > 200 )) && continue      # very wide ranges: not probed port by port
      if who="$(ports_busy_reason "$p" "${ST[name]}")" && ! { (( own )) && [[ "$who" == backhaul* ]]; }; then
        ui_err "listen port $p is in use ($who)"; return 1
      fi
    done
  done < <(_bh_fwd_items "$1")
  (( n > 0 )) || { ui_err "enter at least one port"; return 1; }
  return 0
}

_bh_ask_usage() {  # sets ST[mode]
  if [[ "${ST[transport]}" == udp ]]; then
    ST[mode]=forward
    ui_note "udp transport carries UDP only -> port forward mode (SOCKS needs a TCP transport)."
    return 0
  fi
  local pre=0; [[ "${ST[mode]:-socks}" == forward ]] && pre=1
  echo; ui_info "How will this tunnel be used? (same choice on both servers)"
  ui_pick "$pre" $'SOCKS outbound for 3x-ui\trecommended · x-ui on Iran → SOCKS → foreign exit' \
                 $'Port forward\tBackhaul ports list · Iran ports → foreign'
  if (( SEL == 2 )); then ST[mode]=forward; else ST[mode]=socks; fi
}

_bh_wizard_iran() {
  ST[my_ip]="$(sys_public_ip4)"
  ui_note "This IRAN server listens; the foreign server will dial ${ST[my_ip]}."
  echo
  # [*] Tunnel port
  local p
  while :; do
    p="$(_bh_ask_free_port '[*] Tunnel port' "${ST[tunnel_port]:-$(ports_alloc_public "${ST[name]}")}" "${ST[tunnel_port]:-}" 23)"
    if _bh_reserved "$p" && [[ "$p" != "${ST[tunnel_port]:-}" ]]; then
      ui_confirm "port $p is normally kept for x-ui / the system. Use it anyway?" n || continue
    fi
    break
  done
  ST[tunnel_port]="$p"

  # [*] Transport (+ TLS certificate for wss/wssmux)
  _bh_ask_transport
  local t="${ST[transport]}"
  if _bh_is_tls "$t"; then
    local d; d="$(ui_ask '[-] TLS certificate domain (blank = self-signed, - = clear)' "${ST[domain]:-}")"
    [[ "$d" == - ]] && d=''
    ST[domain]="$d"
  fi

  # [-] Accept UDP (tcp only)
  if [[ "$t" == tcp ]]; then
    ST[accept_udp]="$(ui_ask_bool '[-] Accept UDP connections over TCP transport' "${ST[accept_udp]:-false}")"
  else ST[accept_udp]=false; fi
  # [-] Channel size
  ST[channel_size]="$(ui_ask_int '[-] Channel size' "${ST[channel_size]:-2048}" 64 8192)"
  # [-] TCP_NODELAY (not for udp)
  if [[ "$t" == udp ]]; then ST[nodelay]=false
  else ST[nodelay]="$(ui_ask_bool '[-] Enable TCP_NODELAY' "${ST[nodelay]:-true}")"; fi
  # [-] Heartbeat
  ST[heartbeat]="$(ui_ask_int '[-] Heartbeat (in seconds)' "${ST[heartbeat]:-40}" 1 240)"
  # [-] Security token (mili default: random, never Musixal's 'your_token')
  ST[token]="$(_bh_ask_token "${ST[token]:-$(sys_rand_token 24)}")"
  # [-] Mux concurrency + version (mux transports)
  if _bh_is_mux "$t"; then
    ST[mux_con]="$(ui_ask_int '[-] Mux concurrency' "${ST[mux_con]:-8}" 1 1000)"
    ST[mux_version]="$(ui_ask_int '[-] Mux version (1 or 2)' "${ST[mux_version]:-2}" 1 2)"
  else
    ST[mux_con]="${ST[mux_con]:-8}"; ST[mux_version]="${ST[mux_version]:-2}"
  fi
  # [-] Sniffer + web port
  ST[sniffer]="$(ui_ask_bool '[-] Enable sniffer' "${ST[sniffer]:-false}")"
  ST[web_port]="$(_bh_ask_free_port '[-] Web port (0 = disabled)' "${ST[web_port]:-0}" "${ST[web_port]:-}" 0 zero)"
  # [-] Proxy protocol (not ws/udp)
  if [[ "$t" == ws || "$t" == udp ]]; then ST[proxy_protocol]=false
  else ST[proxy_protocol]="$(ui_ask_bool '[-] Enable proxy protocol' "${ST[proxy_protocol]:-false}")"; fi
  ST[keepalive]="${ST[keepalive]:-75}"

  # [*] usage (mili) -> SOCKS ports, or Musixal's ports list
  _bh_ask_usage
  if [[ "${ST[mode]}" == socks ]]; then
    while :; do
      p="$(_bh_ask_free_port '[*] SOCKS5 port on THIS server (3x-ui outbound → 127.0.0.1:port)' \
            "${ST[iran_socks]:-$(ports_alloc_socks "${ST[name]}")}" "${ST[iran_socks]:-}" 1)"
      if [[ "$p" == "${ST[tunnel_port]}" || "$p" == "${ST[web_port]}" ]]; then ui_err "must differ from the tunnel/web port"; continue; fi
      break
    done
    ST[iran_socks]="$p"
    ST[foreign_socks]="$(ui_ask_port '[*] SOCKS5 port on the FOREIGN server' "${ST[foreign_socks]:-$(_bh_socks_default "${ST[tunnel_port]}")}")"
    ST[fwd]=''
  else
    _bh_ports_help
    local v
    while :; do
      v="$(ui_ask '[*] Enter your ports (comma separated)' "${ST[fwd]:-}")"; v="${v// /}"
      _bh_fwd_check "$v" && break
    done
    ST[fwd]="$v"
  fi
  return 0
}

_bh_wizard_foreign() {
  local v
  # [*] IRAN server IP
  while :; do
    v="$(ui_ask '[*] IRAN server IP address [IPv4/IPv6]' "${ST[iran_ip]:-}")"; v="${v// /}"; v="${v#[}"; v="${v%]}"
    if sys_is_ip4 "$v" || [[ "$v" == *:* && "$v" =~ ^[0-9A-Fa-f:.]+$ ]] || { [[ "$v" == *.* ]] && sys_is_host "$v"; }; then break; fi
    ui_err "enter the Iran server's IP (or domain)"
  done
  ST[iran_ip]="$v"
  # [*] Tunnel port
  ST[tunnel_port]="$(ui_ask_int '[*] Tunnel port (as shown on Iran)' "${ST[tunnel_port]:-}" 23 65535)"
  # [*] Transport
  _bh_ask_transport
  local t="${ST[transport]}"
  # [-] Edge IP (websocket transports, CDN)
  if _bh_is_ws "$t"; then
    v="$(ui_ask '[-] Edge IP/Domain (optional, blank = none, - = clear)' "${ST[edge_ip]:-}")"
    [[ "$v" == - ]] && v=''
    ST[edge_ip]="$v"
  else ST[edge_ip]=''; fi
  # [-] Security token (must match Iran)
  ST[token]="$(_bh_ask_token "${ST[token]:-}")"
  # [-] TCP_NODELAY
  if [[ "$t" == udp ]]; then ST[nodelay]=false
  else ST[nodelay]="$(ui_ask_bool '[-] Enable TCP_NODELAY' "${ST[nodelay]:-true}")"; fi
  # [-] Connection pool
  ST[conn_pool]="$(ui_ask_int '[-] Connection pool' "${ST[conn_pool]:-8}" 1 1024)"
  # [-] Mux version
  if _bh_is_mux "$t"; then
    ST[mux_version]="$(ui_ask_int '[-] Mux version (1 or 2)' "${ST[mux_version]:-2}" 1 2)"
  else ST[mux_version]="${ST[mux_version]:-2}"; fi
  # [-] Sniffer + web port
  ST[sniffer]="$(ui_ask_bool '[-] Enable sniffer' "${ST[sniffer]:-false}")"
  ST[web_port]="$(_bh_ask_free_port '[-] Web port (0 = disabled)' "${ST[web_port]:-0}" "${ST[web_port]:-}" 0 zero)"
  ST[keepalive]="${ST[keepalive]:-75}"

  # [*] usage (mili): the SOCKS helper lives here, on the foreign side
  _bh_ask_usage
  if [[ "${ST[mode]}" == socks ]]; then
    ST[foreign_socks]="$(_bh_ask_free_port '[*] SOCKS5 port (must match the Iran side)' \
          "${ST[foreign_socks]:-$(_bh_socks_default "${ST[tunnel_port]}")}" "${ST[foreign_socks]:-}" 1)"
  fi
  return 0
}

t_backhaul_summary() {
  local t="${ST[transport]}" x=''
  _bh_is_mux "$t" && x=" · mux ${ST[mux_con]:-8} v${ST[mux_version]}"
  if [[ "${ST[role]}" == iran ]]; then
    ui_kv "Role" "Iran · server (listens)"
    ui_kv "Tunnel" ":${ST[tunnel_port]} · $t$x$(_bh_is_tls "$t" && echo " · TLS ${ST[domain]:-self-signed}")"
    ui_kv "Security token" "${ST[token]}"
    ui_kv "Tuning" "nodelay ${ST[nodelay]} · heartbeat ${ST[heartbeat]}s · channel ${ST[channel_size]}"
    ui_kv "Options" "accept_udp ${ST[accept_udp]} · proxy_protocol ${ST[proxy_protocol]} · sniffer ${ST[sniffer]} · web ${ST[web_port]}"
  else
    ui_kv "Role" "Foreign · client (dials Iran)"
    ui_kv "Dials" "$(_bh_hostport "${ST[iran_ip]}" "${ST[tunnel_port]}") · $t$x"
    [[ -n "${ST[edge_ip]:-}" ]] && ui_kv "Edge" "${ST[edge_ip]}"
    ui_kv "Security token" "${ST[token]}"
    ui_kv "Tuning" "nodelay ${ST[nodelay]} · pool ${ST[conn_pool]} · sniffer ${ST[sniffer]} · web ${ST[web_port]}"
  fi
  if [[ "${ST[mode]}" == socks ]]; then
    if [[ "${ST[role]}" == iran ]]; then ui_kv "Usage" "SOCKS · 3x-ui → 127.0.0.1:${ST[iran_socks]} → foreign :${ST[foreign_socks]}"
    else ui_kv "Usage" "SOCKS · exit SOCKS5 on 127.0.0.1:${ST[foreign_socks]}"; fi
  else
    ui_kv "Usage" "port forward${ST[fwd]:+ · ${ST[fwd]}}"
  fi
  return 0
}

# ============================================================================
# render / firewall / ports
# ============================================================================
_bh_tls_ensure() {  # <name>  (self-signed only when no real cert is used)
  local crt key; read -r crt key <<<"$(_bh_tls_paths "$1")"
  [[ "$crt" == "$MILI_ETC/pki/$1/"* && ! -f "$crt" ]] || return 0
  mkdir -p "$MILI_ETC/pki/$1"
  openssl req -x509 -newkey rsa:2048 -keyout "$key" -out "$crt" -days 3650 -nodes \
    -subj "/CN=${ST[domain]:-mili.local}" >/dev/null 2>&1 || ui_warn "could not create a self-signed certificate (openssl)"
  chmod 600 "$key" 2>/dev/null || true
}

t_backhaul_render() {  # <name>
  st_load "$1"; local name="$1" f="$MILI_BH_ETC/$1.toml"
  if [[ "${MILI_DRYRUN:-0}" == 1 ]]; then ui_info "[dry] would write $f:"; _bh_toml "$name"; return 0; fi
  mkdir -p "$MILI_BH_ETC" "$MILI_LOGDIR" 2>/dev/null || true
  if [[ "${ST[role]}" == iran ]] && _bh_is_tls "${ST[transport]}"; then _bh_tls_ensure "$name"; fi
  ( umask 077; _bh_toml "$name" >"$f" )
}

# protocols the Iran-side forward listeners use
_bh_fwd_protos() {
  if [[ "${ST[transport]}" == udp ]]; then echo udp
  elif [[ "${ST[accept_udp]:-false}" == true ]]; then echo "tcp udp"
  else echo tcp; fi
}

t_backhaul_fw_apply() {  # <name>
  st_load "$1"; local name="$1" it bind lp pr
  if [[ "${ST[role]}" == iran ]]; then
    fw_allow "$name" tcp "${ST[tunnel_port]}"; fw_ufw_mirror "$name" tcp "${ST[tunnel_port]}"
    if [[ "${ST[transport]}" == udp ]]; then
      fw_allow "$name" udp "${ST[tunnel_port]}"; fw_ufw_mirror "$name" udp "${ST[tunnel_port]}"
    fi
    if [[ "${ST[mode]}" == forward ]]; then
      while read -r it; do
        read -r bind lp <<<"$(_bh_fwd_local "$it")"
        [[ "$bind" == 127.* ]] && continue
        for pr in $(_bh_fwd_protos); do
          fw_allow "$name" "$pr" "$lp"; fw_ufw_mirror "$name" "$pr" "${lp//-/:}"
        done
      done < <(_bh_fwd_items "${ST[fwd]:-}")
    fi
  fi
  if [[ "${ST[web_port]:-0}" != 0 ]]; then
    fw_allow "$name" tcp "${ST[web_port]}"; fw_ufw_mirror "$name" tcp "${ST[web_port]}"
  fi
  return 0
}

_bh_claim() {  # <name>
  local name="$1" it bind lp a b p pr=tcp
  ports_release "$name"
  if [[ "${ST[role]}" == iran ]]; then
    [[ "${ST[transport]}" == udp ]] && pr=both
    ports_claim "$name" "$pr" "${ST[tunnel_port]}" 0.0.0.0
    if [[ "${ST[mode]}" == socks ]]; then
      ports_claim "$name" tcp "${ST[iran_socks]}" 127.0.0.1
    else
      while read -r it; do
        read -r bind lp <<<"$(_bh_fwd_local "$it")"
        a="${lp%%-*}"; b="${lp##*-}"
        if (( b - a > 100 )); then ui_warn "range $lp: not registered port-by-port (too wide)"; continue; fi
        for (( p = a; p <= b; p++ )); do ports_claim "$name" tcp "$p" "$bind"; done
      done < <(_bh_fwd_items "${ST[fwd]:-}")
    fi
  elif [[ "${ST[mode]}" == socks ]]; then
    ports_claim "$name" tcp "${ST[foreign_socks]}" 127.0.0.1
  fi
  if [[ "${ST[web_port]:-0}" != 0 ]]; then ports_claim "$name" tcp "${ST[web_port]}" 0.0.0.0; fi
  return 0
}

t_backhaul_ports() {
  st_load "$1"
  if [[ "${ST[role]}" == iran ]]; then
    echo "tcp:${ST[tunnel_port]}:0.0.0.0"
    [[ "${ST[mode]}" == socks ]] && echo "tcp:${ST[iran_socks]}:127.0.0.1"
  else
    [[ "${ST[mode]}" == socks ]] && echo "tcp:${ST[foreign_socks]}:127.0.0.1"
  fi
  return 0
}

# ============================================================================
# lifecycle
# ============================================================================
_bh_start_socks() {  # <name> (foreign, socks mode): loopback gost exit
  cores_ensure gost || { ui_err "gost core install failed"; return 1; }
  socks_render "$1" 127.0.0.1 "${ST[foreign_socks]}" "${ST[socks_user]:-}" "${ST[socks_pass]:-}"
  svc_enable "mili-socks@$1.service"
  run systemctl restart "mili-socks@$1.service"
}

t_backhaul_up() {  # <name>
  st_load "$1"; local name="$1"
  require_root
  cores_ensure backhaul || { ui_err "backhaul core install failed"; return 1; }
  t_backhaul_render "$name"
  t_backhaul_fw_apply "$name"
  _bh_claim "$name"
  svc_up "mili-backhaul@$name.service" || return 1
  if [[ "${ST[role]}" == foreign && "${ST[mode]}" == socks ]]; then _bh_start_socks "$name" || return 1; fi
  return 0
}

# create / Edit: (re)write config, RESTART (a plain start is a no-op on a running unit), verify
t_backhaul_provision() {  # <name>
  st_load "$1"; local name="$1" u="mili-backhaul@$1.service"
  require_root
  cores_ensure backhaul || { ui_err "backhaul core install failed"; return 1; }
  t_backhaul_render "$name" || return 1
  fw_remove "$name"; t_backhaul_fw_apply "$name"
  _bh_claim "$name"
  svc_enable "$u"
  run systemctl restart "$u" || { ui_err "could not start $u"; svc_logs "$u" 20; return 1; }
  if [[ "${ST[role]}" == foreign && "${ST[mode]}" == socks ]]; then
    _bh_start_socks "$name" || return 1
  else
    svc_down "mili-socks@$name.service" >/dev/null 2>&1 || true   # mode changed away from socks
  fi
  _bh_verify "$name"
}

# live checks
_bh_listening() { ports_live 2>/dev/null | grep -qx "$1"; }      # tcp or udp
_bh_connected() {  # foreign: an established TCP session to Iran's tunnel port
  local ip="${ST[iran_ip]#[}"; ip="${ip%]}"
  [[ -n "${ST[edge_ip]:-}" ]] && ip=''          # via a CDN edge the peer IP differs
  ss -Htn state established 2>/dev/null | awk -v p="${ST[tunnel_port]}" -v ip="$ip" '
    { n = split($4, a, ":"); if (a[n] == p && (ip == "" || index($4, ip))) { f = 1; exit } } END { exit !f }'
}
_bh_peer_up() {  # iran: the foreign side is connected (Iran opens its ports only then)
  if [[ "${ST[mode]}" == socks ]]; then ports_listening "${ST[iran_socks]}"; return; fi
  local it bind lp
  it="$(_bh_fwd_items "${ST[fwd]:-}" | head -n1)"; [[ -z "$it" ]] && return 1
  read -r bind lp <<<"$(_bh_fwd_local "$it")"
  _bh_listening "${lp%%-*}"
}

_bh_verify() {  # <name>
  local name="$1" u="mili-backhaul@$1.service" i
  [[ "${MILI_DRYRUN:-0}" == 1 ]] && { ui_info "[dry] skipping live checks"; return 0; }
  for (( i = 0; i < 4; i++ )); do sleep 1; svc_active "$u" || break; done
  if ! svc_active "$u"; then
    ui_err "backhaul did not stay up:"; journalctl -u "$u" -n 15 --no-pager 2>/dev/null; return 1
  fi
  if [[ "${ST[role]}" == iran ]]; then
    for (( i = 0; i < 6; i++ )); do _bh_listening "${ST[tunnel_port]}" && break; sleep 1; done
    if ! _bh_listening "${ST[tunnel_port]}"; then
      ui_err "backhaul is running but not listening on :${ST[tunnel_port]}"; journalctl -u "$u" -n 15 --no-pager 2>/dev/null; return 1
    fi
    ui_ok "listening on :${ST[tunnel_port]} (${ST[transport]})"
    if _bh_peer_up; then ui_ok "foreign server connected"
    else ui_note "waiting for the foreign server - the SOCKS/forward ports open once it connects"; fi
  else
    if [[ "${ST[mode]}" == socks ]]; then
      for (( i = 0; i < 5; i++ )); do ports_listening "${ST[foreign_socks]}" && break; sleep 1; done
      if ports_listening "${ST[foreign_socks]}"; then ui_ok "exit SOCKS5 ready on 127.0.0.1:${ST[foreign_socks]}"
      else ui_err "exit SOCKS5 (gost) is not listening on 127.0.0.1:${ST[foreign_socks]}"; return 1; fi
    fi
    if [[ "${ST[transport]}" == udp ]]; then
      ui_note "udp transport: check the Iran side shows 'foreign server connected'."
      return 0
    fi
    for (( i = 0; i < 12; i++ )); do _bh_connected && break; sleep 1; done
    if _bh_connected; then ui_ok "connected to Iran $(_bh_hostport "${ST[iran_ip]}" "${ST[tunnel_port]}")"
    else
      ui_warn "not connected to Iran yet. Check: the Iran tunnel is up, and IP / port / transport / token match;"
      ui_warn "the Iran provider firewall must allow TCP ${ST[tunnel_port]}."
      journalctl -u "$u" -n 6 --no-pager 2>/dev/null | grep -iE 'token|refused|timeout|error' | tail -n 3
    fi
  fi
  return 0
}

t_backhaul_down() {  # <name>
  svc_down "mili-backhaul@$1.service" 2>/dev/null || true
  svc_down "mili-socks@$1.service" 2>/dev/null || true
  fw_remove "$1"
}

t_backhaul_purge() {
  run rm -f "$MILI_BH_ETC/$1.toml" 2>/dev/null || true
  run rm -rf "$MILI_ETC/pki/$1" 2>/dev/null || true
}

# cheap (menu): Iran = tunnel port bound; Foreign = service running
t_backhaul_health() {  # <name>
  st_load "$1"
  if [[ "${ST[role]}" == iran ]]; then _bh_listening "${ST[tunnel_port]}"
  else svc_active "mili-backhaul@$1.service"; fi
}
# deeper (watchdog): Foreign must actually hold a session to Iran
t_backhaul_probe() {  # <name>
  st_load "$1"
  if [[ "${ST[role]}" == iran ]]; then _bh_listening "${ST[tunnel_port]}"; return; fi
  svc_active "mili-backhaul@$1.service" || return 1
  [[ "${ST[transport]}" == udp ]] && return 0
  _bh_connected
}

t_backhaul_info() {
  st_load "$1"
  local t="${ST[transport]}"
  ui_kv "transport" "$t$(_bh_is_mux "$t" && echo " · mux v${ST[mux_version]:-1}")"
  if [[ "${ST[role]}" == iran ]]; then
    ui_kv "role" "Iran · server, listens :${ST[tunnel_port]}"
    ui_kv "foreign" "$(_bh_peer_up && echo connected || echo 'waiting for the foreign server')"
    if [[ "${ST[mode]}" == socks ]]; then echo; xui_outbound_box "127.0.0.1" "${ST[iran_socks]}" "${ST[socks_user]:-}" "${ST[socks_pass]:-}"
    else ui_kv "ports" "${ST[fwd]}"; fi
  else
    ui_kv "role" "Foreign · client → $(_bh_hostport "${ST[iran_ip]}" "${ST[tunnel_port]}")"
    [[ "$t" != udp ]] && ui_kv "link" "$(_bh_connected && echo 'connected to Iran' || echo 'not connected')"
    [[ "${ST[mode]}" == socks ]] && ui_kv "exit SOCKS5" "127.0.0.1:${ST[foreign_socks]}"
  fi
  return 0
}

t_backhaul_xui() {
  st_load "$1"; local name="$1"
  if [[ "${ST[mode]}" == socks && "${ST[role]}" == iran ]]; then
    xui_help_socks "$name" "127.0.0.1" "${ST[iran_socks]}" "${ST[socks_user]:-}" "${ST[socks_pass]:-}"
  elif [[ "${ST[mode]}" == socks ]]; then
    ui_warn "the 3x-ui SOCKS outbound is on the IRAN server: Manage → its Backhaul tunnel → 3x-ui JSON helper."
  else
    ui_head "Use '$name' with 3x-ui (port forward)"; ui_note "Iran ports → foreign: ${ST[fwd]}"
  fi
}

t_backhaul_test() {
  st_load "$1"
  if [[ "${ST[role]}" == iran ]]; then
    if t_backhaul_health "$1"; then ui_ok "listening on :${ST[tunnel_port]}"; else ui_err "not listening on :${ST[tunnel_port]}"; return 1; fi
    if ! _bh_peer_up; then ui_warn "the foreign server is not connected"; return 1; fi
    ui_ok "foreign server connected"
    if [[ "${ST[mode]}" == socks ]]; then doctor_socks 127.0.0.1 "${ST[iran_socks]}" "${ST[socks_user]:-}" "${ST[socks_pass]:-}"; fi
  else
    if t_backhaul_probe "$1"; then ui_ok "connected to Iran"; else ui_err "not connected to Iran"; return 1; fi
  fi
}

# what to type on the other server (Backhaul has no token blob: it's 4 values)
t_backhaul_handoff() {  # <name>
  st_load "$1"
  if [[ "${ST[role]}" == iran ]]; then
    ui_head "Backhaul '$1' - type these on the FOREIGN server"
    ui_note "There: mili → New tunnel → Backhaul → Foreign"
    ui_warn "the token is a secret - share it only with your foreign server"
    echo
    ui_kv "IRAN server IP" "${ST[my_ip]:-$(sys_public_ip4)}"
    ui_kv "Tunnel port" "${ST[tunnel_port]}"
    ui_kv "Transport" "${ST[transport]}"
    ui_kv "Security token" "${ST[token]}"
    _bh_is_mux "${ST[transport]}" && ui_kv "Mux version" "${ST[mux_version]}"
    if [[ "${ST[mode]}" == socks ]]; then
      ui_kv "Usage" "SOCKS outbound"
      ui_kv "SOCKS5 port" "${ST[foreign_socks]}"
    else
      ui_kv "Usage" "Port forward"
    fi
    echo; ui_note "Every other question: press Enter."
    ui_note "If this server's provider has a firewall panel, allow $([[ "${ST[transport]}" == udp ]] && echo 'TCP+UDP' || echo TCP) ${ST[tunnel_port]}."
    if [[ "${ST[mode]}" == socks ]]; then echo; xui_outbound_box "127.0.0.1" "${ST[iran_socks]}" "${ST[socks_user]:-}" "${ST[socks_pass]:-}"; fi
  else
    ui_head "Backhaul '$1' - foreign side"
    if [[ "${ST[transport]}" != udp ]]; then
      if _bh_connected; then ui_ok "connected to Iran $(_bh_hostport "${ST[iran_ip]}" "${ST[tunnel_port]}")"
      else ui_warn "not connected to Iran yet (see the hints above)"; fi
    fi
    if [[ "${ST[mode]}" == socks ]]; then
      ui_note "The 3x-ui SOCKS outbound lives on the IRAN server: Manage → its Backhaul tunnel → 3x-ui JSON helper."
    fi
  fi
  return 0
}
