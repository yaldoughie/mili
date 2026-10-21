# shellcheck shell=bash
# mili :: tunnels/grefrp.sh - GRE + FRP combined.
# A private GRE carries an FRP session: frps binds the IRAN INNER IP, frpc on
# FOREIGN dials it over GRE. No public FRP port is ever exposed -> only GRE/FOU
# is visible on the wire. Optional failover note when GRE is down.
#
# roles: iran (frps) | foreign (frpc)

t_register grefrp
feature "tunnel.grefrp" free

MILI_GRF_S="$MILI_ETC/engines/frps"
MILI_GRF_C="$MILI_ETC/engines/frpc"

t_grefrp_meta() {
  echo "id=grefrp"
  echo "title=GRE + FRP  (private, stealth)"
  echo "tier=free"
  echo "layer=fwd"
  echo "roles=iran foreign"
  echo "primary=iran"     # iran (frps) generates; foreign imports + replies
  echo "twoway=yes"
  echo "cores=frp"
}

_grf_if() { printf 'mgrf-%s' "$1"; }
_grf_inner_local() { local n="$1" r="$2"; [[ "$r" == iran ]] && echo "10.77.$n.1" || echo "10.77.$n.2"; }
_grf_inner_peer()  { local n="$1" r="$2"; [[ "$r" == iran ]] && echo "10.77.$n.2" || echo "10.77.$n.1"; }

t_grefrp_wizard() {  # <role> <level>  (runs on the GENERATOR = iran side)
  local role="$1" level="$2" n
  ST[my_ip]="$(sys_public_ip4)"
  [[ "$level" == advanced ]] && ST[my_ip]="$(ui_ask "This server public IP (auto-detected)" "${ST[my_ip]}")"
  ui_ok "this server's public IP: ${ST[my_ip]}"
  ST[peer_ip]="${ST[peer_ip]:-}"   # arrives via the reply code

  echo; ui_info "GRE variant: 1) gre  2) gre+fou (recommended)"
  local gv; gv="$(ui_ask 'variant' "${ST[variant]:-2}")"
  case "$gv" in 1) ST[variant]=gre;; *) ST[variant]=fou;; esac
  [[ "${ST[variant]}" == fou ]] && ST[fou_port]="${ST[fou_port]:-$(sys_rand_port 20000 29999)}"

  if [[ -z "${ST[inner_n]:-}" ]]; then n="$(pool_inner_subnet)" || { ui_err "no inner subnet"; return 1; }; ST[inner_n]="$n"; fi
  [[ -z "${ST[key]:-}" ]] && ST[key]="$(pool_gre_key)"
  ST[inner_local]="$(_grf_inner_local "${ST[inner_n]}" "$role")"
  ST[inner_peer]="$(_grf_inner_peer  "${ST[inner_n]}" "$role")"
  [[ -z "${ST[bind_port]:-}" ]] && ST[bind_port]="$(ports_alloc_internal)"
  [[ -z "${ST[token]:-}" ]] && ST[token]="$(sys_rand_token 24)"

  echo; ui_info "Usage mode: 1) socks  2) forward"
  local um; um="$(ui_ask 'mode' "${ST[mode]:-1}")"
  case "$um" in 2) ST[mode]=forward;; *) ST[mode]=socks;; esac
  case "${ST[mode]}" in
    socks)
      ST[remote_port]="${ST[remote_port]:-$(ports_alloc_socks)}"
      [[ -z "${ST[socks_user]:-}" ]] && ST[socks_user]="mili"
      [[ -z "${ST[socks_pass]:-}" ]] && ST[socks_pass]="$(sys_rand_token 18)" ;;
    forward)
      ST[fwd]="$(ui_ask 'Forward spec iranPublic=foreignLocal/proto' "${ST[fwd]:-}")" ;;
  esac

  if [[ "$level" == advanced ]]; then
    ST[mtu]="$(ui_ask 'GRE MTU' "${ST[mtu]:-1400}")"
    ST[transport]="$(ui_ask 'frp transport tcp|kcp|quic|websocket' "${ST[transport]:-tcp}")"
    ST[tls]="$(ui_ask 'frp TLS true/false' "${ST[tls]:-true}")"
  else
    ST[mtu]="${ST[mtu]:-1400}"; ST[transport]="${ST[transport]:-tcp}"; ST[tls]="${ST[tls]:-true}"
  fi
  ST[ttl]="${ST[ttl]:-255}"
  return 0
}

# ---- GRE interface (reuses the same plumbing idea as gre.sh) ---------------
t_grefrp_ifup() {  # <name>
  st_load "$1"; local name="$1" ifc; ifc="$(_grf_if "$name")"
  run modprobe ip_gre 2>/dev/null || true
  if [[ "${ST[variant]}" == fou ]]; then
    run modprobe fou 2>/dev/null || true
    run ip fou add port "${ST[fou_port]}" ipproto 47 2>/dev/null || true
    run ip link add "$ifc" type gre local "${ST[my_ip]}" remote "${ST[peer_ip]}" \
      key "${ST[key]}" ttl "${ST[ttl]}" encap fou encap-sport auto encap-dport "${ST[fou_port]}" 2>/dev/null \
      || run ip link add "$ifc" type gre local "${ST[my_ip]}" remote "${ST[peer_ip]}" key "${ST[key]}" ttl "${ST[ttl]}"
  else
    run ip link add "$ifc" type gre local "${ST[my_ip]}" remote "${ST[peer_ip]}" key "${ST[key]}" ttl "${ST[ttl]}"
  fi
  run ip addr add "${ST[inner_local]}/30" dev "$ifc" 2>/dev/null || true
  run ip link set "$ifc" mtu "${ST[mtu]}" up
}
t_grefrp_ifdown() {  # <name>
  st_load "$1"; local ifc; ifc="$(_grf_if "$1")"
  run ip link del "$ifc" 2>/dev/null || true
  [[ "${ST[variant]}" == fou ]] && run ip fou del port "${ST[fou_port]}" 2>/dev/null || true
}

t_grefrp_render() {  # <name> : frp config bound to inner IPs
  st_load "$1"; local name="$1"
  if [[ "${ST[role]}" == iran ]]; then
    run mkdir -p "$MILI_GRF_S"; local f="$MILI_GRF_S/$name.toml"
    [[ "${MILI_DRYRUN:-0}" == 1 ]] && { ui_info "[dry] frps(inner) config for $name"; return 0; }
    cat >"$f" <<EOF
# mili GRE+FRP frps (Iran) bound to inner IP for tunnel $name
bindAddr = "${ST[inner_local]}"
bindPort = ${ST[bind_port]}
auth.method = "token"
auth.token = "${ST[token]}"
webServer.addr = "127.0.0.1"
log.to = "/var/log/mili/frps-$name.log"
log.level = "info"
EOF
    chmod 600 "$f"
  else
    run mkdir -p "$MILI_GRF_C"; local f="$MILI_GRF_C/$name.toml"
    [[ "${MILI_DRYRUN:-0}" == 1 ]] && { ui_info "[dry] frpc(inner) config for $name"; return 0; }
    {
      cat <<EOF
# mili GRE+FRP frpc (Foreign) dialing Iran inner IP over GRE for tunnel $name
serverAddr = "${ST[inner_peer]}"
serverPort = ${ST[bind_port]}
auth.method = "token"
auth.token = "${ST[token]}"
transport.protocol = "${ST[transport]}"
transport.tls.enable = ${ST[tls]}
log.to = "/var/log/mili/frpc-$name.log"
log.level = "info"
EOF
      if [[ "${ST[mode]}" == socks ]]; then
        cat <<EOF

[[proxies]]
name = "$name-socks"
type = "tcp"
remotePort = ${ST[remote_port]}
[proxies.plugin]
type = "socks5"
username = "${ST[socks_user]}"
password = "${ST[socks_pass]}"
EOF
      else
        local item lport rport proto i=0
        IFS=',' read -ra items <<<"${ST[fwd]}"
        for item in "${items[@]}"; do
          [[ -z "$item" ]] && continue
          proto="${item##*/}"; item="${item%/*}"; lport="${item%%=*}"; rport="${item##*=}"
          [[ "$proto" != udp ]] && proto=tcp
          cat <<EOF

[[proxies]]
name = "$name-fwd$i"
type = "$proto"
localIP = "127.0.0.1"
localPort = $rport
remotePort = $lport
EOF
          i=$((i+1))
        done
      fi
    } >"$f"
    chmod 600 "$f"
  fi
}

t_grefrp_fw_apply() {  # <name>
  st_load "$1"; local name="$1"
  # only GRE/FOU is public
  if [[ "${ST[variant]}" == fou ]]; then
    fw_allow "$name" udp "${ST[fou_port]}" "${ST[peer_ip]}"; fw_ufw_mirror "$name" udp "${ST[fou_port]}" "${ST[peer_ip]}"
  else
    fw_allow_proto "$name" 47 "${ST[peer_ip]}"; fw_ufw_allow_gre "$name" "${ST[peer_ip]}"
  fi
  fw_mss "$name" "$(_grf_if "$name")" pmtu
  if [[ "${ST[role]}" == iran ]]; then
    if [[ "${ST[mode]}" == socks ]]; then
      fw_loopback_guard "$name" tcp "${ST[remote_port]}"
    else
      local item lport proto
      IFS=',' read -ra items <<<"${ST[fwd]}"
      for item in "${items[@]}"; do
        [[ -z "$item" ]] && continue
        proto="${item##*/}"; item="${item%/*}"; lport="${item%%=*}"
        [[ "$proto" != udp ]] && proto=tcp
        fw_allow "$name" "$proto" "$lport"; fw_ufw_mirror "$name" "$proto" "$lport"
      done
    fi
  fi
}

t_grefrp_up() {  # <name>
  st_load "$1"; local name="$1"
  require_root
  if [[ -z "${ST[peer_ip]:-}" ]]; then
    ui_warn "waiting for the peer's reply code before GRE+FRP can come up"
    ui_note "import the REPLY code from the other server to finish '$name'."
    return 0
  fi
  cores_ensure frp
  t_grefrp_fw_apply "$name"
  svc_up "mili-l3@$name.service"       # brings GRE iface up (via _l3 -> ifup)
  t_grefrp_render "$name"
  if [[ "${ST[role]}" == iran ]]; then
    svc_up "mili-frps@$name.service"
    [[ "${ST[mode]}" == socks ]] && ports_claim "$name" tcp "${ST[remote_port]}" "127.0.0.1"
  else
    svc_up "mili-frpc@$name.service"
  fi
  [[ "${ST[variant]}" == fou ]] && ports_claim "$name" udp "${ST[fou_port]}" "0.0.0.0"
}

t_grefrp_down() {  # <name>
  st_load "$1"; local name="$1"
  svc_down "mili-frps@$name.service" 2>/dev/null || true
  svc_down "mili-frpc@$name.service" 2>/dev/null || true
  svc_down "mili-l3@$name.service" 2>/dev/null || true
  t_grefrp_ifdown "$name" 2>/dev/null || true
  fw_remove "$name"
}

t_grefrp_purge() {
  st_load "$1"
  run rm -f "$MILI_GRF_S/$1.toml" "$MILI_GRF_C/$1.toml" 2>/dev/null || true
  pool_inner_release "${ST[inner_n]}"; pool_meta_release "$1"
}

t_grefrp_unit() { st_load "$1"; [[ "${ST[role]}" == iran ]] && echo "mili-frps@$1.service" || echo "mili-frpc@$1.service"; }

t_grefrp_health() {  # <name> : GRE reachable AND frp link up
  st_load "$1"
  ping -c1 -W2 -I "$(_grf_if "$1")" "${ST[inner_peer]}" >/dev/null 2>&1 || return 1
  if [[ "${ST[role]}" == iran ]]; then
    ss -Hlnt 2>/dev/null | grep -q "${ST[inner_local]}:${ST[bind_port]}" || \
    ss -Hlnt 2>/dev/null | awk '{print $4}' | grep -qE ":${ST[bind_port]}\$"
  else
    svc_active "mili-frpc@$1.service"
  fi
}

t_grefrp_ports() {
  st_load "$1"
  [[ "${ST[variant]}" == fou ]] && echo "udp:${ST[fou_port]}:0.0.0.0"
  [[ "${ST[role]}" == iran && "${ST[mode]}" == socks ]] && echo "tcp:${ST[remote_port]}:127.0.0.1"
}

t_grefrp_info() {
  st_load "$1"
  ui_kv "variant" "${ST[variant]} (private GRE$([[ ${ST[variant]} == fou ]] && echo '+FOU'))"
  ui_kv "role/mode" "${ST[role]} / ${ST[mode]}"
  ui_kv "inner" "${ST[inner_local]} <-> ${ST[inner_peer]}"
  ui_kv "frp" "inner :${ST[bind_port]} transport=${ST[transport]} tls=${ST[tls]}"
  [[ "${ST[variant]}" == fou ]] && ui_kv "fou udp" "${ST[fou_port]} (only public port)"
  [[ "${ST[role]}" == iran && "${ST[mode]}" == socks ]] && { echo; xui_outbound_box "127.0.0.1" "${ST[remote_port]}" "${ST[socks_user]}" "${ST[socks_pass]}"; }
  [[ "${ST[mode]}" == forward ]] && ui_kv "forward" "${ST[fwd]}"
}

t_grefrp_xui() {
  st_load "$1"; local name="$1"
  if [[ "${ST[mode]}" == socks && "${ST[role]}" == iran ]]; then
    xui_help_socks "$name" "127.0.0.1" "${ST[remote_port]}" "${ST[socks_user]}" "${ST[socks_pass]}"
  elif [[ "${ST[mode]}" == socks ]]; then
    ui_warn "SOCKS endpoint is on the IRAN server (127.0.0.1:${ST[remote_port]}); run helper there."
  else
    ui_head "Use '$name' with 3x-ui (port forward over GRE+FRP)"
    ui_note "Foreign ports published on Iran public ports: ${ST[fwd]}"
  fi
}

t_grefrp_test() {
  st_load "$1"
  ping -c1 -W2 -I "$(_grf_if "$1")" "${ST[inner_peer]}" >/dev/null 2>&1 && ui_ok "GRE up" || ui_err "GRE down"
  [[ "${ST[mode]}" == socks && "${ST[role]}" == iran ]] && doctor_socks 127.0.0.1 "${ST[remote_port]}" "${ST[socks_user]}" "${ST[socks_pass]}"
}

t_grefrp_pair_export() {  # iran -> foreign
  st_load "$1"
  cat <<EOF
type=grefrp
name=${ST[name]}
role=foreign
variant=${ST[variant]}
mode=${ST[mode]}
inner_n=${ST[inner_n]}
key=${ST[key]}
mtu=${ST[mtu]}
ttl=${ST[ttl]}
fou_port=${ST[fou_port]:-}
gen_ip=${ST[my_ip]}
bind_port=${ST[bind_port]}
token=${ST[token]}
transport=${ST[transport]}
tls=${ST[tls]}
remote_port=${ST[remote_port]:-}
socks_user=${ST[socks_user]:-}
socks_pass=${ST[socks_pass]:-}
fwd=${ST[fwd]:-}
EOF
}

t_grefrp_pair_import() {  # runs on foreign
  local p="$1" name n
  name="$(pair_field "$p" name)"; n="$(pair_field "$p" inner_n)"
  ST=(); ST[name]="$name"; ST[type]=grefrp; ST[role]=foreign
  ST[variant]="$(pair_field "$p" variant)"; ST[mode]="$(pair_field "$p" mode)"
  ST[inner_n]="$n"; ST[key]="$(pair_field "$p" key)"
  ST[mtu]="$(pair_field "$p" mtu)"; ST[ttl]="$(pair_field "$p" ttl)"
  ST[fou_port]="$(pair_field "$p" fou_port)"
  ST[my_ip]="$(sys_public_ip4)"
  ST[peer_ip]="$(pair_field "$p" gen_ip)"
  ui_ok "this server's public IP: ${ST[my_ip]}  (peer iran: ${ST[peer_ip]})"
  ST[inner_local]="$(_grf_inner_local "$n" foreign)"
  ST[inner_peer]="$(_grf_inner_peer  "$n" foreign)"
  ST[bind_port]="$(pair_field "$p" bind_port)"; ST[token]="$(pair_field "$p" token)"
  ST[transport]="$(pair_field "$p" transport)"; ST[tls]="$(pair_field "$p" tls)"
  ST[remote_port]="$(pair_field "$p" remote_port)"
  ST[socks_user]="$(pair_field "$p" socks_user)"; ST[socks_pass]="$(pair_field "$p" socks_pass)"
  ST[fwd]="$(pair_field "$p" fwd)"
  pool_inner_claim "$n" "$name"
  st_save
  t_grefrp_up "$name"; st_set state up; st_save
}

t_grefrp_pair_reply() {  # foreign -> iran
  st_load "$1"
  cat <<EOF
type=grefrp
name=${ST[name]}
reply=1
peer_ip=${ST[my_ip]}
EOF
}

t_grefrp_pair_finalize() {  # runs on iran
  local p="$1" name
  name="$(pair_field "$p" name)"
  st_load "$name" || return 1
  ST[peer_ip]="$(pair_field "$p" peer_ip)"
  st_save
  t_grefrp_up "$name"; st_set state up; st_save
}
