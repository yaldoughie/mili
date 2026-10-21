# shellcheck shell=bash
# mili :: tunnels/frp.sh - reverse FRP tunnel (fatedier/frp).
# frps listens on IRAN (public), frpc dials from FOREIGN. Foreign egress is
# exposed back to Iran. SOCKS mode uses frp's built-in socks5 plugin (no gost).
#
# roles: iran (frps) | foreign (frpc)
# config: /etc/mili/engines/{frps,frpc}/<name>.toml

t_register frp
feature "tunnel.frp" free

MILI_FRP_ETC_S="$MILI_ETC/engines/frps"
MILI_FRP_ETC_C="$MILI_ETC/engines/frpc"

t_frp_meta() {
  echo "id=frp"
  echo "title=FRP  (reverse, public)"
  echo "tier=free"
  echo "layer=fwd"
  echo "roles=iran foreign"
  echo "cores=frp"
}

t_frp_wizard() {  # <role> <level>
  local role="$1" level="$2"
  if [[ "$role" == iran ]]; then
    ST[bind_port]="$(ui_ask 'frps public bind port (Iran)' "${ST[bind_port]:-$(ports_alloc_public)}")"
    ST[my_ip]="$(ui_ask "This Iran server public IP" "$(sys_public_ip4)")"
  else
    ST[iran_ip]="$(ui_ask 'Iran server public IP' "${ST[iran_ip]:-}")"
    ST[bind_port]="$(ui_ask 'frps bind port on Iran' "${ST[bind_port]:-}")"
  fi
  [[ -z "${ST[token]:-}" ]] && ST[token]="$(sys_rand_token 24)"

  echo; ui_info "Usage mode:"
  ui_item 1 "socks" "SOCKS5 egress on foreign, reachable at Iran 127.0.0.1:<port>"
  ui_item 2 "forward" "expose foreign port on Iran public port"
  local um; um="$(ui_ask 'mode' "${ST[mode]:-1}")"
  case "$um" in 2) ST[mode]=forward;; *) ST[mode]=socks;; esac

  case "${ST[mode]}" in
    socks)
      ST[remote_port]="$(ui_ask 'Iran-side SOCKS port (loopback)' "${ST[remote_port]:-$(ports_alloc_socks)}")"
      [[ -z "${ST[socks_user]:-}" ]] && ST[socks_user]="mili"
      [[ -z "${ST[socks_pass]:-}" ]] && ST[socks_pass]="$(sys_rand_token 18)" ;;
    forward)
      ST[fwd]="$(ui_ask 'Forward spec  iranPublic=foreignLocal/proto  e.g. 8443=443/tcp' "${ST[fwd]:-}")" ;;
  esac

  if [[ "$level" == advanced ]]; then
    echo; ui_info "transport: tcp | kcp | quic | websocket"
    ST[transport]="$(ui_ask 'transport protocol' "${ST[transport]:-tcp}")"
    ST[tls]="$(ui_ask 'enable TLS (true/false)' "${ST[tls]:-true}")"
    ST[pool]="$(ui_ask 'poolCount' "${ST[pool]:-5}")"
  else
    ST[transport]="${ST[transport]:-tcp}"; ST[tls]="${ST[tls]:-true}"; ST[pool]="${ST[pool]:-5}"
  fi
  return 0
}

t_frp_render() {  # <name>
  st_load "$1"; local name="$1"
  if [[ "${ST[role]}" == iran ]]; then
    run mkdir -p "$MILI_FRP_ETC_S"
    local f="$MILI_FRP_ETC_S/$name.toml"
    if [[ "${MILI_DRYRUN:-0}" == 1 ]]; then ui_info "[dry] frps config:"; else
    cat >"$f" <<EOF
# mili frps (Iran) for tunnel $name
bindAddr = "0.0.0.0"
bindPort = ${ST[bind_port]}
auth.method = "token"
auth.token = "${ST[token]}"
webServer.addr = "127.0.0.1"
transport.maxPoolCount = 50
log.to = "/var/log/mili/frps-$name.log"
log.level = "info"
EOF
    chmod 600 "$f"; fi
  else
    run mkdir -p "$MILI_FRP_ETC_C"
    local f="$MILI_FRP_ETC_C/$name.toml"
    if [[ "${MILI_DRYRUN:-0}" == 1 ]]; then ui_info "[dry] frpc config:"; else
    {
      cat <<EOF
# mili frpc (Foreign) for tunnel $name
serverAddr = "${ST[iran_ip]}"
serverPort = ${ST[bind_port]}
auth.method = "token"
auth.token = "${ST[token]}"
transport.protocol = "${ST[transport]}"
transport.tls.enable = ${ST[tls]}
transport.poolCount = ${ST[pool]}
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
          proto="${item##*/}"; item="${item%/*}"
          lport="${item%%=*}"; rport="${item##*=}"
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
    chmod 600 "$f"; fi
  fi
}

t_frp_unit() { st_load "$1"; [[ "${ST[role]}" == iran ]] && echo "mili-frps@$1.service" || echo "mili-frpc@$1.service"; }

t_frp_fw_apply() {  # <name>
  st_load "$1"; local name="$1"
  if [[ "${ST[role]}" == iran ]]; then
    fw_allow "$name" tcp "${ST[bind_port]}"
    fw_ufw_mirror "$name" tcp "${ST[bind_port]}"
    if [[ "${ST[mode]}" == socks ]]; then
      # SOCKS remote port must stay loopback-only on Iran
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

t_frp_up() {  # <name>
  st_load "$1"; local name="$1"
  require_root; cores_ensure frp
  t_frp_render "$name"
  t_frp_fw_apply "$name"
  if [[ "${ST[role]}" == iran ]]; then
    svc_up "mili-frps@$name.service"
    ports_claim "$name" tcp "${ST[bind_port]}" "0.0.0.0"
    [[ "${ST[mode]}" == socks ]] && ports_claim "$name" tcp "${ST[remote_port]}" "127.0.0.1"
  else
    svc_up "mili-frpc@$name.service"
  fi
}

t_frp_down() {  # <name>
  st_load "$1"; local name="$1"
  svc_down "mili-frps@$name.service" 2>/dev/null || true
  svc_down "mili-frpc@$name.service" 2>/dev/null || true
  fw_remove "$name"
}

t_frp_purge() {
  st_load "$1"
  run rm -f "$MILI_FRP_ETC_S/$1.toml" "$MILI_FRP_ETC_C/$1.toml" 2>/dev/null || true
}

t_frp_health() {  # <name>
  st_load "$1"
  if [[ "${ST[role]}" == iran ]]; then
    ss -Hlnt 2>/dev/null | awk '{print $4}' | grep -qE ":${ST[bind_port]}\$"
  else
    svc_active "mili-frpc@$1.service"
  fi
}

t_frp_ports() {
  st_load "$1"
  [[ "${ST[role]}" == iran ]] || return 0
  echo "tcp:${ST[bind_port]}:0.0.0.0"
  [[ "${ST[mode]}" == socks ]] && echo "tcp:${ST[remote_port]}:127.0.0.1"
}

t_frp_info() {
  st_load "$1"
  ui_kv "role" "${ST[role]}"
  ui_kv "mode" "${ST[mode]}"
  ui_kv "transport" "${ST[transport]} tls=${ST[tls]}"
  if [[ "${ST[role]}" == iran ]]; then
    ui_kv "frps bind" "0.0.0.0:${ST[bind_port]}"
    [[ "${ST[mode]}" == socks ]] && ui_kv "socks (Iran)" "127.0.0.1:${ST[remote_port]} (user ${ST[socks_user]})"
    [[ "${ST[mode]}" == forward ]] && ui_kv "forward" "${ST[fwd]}"
  else
    ui_kv "dials" "${ST[iran_ip]}:${ST[bind_port]}"
  fi
}

t_frp_xui() {
  st_load "$1"; local name="$1"
  if [[ "${ST[mode]}" == socks && "${ST[role]}" == iran ]]; then
    xui_help_socks "$name" "127.0.0.1" "${ST[remote_port]}" "${ST[socks_user]}" "${ST[socks_pass]}"
  elif [[ "${ST[mode]}" == socks ]]; then
    ui_warn "SOCKS endpoint lives on the IRAN server (127.0.0.1:${ST[remote_port]}). Run this helper there."
  else
    ui_head "Use '$name' with 3x-ui (port forward)"
    ui_note "Foreign ports are published on the Iran public ports: ${ST[fwd]}"
  fi
}

t_frp_test() {
  st_load "$1"
  if [[ "${ST[mode]}" == socks && "${ST[role]}" == iran ]]; then
    doctor_socks 127.0.0.1 "${ST[remote_port]}" "${ST[socks_user]}" "${ST[socks_pass]}"
  else
    t_frp_health "$1" && ui_ok "frp link healthy" || ui_err "frp link down"
  fi
}

t_frp_pair_export() {
  st_load "$1"
  local peerrole; [[ "${ST[role]}" == iran ]] && peerrole=foreign || peerrole=iran
  cat <<EOF
type=frp
name=${ST[name]}
role=$peerrole
mode=${ST[mode]}
bind_port=${ST[bind_port]}
token=${ST[token]}
transport=${ST[transport]}
tls=${ST[tls]}
pool=${ST[pool]}
iran_ip=${ST[my_ip]:-${ST[iran_ip]:-}}
remote_port=${ST[remote_port]:-}
socks_user=${ST[socks_user]:-}
socks_pass=${ST[socks_pass]:-}
fwd=${ST[fwd]:-}
EOF
}

t_frp_pair_import() {
  local p="$1" name role
  name="$(pair_field "$p" name)"; role="$(pair_field "$p" role)"
  ST=(); ST[name]="$name"; ST[type]=frp; ST[role]="$role"
  ST[mode]="$(pair_field "$p" mode)"
  ST[bind_port]="$(pair_field "$p" bind_port)"
  ST[token]="$(pair_field "$p" token)"
  ST[transport]="$(pair_field "$p" transport)"
  ST[tls]="$(pair_field "$p" tls)"
  ST[pool]="$(pair_field "$p" pool)"
  ST[iran_ip]="$(pair_field "$p" iran_ip)"
  ST[remote_port]="$(pair_field "$p" remote_port)"
  ST[socks_user]="$(pair_field "$p" socks_user)"
  ST[socks_pass]="$(pair_field "$p" socks_pass)"
  ST[fwd]="$(pair_field "$p" fwd)"
  [[ "$role" == iran ]] && ST[my_ip]="$(sys_public_ip4)"
  st_save
  t_frp_up "$name"; st_set state up; st_save
}
