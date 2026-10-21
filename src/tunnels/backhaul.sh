# shellcheck shell=bash
# mili :: tunnels/backhaul.sh - Musixal/Backhaul (open-source only).
# server = IRAN (listens public tunnel port), client = FOREIGN (dials).
# SOCKS mode: foreign runs mili-socks (gost); Backhaul forwards an Iran port to
# it. skip_optz=true ALWAYS (protects the ephemeral range used by xray).
#
# roles: iran (server) | foreign (client)
# config: /etc/mili/engines/backhaul/<name>.toml

t_register backhaul
feature "tunnel.backhaul" free

MILI_BH_ETC="$MILI_ETC/engines/backhaul"

t_backhaul_meta() {
  echo "id=backhaul"
  echo "title=Backhaul  (reverse mux)"
  echo "tier=free"
  echo "layer=fwd"
  echo "roles=iran foreign"
  echo "cores=backhaul"
}

t_backhaul_wizard() {  # <role> <level>
  local role="$1" level="$2"
  if [[ "$role" == iran ]]; then
    ST[tunnel_port]="$(ui_ask 'Public tunnel port (Iran listens)' "${ST[tunnel_port]:-$(ports_alloc_public)}")"
    ST[my_ip]="$(ui_ask 'This Iran server public IP' "$(sys_public_ip4)")"
  else
    ST[iran_ip]="$(ui_ask 'Iran server public IP' "${ST[iran_ip]:-}")"
    ST[tunnel_port]="$(ui_ask 'Tunnel port on Iran' "${ST[tunnel_port]:-}")"
  fi
  [[ -z "${ST[token]:-}" ]] && ST[token]="$(sys_rand_token 24)"

  echo; ui_info "transport: tcp tcpmux ws wss wsmux wssmux udp"
  ST[transport]="$(ui_ask 'transport' "${ST[transport]:-tcp}")"

  echo; ui_info "Usage mode: 1) socks  2) forward"
  local um; um="$(ui_ask 'mode' "${ST[mode]:-1}")"
  case "$um" in 2) ST[mode]=forward;; *) ST[mode]=socks;; esac
  case "${ST[mode]}" in
    socks)
      ST[iran_socks]="${ST[iran_socks]:-$(ports_alloc_socks)}"
      ST[foreign_socks]="${ST[foreign_socks]:-$(sys_rand_port 10800 10999)}"
      [[ -z "${ST[socks_user]:-}" ]] && ST[socks_user]="mili"
      [[ -z "${ST[socks_pass]:-}" ]] && ST[socks_pass]="$(sys_rand_token 18)" ;;
    forward)
      ST[fwd]="$(ui_ask 'ports spec (backhaul syntax, comma)  e.g. 8443=443,2083=127.0.0.1:2083' "${ST[fwd]:-}")" ;;
  esac

  if [[ "$level" == advanced ]]; then
    ST[nodelay]="$(ui_ask 'nodelay true/false' "${ST[nodelay]:-true}")"
    ST[keepalive]="$(ui_ask 'keepalive_period (s)' "${ST[keepalive]:-75}")"
    ST[heartbeat]="$(ui_ask 'heartbeat (s)' "${ST[heartbeat]:-40}")"
    ST[mux_con]="$(ui_ask 'mux_con' "${ST[mux_con]:-8}")"
    ST[conn_pool]="$(ui_ask 'connection_pool' "${ST[conn_pool]:-8}")"
    [[ "${ST[transport]}" == wss* ]] && ST[domain]="$(ui_ask 'TLS domain (optional, blank=self-signed)' "${ST[domain]:-}")"
  else
    ST[nodelay]="${ST[nodelay]:-true}"; ST[keepalive]="${ST[keepalive]:-75}"
    ST[heartbeat]="${ST[heartbeat]:-40}"; ST[mux_con]="${ST[mux_con]:-8}"; ST[conn_pool]="${ST[conn_pool]:-8}"
  fi
  return 0
}

_bh_ports_line() {  # build the ports = [...] array contents
  st_load "$1"
  if [[ "${ST[mode]}" == socks ]]; then
    printf '"%s=%s"' "${ST[iran_socks]}" "${ST[foreign_socks]}"
  else
    local item out='' first=1
    IFS=',' read -ra items <<<"${ST[fwd]}"
    for item in "${items[@]}"; do
      [[ -z "$item" ]] && continue
      [[ $first -eq 1 ]] && first=0 || out+=", "
      out+="\"$item\""
    done
    printf '%s' "$out"
  fi
}

_bh_tls() {  # emit tls cert/key lines for wss* transports
  st_load "$1"
  [[ "${ST[transport]}" == wss* ]] || return 0
  local crt key dir="$MILI_ETC/pki/$1"
  if [[ -n "${ST[domain]:-}" && -f "/root/cert/${ST[domain]}/fullchain.pem" ]]; then
    crt="/root/cert/${ST[domain]}/fullchain.pem"; key="/root/cert/${ST[domain]}/privkey.pem"
  else
    crt="$dir/cert.pem"; key="$dir/key.pem"
    if [[ ! -f "$crt" && "${MILI_DRYRUN:-0}" != 1 ]]; then
      mkdir -p "$dir"
      openssl req -x509 -newkey rsa:2048 -keyout "$key" -out "$crt" -days 3650 -nodes \
        -subj "/CN=${ST[domain]:-mili.local}" >/dev/null 2>&1 || true
    fi
  fi
  printf 'tls_cert = "%s"\ntls_key = "%s"\n' "$crt" "$key"
}

t_backhaul_render() {  # <name>
  st_load "$1"; local name="$1" f; f="$MILI_BH_ETC/$name.toml"
  run mkdir -p "$MILI_BH_ETC"
  [[ "${MILI_DRYRUN:-0}" == 1 ]] && { ui_info "[dry] backhaul config for $name (role ${ST[role]})"; return 0; }
  if [[ "${ST[role]}" == iran ]]; then
    {
      echo "# mili Backhaul server (Iran) tunnel $name"
      echo "[server]"
      echo "bind_addr = \"0.0.0.0:${ST[tunnel_port]}\""
      echo "transport = \"${ST[transport]}\""
      echo "token = \"${ST[token]}\""
      echo "keepalive_period = ${ST[keepalive]}"
      echo "nodelay = ${ST[nodelay]}"
      echo "heartbeat = ${ST[heartbeat]}"
      echo "mux_con = ${ST[mux_con]}"
      echo "channel_size = 2048"
      echo "sniffer = false"
      echo "web_port = 0"
      echo "skip_optz = true"
      _bh_tls "$name"
      echo "ports = [ $(_bh_ports_line "$name") ]"
    } >"$f"
  else
    {
      echo "# mili Backhaul client (Foreign) tunnel $name"
      echo "[client]"
      echo "remote_addr = \"${ST[iran_ip]}:${ST[tunnel_port]}\""
      echo "transport = \"${ST[transport]}\""
      echo "token = \"${ST[token]}\""
      echo "keepalive_period = ${ST[keepalive]}"
      echo "nodelay = ${ST[nodelay]}"
      echo "connection_pool = ${ST[conn_pool]}"
      echo "sniffer = false"
      echo "web_port = 0"
      echo "skip_optz = true"
      [[ "${ST[transport]}" == wss* ]] && echo "edge_ip = \"\""
    } >"$f"
  fi
  chmod 600 "$f"
}

t_backhaul_unit() { echo "mili-backhaul@$1.service"; }

t_backhaul_fw_apply() {  # <name>
  st_load "$1"; local name="$1"
  if [[ "${ST[role]}" == iran ]]; then
    fw_allow "$name" tcp "${ST[tunnel_port]}"; fw_ufw_mirror "$name" tcp "${ST[tunnel_port]}"
    if [[ "${ST[mode]}" == socks ]]; then
      fw_loopback_guard "$name" tcp "${ST[iran_socks]}"
    else
      local item lport proto=tcp
      IFS=',' read -ra items <<<"${ST[fwd]}"
      for item in "${items[@]}"; do
        [[ -z "$item" ]] && continue
        lport="${item%%=*}"
        fw_allow "$name" tcp "$lport"; fw_ufw_mirror "$name" tcp "$lport"
      done
    fi
  fi
}

t_backhaul_up() {  # <name>
  st_load "$1"; local name="$1"
  require_root; cores_ensure backhaul
  t_backhaul_render "$name"
  t_backhaul_fw_apply "$name"
  svc_up "mili-backhaul@$name.service"
  if [[ "${ST[role]}" == iran ]]; then
    ports_claim "$name" tcp "${ST[tunnel_port]}" "0.0.0.0"
    [[ "${ST[mode]}" == socks ]] && ports_claim "$name" tcp "${ST[iran_socks]}" "127.0.0.1"
  else
    if [[ "${ST[mode]}" == socks ]]; then
      cores_ensure gost
      socks_render "$name" "127.0.0.1" "${ST[foreign_socks]}" "${ST[socks_user]}" "${ST[socks_pass]}"
      svc_up "mili-socks@$name.service"
      ports_claim "$name" tcp "${ST[foreign_socks]}" "127.0.0.1"
    fi
  fi
}

t_backhaul_down() {  # <name>
  st_load "$1"; local name="$1"
  svc_down "mili-backhaul@$name.service" 2>/dev/null || true
  svc_down "mili-socks@$name.service" 2>/dev/null || true
  fw_remove "$name"
}

t_backhaul_purge() { run rm -f "$MILI_BH_ETC/$1.toml" 2>/dev/null || true; }

t_backhaul_health() {  # <name>
  st_load "$1"
  if [[ "${ST[role]}" == iran ]]; then
    ss -Hlnt 2>/dev/null | awk '{print $4}' | grep -qE ":${ST[tunnel_port]}\$"
  else
    svc_active "mili-backhaul@$1.service"
  fi
}

t_backhaul_ports() {
  st_load "$1"
  if [[ "${ST[role]}" == iran ]]; then
    echo "tcp:${ST[tunnel_port]}:0.0.0.0"
    [[ "${ST[mode]}" == socks ]] && echo "tcp:${ST[iran_socks]}:127.0.0.1"
  else
    [[ "${ST[mode]}" == socks ]] && echo "tcp:${ST[foreign_socks]}:127.0.0.1"
  fi
}

t_backhaul_info() {
  st_load "$1"
  ui_kv "role/mode" "${ST[role]} / ${ST[mode]}"
  ui_kv "transport" "${ST[transport]}"
  if [[ "${ST[role]}" == iran ]]; then
    ui_kv "listen" "0.0.0.0:${ST[tunnel_port]}"
    [[ "${ST[mode]}" == socks ]] && ui_kv "socks (Iran)" "127.0.0.1:${ST[iran_socks]} (user ${ST[socks_user]})"
    [[ "${ST[mode]}" == forward ]] && ui_kv "ports" "${ST[fwd]}"
  else
    ui_kv "dials" "${ST[iran_ip]}:${ST[tunnel_port]}"
    [[ "${ST[mode]}" == socks ]] && ui_kv "egress socks" "127.0.0.1:${ST[foreign_socks]}"
  fi
}

t_backhaul_xui() {
  st_load "$1"; local name="$1"
  if [[ "${ST[mode]}" == socks && "${ST[role]}" == iran ]]; then
    xui_help_socks "$name" "127.0.0.1" "${ST[iran_socks]}" "${ST[socks_user]}" "${ST[socks_pass]}"
  elif [[ "${ST[mode]}" == socks ]]; then
    ui_warn "SOCKS endpoint is on the IRAN server (127.0.0.1:${ST[iran_socks]}); run helper there."
  else
    ui_head "Use '$name' with 3x-ui (port forward)"; ui_note "Foreign ports published on Iran: ${ST[fwd]}"
  fi
}

t_backhaul_test() {
  st_load "$1"
  if [[ "${ST[mode]}" == socks && "${ST[role]}" == iran ]]; then
    doctor_socks 127.0.0.1 "${ST[iran_socks]}" "${ST[socks_user]}" "${ST[socks_pass]}"
  else
    t_backhaul_health "$1" && ui_ok "backhaul up" || ui_err "backhaul down"
  fi
}

t_backhaul_pair_export() {
  st_load "$1"
  local peerrole; [[ "${ST[role]}" == iran ]] && peerrole=foreign || peerrole=iran
  cat <<EOF
type=backhaul
name=${ST[name]}
role=$peerrole
mode=${ST[mode]}
transport=${ST[transport]}
tunnel_port=${ST[tunnel_port]}
token=${ST[token]}
iran_ip=${ST[my_ip]:-${ST[iran_ip]:-}}
iran_socks=${ST[iran_socks]:-}
foreign_socks=${ST[foreign_socks]:-}
socks_user=${ST[socks_user]:-}
socks_pass=${ST[socks_pass]:-}
fwd=${ST[fwd]:-}
nodelay=${ST[nodelay]}
keepalive=${ST[keepalive]}
heartbeat=${ST[heartbeat]:-40}
mux_con=${ST[mux_con]:-8}
conn_pool=${ST[conn_pool]:-8}
domain=${ST[domain]:-}
EOF
}

t_backhaul_pair_import() {
  local p="$1" name role k
  name="$(pair_field "$p" name)"; role="$(pair_field "$p" role)"
  ST=(); ST[name]="$name"; ST[type]=backhaul; ST[role]="$role"
  for k in mode transport tunnel_port token iran_ip iran_socks foreign_socks socks_user socks_pass fwd nodelay keepalive heartbeat mux_con conn_pool domain; do
    ST[$k]="$(pair_field "$p" "$k")"
  done
  [[ "$role" == iran ]] && ST[my_ip]="$(sys_public_ip4)"
  st_save
  t_backhaul_up "$name"; st_set state up; st_save
}
