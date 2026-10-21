# shellcheck shell=bash
# mili :: tunnels/paqet.sh - hanselime/paqet raw-packet tunnel.
# server = FOREIGN (listens), client = IRAN (dials, exposes local SOCKS5).
# Uses raw pcap packets with TCP-flag cycling + KCP. mili adds the required
# raw NOTRACK + mangle RST-drop in ITS OWN chains (never iptables-persistent).
#
# NOTE: paqet is alpha; the generated config keys follow the documented layout
# and are confirmed against the installed binary at first run (verify-at-impl).
#
# roles: iran (client) | foreign (server)
# config: /etc/mili/engines/paqet/<name>.conf

t_register paqet
feature "tunnel.paqet" free

MILI_PQ_ETC="$MILI_ETC/engines/paqet"

t_paqet_meta() {
  echo "id=paqet"
  echo "title=paqet  (raw packet, anti-DPI)"
  echo "tier=free"
  echo "layer=socks"
  echo "roles=iran foreign"
  echo "primary=foreign"   # foreign = server (listener) generates; iran dials in
  echo "twoway=no"
  echo "cores=paqet"
}

_paqet_guard_port() {  # refuse kernel/x-ui/reserved ports for the raw listener
  local port="$1"
  local r
  for r in 80 443 22 53; do [[ "$port" == "$r" ]] && return 1; done
  ports_xui | grep -qx "$port" && return 1
  return 0
}

t_paqet_wizard() {  # <role> <level>
  local role="$1" level="$2"
  # generator = foreign (server/listener); iran side is created by import
  ST[my_ip]="$(sys_public_ip4)"
  [[ "$level" == advanced ]] && ST[my_ip]="$(ui_ask 'This foreign server public IP (auto-detected)' "${ST[my_ip]}")"
  ui_ok "this foreign server's public IP: ${ST[my_ip]}  (iran will dial it)"
  ST[listen_port]="$(ui_ask 'paqet listen port (foreign, raw)' "${ST[listen_port]:-$(sys_rand_port 20000 29999)}")"
  _paqet_guard_port "${ST[listen_port]}" || { ui_err "that port is reserved / used by x-ui; pick another"; return 1; }
  [[ -z "${ST[secret]:-}" ]] && ST[secret]="$(sys_rand_hex 16)"

  # auto network facts (client side needs iface / local ip / router mac)
  ST[iface]="${ST[iface]:-$(sys_default_iface)}"
  ST[local_ip]="${ST[local_ip]:-$(sys_local_ip4)}"
  ST[router_mac]="${ST[router_mac]:-$(sys_gw_mac 2>/dev/null)}"

  if [[ "$level" == advanced ]]; then
    ST[local_flag]="$(ui_ask 'local TCP flag (e.g. PA/S/A)' "${ST[local_flag]:-PA}")"
    ST[remote_flag]="$(ui_ask 'remote TCP flag' "${ST[remote_flag]:-PA}")"
    echo; ui_info "KCP mode: normal fast fast2 fast3 manual"
    ST[kcp]="$(ui_ask 'kcp mode' "${ST[kcp]:-fast2}")"
    ST[conn]="$(ui_ask 'connection count' "${ST[conn]:-4}")"
    ST[mtu]="$(ui_ask 'mtu' "${ST[mtu]:-1350}")"
    ST[nocongestion]="$(ui_ask 'nocongestion true/false' "${ST[nocongestion]:-true}")"
  else
    ST[local_flag]="${ST[local_flag]:-PA}"; ST[remote_flag]="${ST[remote_flag]:-PA}"
    ST[kcp]="${ST[kcp]:-fast2}"; ST[conn]="${ST[conn]:-4}"; ST[mtu]="${ST[mtu]:-1350}"; ST[nocongestion]="${ST[nocongestion]:-true}"
  fi
  ST[mode]=socks
  return 0
}

t_paqet_render() {  # <name>
  st_load "$1"; local name="$1" f; f="$MILI_PQ_ETC/$name.conf"
  run mkdir -p "$MILI_PQ_ETC"
  [[ "${MILI_DRYRUN:-0}" == 1 ]] && { ui_info "[dry] paqet config for $name (role ${ST[role]})"; return 0; }
  if [[ "${ST[role]}" == foreign ]]; then
    cat >"$f" <<EOF
# mili paqet server (foreign) tunnel $name
mode = server
iface = ${ST[iface]}
local_ip = ${ST[local_ip]}
listen = ${ST[listen_port]}
secret = ${ST[secret]}
local_flag = ${ST[local_flag]}
remote_flag = ${ST[remote_flag]}
kcp_mode = ${ST[kcp]}
conn = ${ST[conn]}
mtu = ${ST[mtu]}
nocongestion = ${ST[nocongestion]}
EOF
  else
    cat >"$f" <<EOF
# mili paqet client (Iran) tunnel $name
mode = client
iface = ${ST[iface]}
local_ip = ${ST[local_ip]}
router_mac = ${ST[router_mac]}
remote = ${ST[foreign_ip]}:${ST[listen_port]}
secret = ${ST[secret]}
local_flag = ${ST[local_flag]}
remote_flag = ${ST[remote_flag]}
kcp_mode = ${ST[kcp]}
conn = ${ST[conn]}
mtu = ${ST[mtu]}
nocongestion = ${ST[nocongestion]}
socks = 127.0.0.1:${ST[socks_port]}
EOF
  fi
  chmod 600 "$f"
}

t_paqet_unit() { echo "mili-paqet@$1.service"; }

t_paqet_fw_apply() {  # <name>
  st_load "$1"; local name="$1"
  # raw NOTRACK + RST-drop on the paqet port (both sides) - mili chains only
  fw_raw_notrack "$name" tcp "${ST[listen_port]}"
  fw_drop_rst "$name" "${ST[listen_port]}"
  if [[ "${ST[role]}" == foreign ]]; then
    fw_allow "$name" tcp "${ST[listen_port]}"; fw_ufw_mirror "$name" tcp "${ST[listen_port]}"
  fi
}

t_paqet_up() {  # <name>
  st_load "$1"; local name="$1"
  require_root; cores_ensure paqet
  sys_apt_ensure libpcap0.8
  t_paqet_render "$name"
  t_paqet_fw_apply "$name"
  svc_up "mili-paqet@$name.service"
  if [[ "${ST[role]}" == foreign ]]; then
    ports_claim "$name" tcp "${ST[listen_port]}" "0.0.0.0"
  else
    ports_claim "$name" tcp "${ST[socks_port]}" "127.0.0.1"
  fi
}

t_paqet_down() {  # <name>
  svc_down "mili-paqet@$1.service" 2>/dev/null || true
  fw_remove "$1"
}

t_paqet_purge() { run rm -f "$MILI_PQ_ETC/$1.conf" 2>/dev/null || true; }

t_paqet_health() {  # <name>
  st_load "$1"
  if [[ "${ST[role]}" == iran ]]; then
    ss -Hlnt 2>/dev/null | awk '{print $4}' | grep -qE ":${ST[socks_port]}\$"
  else
    svc_active "mili-paqet@$1.service"
  fi
}

t_paqet_ports() {
  st_load "$1"
  [[ "${ST[role]}" == foreign ]] && echo "tcp:${ST[listen_port]}:0.0.0.0"
  [[ "${ST[role]}" == iran ]] && echo "tcp:${ST[socks_port]}:127.0.0.1"
}

t_paqet_info() {
  st_load "$1"
  ui_kv "role" "${ST[role]}"
  ui_kv "kcp" "${ST[kcp]} conn=${ST[conn]} mtu=${ST[mtu]}"
  ui_kv "flags" "local=${ST[local_flag]} remote=${ST[remote_flag]}"
  if [[ "${ST[role]}" == foreign ]]; then
    ui_kv "listen" "0.0.0.0:${ST[listen_port]} (raw)"
  else
    ui_kv "dials" "${ST[foreign_ip]}:${ST[listen_port]}"
    ui_kv "socks (Iran)" "127.0.0.1:${ST[socks_port]}"
  fi
}

t_paqet_xui() {
  st_load "$1"; local name="$1"
  if [[ "${ST[role]}" == iran ]]; then
    # paqet client socks5 has no auth by default
    xui_help_socks "$name" "127.0.0.1" "${ST[socks_port]}" "" ""
  else
    ui_warn "paqet SOCKS endpoint is on the IRAN (client) server at 127.0.0.1:${ST[socks_port]}."
  fi
}

t_paqet_test() {
  st_load "$1"
  if [[ "${ST[role]}" == iran ]]; then doctor_socks 127.0.0.1 "${ST[socks_port]}"; else t_paqet_health "$1" && ui_ok "paqet server up" || ui_err "down"; fi
}

t_paqet_pair_export() {
  st_load "$1"
  local peerrole; [[ "${ST[role]}" == foreign ]] && peerrole=iran || peerrole=foreign
  cat <<EOF
type=paqet
name=${ST[name]}
role=$peerrole
listen_port=${ST[listen_port]}
secret=${ST[secret]}
foreign_ip=${ST[my_ip]:-${ST[foreign_ip]:-}}
local_flag=${ST[local_flag]}
remote_flag=${ST[remote_flag]}
kcp=${ST[kcp]}
conn=${ST[conn]}
mtu=${ST[mtu]}
nocongestion=${ST[nocongestion]}
EOF
}

t_paqet_pair_import() {
  local p="$1" name role k
  name="$(pair_field "$p" name)"; role="$(pair_field "$p" role)"
  ST=(); ST[name]="$name"; ST[type]=paqet; ST[role]="$role"; ST[mode]=socks
  for k in listen_port secret foreign_ip local_flag remote_flag kcp conn mtu nocongestion; do
    ST[$k]="$(pair_field "$p" "$k")"
  done
  ST[iface]="$(sys_default_iface)"; ST[local_ip]="$(sys_local_ip4)"; ST[router_mac]="$(sys_gw_mac 2>/dev/null)"
  [[ "$role" == foreign ]] && ST[my_ip]="$(sys_public_ip4)"
  [[ "$role" == iran ]] && ST[socks_port]="$(ports_alloc_socks)"
  st_save
  t_paqet_up "$name"; st_set state up; st_save
}
