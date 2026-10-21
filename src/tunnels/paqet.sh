# shellcheck shell=bash
# mili :: tunnels/paqet.sh - hanselime/paqet raw-packet tunnel (KCP over pcap).
#
# NATIVE flow (no mili pairing code): mili asks the same questions as the
# ChownYourLife/paqet-tunnel deploy script, in the same order, every one with an
# Enter default, and writes paqet's own YAML config.
#   FOREIGN = server ("Kharej") - listens on a raw port      (set up first)
#   IRAN    = client            - dials it with the values the foreign shows:
#             foreign IP, port, encryption key  -> local SOCKS5 for 3x-ui
#
# Firewall (paqet README / deploy script, server side): raw NOTRACK on the port
# (in + out) and drop kernel RSTs from it - in mili's own chains, never
# iptables-persistent. paqet binaries are static (no libpcap package needed).
# config: /etc/mili/engines/paqet/<name>.yaml   run: paqet run -c <config>

t_register paqet
feature "tunnel.paqet" free

MILI_PQ_ETC="$MILI_ETC/engines/paqet"

t_paqet_meta() {
  echo "id=paqet"
  echo "title=paqet  (raw packet, anti-DPI)"
  echo "tier=free"
  echo "layer=socks"
  echo "roles=foreign iran"
  echo "primary=foreign"
  echo "pairing=native"
  echo "handoff_label=Show values for the Iran server"
  echo "first_hint=Set up the FOREIGN server first (it listens). Then on the IRAN server pick paqet → Iran and type the IP, port and key the foreign server shows."
  echo "cores=paqet"
}

t_paqet_unit() { echo "mili-paqet@$1.service"; }

# ============================================================================
# pure helpers (unit-tested)
# ============================================================================
# KCP values, exactly as the deploy script's set_kcp_defaults / apply_kcp_preset:
# prints "nodelay interval resend nocongestion rcvwnd sndwnd smuxbuf streambuf"
_pq_kcp_values() {  # <preset normal|gaming|streaming> <role server|client>
  local preset="$1" role="$2" nd=1 iv=10 rs=2 nc=1 rw sw sb=4194304 st=2097152
  if [[ "$role" == server ]]; then rw=2048; sw=2048; else rw=1024; sw=1024; fi
  case "$preset" in
    gaming)
      if [[ "$role" == server ]]; then rw=1024; sw=1024; else rw=512; sw=512; fi
      sb=2097152; st=1048576 ;;
    streaming)
      if [[ "$role" == server ]]; then rw=4096; sw=4096; else rw=2048; sw=2048; fi
      sb=8388608; st=4194304 ;;
  esac
  printf '%s %s %s %s %s %s %s %s' "$nd" "$iv" "$rs" "$nc" "$rw" "$sw" "$sb" "$st"
}

# TCP flag list "PA,S" -> ["PA", "S"]
_pq_flags() {
  local f out='' x; local -a fl=()
  IFS=',' read -ra fl <<<"${1:-PA}"
  for x in "${fl[@]}"; do [[ -n "$x" ]] && out+="${out:+, }\"$x\""; done
  printf '[%s]' "${out:-\"PA\"}"
}

_pq_valid_mac() { [[ "$1" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; }
_pq_valid_key() { local re='^[^"\\[:space:]]+$'; [[ -n "$1" && "$1" =~ $re ]]; }

# forward items "L=T,L=T" -> one "L T" per line
_pq_fwd_items() {
  local it; local -a _pqi=()
  IFS=',' read -ra _pqi <<<"${1// /}"
  for it in "${_pqi[@]}"; do [[ "$it" == *=* ]] && printf '%s %s\n' "${it%%=*}" "${it#*=}"; done
  return 0
}

# paqet's YAML (the deploy script's layout, with paqet's real key names)
_pq_yaml() {  # <name>
  local name="$1" role kv nd iv rs nc rw sw sb st
  if [[ "${ST[role]}" == foreign ]]; then role=server; else role=client; fi
  kv="$(_pq_kcp_values "${ST[kcp_preset]:-normal}" "$role")"
  read -r nd iv rs nc rw sw sb st <<<"$kv"
  if [[ "$role" == server ]]; then
    printf '# mili paqet server (foreign) - tunnel %s\n' "$name"
  else
    printf '# mili paqet client (Iran) - tunnel %s\n' "$name"
  fi
  printf 'role: "%s"\n\n' "$role"
  printf 'log:\n  level: "info"\n\n'
  if [[ "$role" == server ]]; then
    printf 'listen:\n  addr: ":%s"\n\n' "${ST[listen_port]}"
  elif [[ "${ST[proxy]:-socks}" == forward ]]; then
    printf 'forward:\n'
    local l t
    while read -r l t; do
      printf '  - listen: ":%s"\n    target: "%s:%s"\n    protocol: "tcp"\n' "$l" "${ST[foreign_ip]}" "$t"
    done < <(_pq_fwd_items "${ST[fwd]:-}")
    printf '\n'
  else
    printf 'socks5:\n  - listen: "127.0.0.1:%s"\n    username: ""\n    password: ""\n\n' "${ST[socks_port]}"
  fi
  printf 'network:\n'
  printf '  interface: "%s"\n' "${ST[iface]}"
  printf '  ipv4:\n'
  if [[ "$role" == server ]]; then
    printf '    addr: "%s:%s"\n' "${ST[local_ip]}" "${ST[listen_port]}"
  else
    printf '    addr: "%s:0"\n' "${ST[local_ip]}"
  fi
  printf '    router_mac: "%s"\n' "${ST[router_mac]}"
  printf '  tcp:\n    local_flag: %s\n    remote_flag: %s\n' "$(_pq_flags "${ST[local_flag]:-PA}")" "$(_pq_flags "${ST[remote_flag]:-PA}")"
  printf '  pcap:\n    sockbuf: %s\n\n' "$([[ "$role" == server ]] && echo 8388608 || echo 4194304)"
  if [[ "$role" == client ]]; then
    printf 'server:\n  addr: "%s:%s"\n\n' "${ST[foreign_ip]}" "${ST[listen_port]}"
  fi
  printf 'transport:\n'
  printf '  protocol: "kcp"\n'
  printf '  conn: %s\n' "${ST[conn]:-3}"
  printf '  kcp:\n'
  printf '    mode: "%s"\n' "${ST[kcp]:-fast}"
  printf '    mtu: %s\n' "${ST[mtu]:-1350}"
  printf '    nodelay: %s\n    interval: %s\n    resend: %s\n    nocongestion: %s\n' "$nd" "$iv" "$rs" "$nc"
  printf '    rcvwnd: %s\n    sndwnd: %s\n' "$rw" "$sw"
  printf '    block: "aes"\n'
  printf '    key: "%s"\n' "${ST[secret]}"
  printf '    smuxbuf: %s\n    streambuf: %s\n' "$sb" "$st"
}

# ============================================================================
# wizard (the deploy script's question order)
# ============================================================================
t_paqet_wizard() {  # <role> [level]
  if [[ "$1" == foreign ]]; then _pq_wizard_foreign; else _pq_wizard_iran; fi
}

# ports paqet's iptables rules would wreck (README: never 80/443/standard ports)
_pq_port_refused() {
  local p="$1" r
  for r in 22 53 80 443 "${MILI_RESERVED[@]}"; do [[ "$r" == "$p" ]] && return 0; done
  ports_xui 2>/dev/null | grep -qx "$p"
}

# KCP questions, shared by both roles (connections -> mode [-> preset] -> MTU)
_pq_ask_kcp() {
  echo; ui_info "KCP configuration (connection tuning):"
  ST[conn]="$(ui_ask_int '[-] Number of parallel connections (1-3 = lower bandwidth overhead)' "${ST[conn]:-3}" 1 256)"
  local -a modes=(fast fast2 fast3 manual); local i pre=0
  for i in "${!modes[@]}"; do [[ "${modes[$i]}" == "${ST[kcp]:-fast}" ]] && pre=$i; done
  echo; ui_info "KCP performance mode:"
  ui_pick "$pre" $'fast\trecommended' $'fast2\tmore aggressive' $'fast3\tmost aggressive · very high bandwidth use' $'manual\tcustom low-level parameters'
  ST[kcp]="${modes[$((SEL-1))]}"
  if [[ "${ST[kcp]}" == manual ]]; then
    local -a presets=(normal gaming streaming); pre=0
    for i in "${!presets[@]}"; do [[ "${presets[$i]}" == "${ST[kcp_preset]:-normal}" ]] && pre=$i; done
    echo; ui_info "Manual preset:"
    ui_pick "$pre" $'Normal\tbalanced' $'Gaming\tlow latency' $'Streaming/Downloading\thigh throughput'
    ST[kcp_preset]="${presets[$((SEL-1))]}"
  else
    ST[kcp_preset]=normal
  fi
  ST[mtu]="$(ui_ask_int '[-] MTU (1200-1300 can help unstable links)' "${ST[mtu]:-1350}" 50 1500)"
  ST[local_flag]="${ST[local_flag]:-PA}"; ST[remote_flag]="${ST[remote_flag]:-PA}"
}

# gateway MAC for the route out of <iface>
_pq_gw_mac() {  # <iface>
  local ifc="$1" gw mac
  gw="$(ip -4 route show default dev "$ifc" 2>/dev/null | awk '{print $3; exit}')"
  [[ -z "$gw" ]] && { sys_gw_mac 2>/dev/null; return; }
  ping -c1 -W1 "$gw" >/dev/null 2>&1 || true
  mac="$(ip neigh show "$gw" dev "$ifc" 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i == "lladdr") print $(i + 1)}' | head -n1)"
  printf '%s' "$mac"
}

# network interface / local IPv4 / gateway MAC (auto, like the script; asks only when it must)
_pq_ask_network() {
  local -a ent=(); local i pre=0 mac
  mapfile -t ent < <(ip -o -4 addr show scope global 2>/dev/null | awk '{split($4, a, "/"); print $2 " " a[1]}')
  if (( ${#ent[@]} > 1 )); then
    local -a labels=()
    for i in "${!ent[@]}"; do
      [[ "${ent[$i]}" == "${ST[iface]:-} ${ST[local_ip]:-}" ]] && pre=$i
      labels+=("${ent[$i]% *} → ${ent[$i]#* }")
    done
    echo; ui_info "Multiple IPv4 addresses - which interface/IP should paqet use?"
    ui_pick "$pre" "${labels[@]}"
    ST[iface]="${ent[$((SEL-1))]% *}"; ST[local_ip]="${ent[$((SEL-1))]#* }"
  elif (( ${#ent[@]} == 1 )); then
    ST[iface]="${ent[0]% *}"; ST[local_ip]="${ent[0]#* }"
  else
    ST[iface]="${ST[iface]:-$(sys_default_iface)}"; ST[local_ip]="${ST[local_ip]:-$(sys_local_ip4)}"
  fi
  mac="$(_pq_gw_mac "${ST[iface]}")"
  if ! _pq_valid_mac "$mac"; then
    ui_warn "could not detect the gateway MAC automatically (try: ip neigh)"
    while :; do
      mac="$(ui_ask '[*] Gateway/router MAC address' "${ST[router_mac]:-}")"
      _pq_valid_mac "$mac" && break
      ui_err "format: aa:bb:cc:dd:ee:ff"
    done
  fi
  ST[router_mac]="$mac"
  ui_ok "network: ${ST[iface]} · ${ST[local_ip]} · gateway MAC ${ST[router_mac]}"
}

_pq_wizard_foreign() {
  ST[my_ip]="$(sys_public_ip4)"
  ui_note "This FOREIGN server listens; the Iran server will dial ${ST[my_ip]}."
  echo
  # [*] Port to listen on
  local p who def="${ST[listen_port]:-}"
  [[ -z "$def" ]] && def="$(ports_free_in 9999 65535 2>/dev/null || ports_alloc_public "${ST[name]}")"
  while :; do
    p="$(ui_ask_int '[*] Port to listen on' "$def" 1 65535)"
    if _pq_port_refused "$p"; then
      ui_err "port $p is a standard / x-ui port - paqet's firewall rules would hit normal traffic. Pick a high port."; continue
    fi
    if who="$(ports_busy_reason "$p" "${ST[name]}")"; then ui_err "port $p is in use ($who)"; continue; fi
    break
  done
  ST[listen_port]="$p"
  # [-] connections / KCP mode / MTU
  _pq_ask_kcp
  # [*] encryption key (generated here, like the script; same format as `paqet secret`)
  ST[secret]="${ST[secret]:-$(sys_rand_hex 32)}"
  echo; ui_info "Encryption key (the Iran server needs it - shown again at the end):"
  printf '    %s%s%s\n' "${C_YEL:-}" "${ST[secret]}" "${C_RST:-}"
  # [*] network
  _pq_ask_network
  ST[mode]=socks
  return 0
}

_pq_wizard_iran() {
  local v p who
  # [*] Kharej SERVER IP
  while :; do
    v="$(ui_ask '[*] Kharej SERVER IP address' "${ST[foreign_ip]:-}")"; v="${v// /}"
    sys_is_ip4 "$v" && break
    ui_err "enter the foreign server's public IPv4"
  done
  ST[foreign_ip]="$v"
  # [*] SERVER port
  ST[listen_port]="$(ui_ask_int '[*] SERVER port' "${ST[listen_port]:-9999}" 1 65535)"
  # [*] proxy type
  local pre=0; [[ "${ST[proxy]:-socks}" == forward ]] && pre=1
  echo; ui_info "Proxy configuration:"
  ui_pick "$pre" $'SOCKS5 proxy\trecommended · 3x-ui outbound → 127.0.0.1:port' \
                 $'Port forwarding\tlocal ports → the foreign server'
  if (( SEL == 2 )); then
    ST[proxy]=forward
    echo; ui_info "Port forwarding: local_port=target_port (comma separated), e.g. 443=443, 8443=8080"
    ui_note "Targets are on the foreign server (${ST[foreign_ip]}). Don't use the paqet port (${ST[listen_port]}) as a target."
    while :; do
      v="$(ui_ask '[*] Port mappings' "${ST[fwd]:-}")"; v="${v// /}"
      _pq_fwd_check "$v" && break
    done
    ST[fwd]="$v"
  else
    ST[proxy]=socks
    while :; do
      p="$(ui_ask_port '[*] SOCKS5 port (3x-ui outbound → 127.0.0.1:port)' "${ST[socks_port]:-$(ports_alloc_socks "${ST[name]}")}")"
      if who="$(ports_busy_reason "$p" "${ST[name]}")" && ! [[ "$p" == "${ST[socks_port]:-}" && "$who" == paqet* ]]; then
        ui_err "port $p is in use ($who)"; continue
      fi
      break
    done
    ST[socks_port]="$p"
  fi
  # [-] connections / KCP mode / MTU
  _pq_ask_kcp
  # [*] encryption key (must match the foreign server)
  while :; do
    v="$(ui_ask '[*] Encryption key (from the foreign server)' "${ST[secret]:-}")"; v="${v// /}"
    _pq_valid_key "$v" && break
    ui_err "paste the key the foreign server showed"
  done
  ST[secret]="$v"
  # [*] network
  _pq_ask_network
  ST[mode]=socks
  return 0
}

# forward mappings: format, no loop to the paqet port, local ports free
_pq_fwd_check() {  # <list>
  local l t who n=0 own
  [[ -z "$1" ]] && { ui_err "enter at least one mapping"; return 1; }
  local it; local -a items=()
  IFS=',' read -ra items <<<"$1"
  for it in "${items[@]}"; do
    [[ "$it" =~ ^[0-9]+=[0-9]+$ ]] || { ui_err "invalid mapping: $it (use local=target)"; return 1; }
    l="${it%%=*}"; t="${it#*=}"
    (( l >= 1 && l <= 65535 && t >= 1 && t <= 65535 )) || { ui_err "ports must be 1-65535: $it"; return 1; }
    if [[ "$t" == "${ST[listen_port]}" ]]; then
      ui_err "unsafe: $it targets the paqet port itself (traffic loop)"; return 1
    fi
    own=0; [[ ",${ST[fwd]:-}," == *",$it,"* ]] && own=1
    if who="$(ports_busy_reason "$l" "${ST[name]}")" && ! { (( own )) && [[ "$who" == paqet* ]]; }; then
      ui_err "local port $l is in use ($who)"; return 1
    fi
    ((n++))
  done
  (( n > 3 )) && ui_note "tip: many mappings are fine; for lower bandwidth overhead keep connections at 1-3."
  return 0
}

t_paqet_summary() {
  local kcp="${ST[kcp]}"; [[ "$kcp" == manual ]] && kcp="manual (${ST[kcp_preset]})"
  if [[ "${ST[role]}" == foreign ]]; then
    ui_kv "Role" "Foreign · server (listens)"
    ui_kv "Listen" ":${ST[listen_port]} (raw TCP packets)"
  else
    ui_kv "Role" "Iran · client"
    ui_kv "Server" "${ST[foreign_ip]}:${ST[listen_port]}"
    if [[ "${ST[proxy]}" == forward ]]; then ui_kv "Forward" "${ST[fwd]} (→ ${ST[foreign_ip]})"
    else ui_kv "SOCKS5" "127.0.0.1:${ST[socks_port]}  (3x-ui outbound)"; fi
  fi
  ui_kv "KCP" "conn ${ST[conn]} · mode $kcp · MTU ${ST[mtu]}"
  ui_kv "Encryption key" "${ST[secret]}"
  ui_kv "Network" "${ST[iface]} · ${ST[local_ip]} · gw ${ST[router_mac]}"
  return 0
}

# ============================================================================
# render / firewall / ports
# ============================================================================
t_paqet_render() {  # <name>
  st_load "$1"; local name="$1" f="$MILI_PQ_ETC/$1.yaml"
  if [[ "${MILI_DRYRUN:-0}" == 1 ]]; then ui_info "[dry] would write $f:"; _pq_yaml "$name"; return 0; fi
  mkdir -p "$MILI_PQ_ETC"
  ( umask 077; _pq_yaml "$name" >"$f" )
  rm -f "$MILI_PQ_ETC/$name.conf" 2>/dev/null || true    # pre-YAML builds
}

t_paqet_fw_apply() {  # <name>
  st_load "$1"; local name="$1" l t
  if [[ "${ST[role]}" == foreign ]]; then
    # server side, as paqet's README / the deploy script: kernel must not track or RST the port
    fw_raw_notrack "$name" tcp "${ST[listen_port]}"
    fw_drop_rst "$name" "${ST[listen_port]}"
    fw_allow "$name" tcp "${ST[listen_port]}"; fw_ufw_mirror "$name" tcp "${ST[listen_port]}"
  elif [[ "${ST[proxy]:-socks}" == forward ]]; then
    while read -r l t; do fw_allow "$name" tcp "$l"; fw_ufw_mirror "$name" tcp "$l"; done < <(_pq_fwd_items "${ST[fwd]:-}")
  fi
  return 0
}

_pq_claim() {  # <name>
  local name="$1" l t
  ports_release "$name"
  if [[ "${ST[role]}" == foreign ]]; then
    ports_claim "$name" tcp "${ST[listen_port]}" 0.0.0.0
  elif [[ "${ST[proxy]:-socks}" == forward ]]; then
    while read -r l t; do ports_claim "$name" tcp "$l" 0.0.0.0; done < <(_pq_fwd_items "${ST[fwd]:-}")
  else
    ports_claim "$name" tcp "${ST[socks_port]}" 127.0.0.1
  fi
  return 0
}

t_paqet_ports() {
  st_load "$1"
  if [[ "${ST[role]}" == foreign ]]; then echo "tcp:${ST[listen_port]}:0.0.0.0"
  elif [[ "${ST[proxy]:-socks}" == forward ]]; then local l t; while read -r l t; do echo "tcp:$l:0.0.0.0"; done < <(_pq_fwd_items "${ST[fwd]:-}")
  else echo "tcp:${ST[socks_port]}:127.0.0.1"; fi
  return 0
}

# ============================================================================
# lifecycle
# ============================================================================
t_paqet_up() {  # <name>
  st_load "$1"; local name="$1"
  require_root
  cores_ensure paqet || { ui_err "paqet core install failed"; return 1; }
  t_paqet_render "$name"
  t_paqet_fw_apply "$name"
  _pq_claim "$name"
  svc_up "mili-paqet@$name.service"
}

# create / Edit: write config, check it (client: paqet ping), RESTART, verify
t_paqet_provision() {  # <name>
  st_load "$1"; local name="$1" u="mili-paqet@$1.service" out
  require_root
  cores_ensure paqet || { ui_err "paqet core install failed"; return 1; }
  t_paqet_render "$name" || return 1
  fw_remove "$name"; t_paqet_fw_apply "$name"
  _pq_claim "$name"
  if [[ "${ST[role]}" == iran && "${MILI_DRYRUN:-0}" != 1 ]]; then
    # the deploy script's connectivity test: parses the config and sends one raw packet
    out="$("$(cores_path paqet)" ping -c "$MILI_PQ_ETC/$name.yaml" 2>&1)"
    if grep -qiE 'failed to parse configuration|validation failed' <<<"$out"; then
      ui_err "paqet rejected the config:"; printf '%s\n' "$out" | tail -n 8; return 1
    fi
    if grep -q 'packet sent successfully' <<<"$out"; then ui_ok "config OK · test packet sent to ${ST[foreign_ip]}:${ST[listen_port]}"
    else ui_warn "paqet ping: $(printf '%s' "$out" | tail -n 1)"; fi
  fi
  svc_enable "$u"
  run systemctl restart "$u" || { ui_err "could not start $u"; svc_logs "$u" 20; return 1; }
  _pq_verify "$name"
}

# exit IP through the local SOCKS (empty = no traffic through the tunnel)
_pq_exit_ip() { curl -fsS --max-time "${2:-10}" --socks5-hostname "127.0.0.1:$1" https://api.ipify.org 2>/dev/null | tr -d '[:space:]'; }

_pq_verify() {  # <name>
  local name="$1" u="mili-paqet@$1.service" i errs l t xip
  [[ "${MILI_DRYRUN:-0}" == 1 ]] && { ui_info "[dry] skipping live checks"; return 0; }
  for (( i = 0; i < 3; i++ )); do sleep 1; svc_active "$u" || break; done
  errs="$(journalctl -u "$u" -n 30 --no-pager 2>/dev/null | grep -iE 'failed to parse configuration|validation failed|fatal' | tail -n 5)"
  if ! svc_active "$u" || [[ -n "$errs" ]]; then
    ui_err "paqet did not stay up:"; [[ -n "$errs" ]] && printf '%s\n' "$errs" || journalctl -u "$u" -n 15 --no-pager 2>/dev/null
    return 1
  fi
  if [[ "${ST[role]}" == foreign ]]; then
    ui_ok "paqet server running on :${ST[listen_port]} (raw packets via ${ST[iface]})"
    return 0
  fi
  if [[ "${ST[proxy]:-socks}" == forward ]]; then
    while read -r l t; do
      for (( i = 0; i < 5; i++ )); do ports_listening "$l" && break; sleep 1; done
      if ports_listening "$l"; then ui_ok "forward :$l → ${ST[foreign_ip]}:$t"; else ui_err "forward :$l is not listening"; return 1; fi
    done < <(_pq_fwd_items "${ST[fwd]:-}")
    return 0
  fi
  for (( i = 0; i < 6; i++ )); do ports_listening "${ST[socks_port]}" && break; sleep 1; done
  ports_listening "${ST[socks_port]}" || { ui_err "SOCKS5 is not listening on 127.0.0.1:${ST[socks_port]}"; return 1; }
  ui_ok "SOCKS5 ready on 127.0.0.1:${ST[socks_port]}"
  xip="$(_pq_exit_ip "${ST[socks_port]}" 12)"
  if [[ -n "$xip" ]]; then
    ui_ok "traffic flows through the tunnel · exit IP $xip"
  else
    ui_warn "no traffic through the tunnel yet. Check: the foreign paqet tunnel is up, port + key match,"
    ui_warn "and TCP ${ST[listen_port]} is allowed in the FOREIGN provider's firewall (cloud panel)."
  fi
  return 0
}

t_paqet_down() {  # <name>
  svc_down "mili-paqet@$1.service" 2>/dev/null || true
  fw_remove "$1"
}

t_paqet_purge() { run rm -f "$MILI_PQ_ETC/$1.yaml" "$MILI_PQ_ETC/$1.conf" 2>/dev/null || true; }

# cheap (menu): server = service running; client = its local listener is up
t_paqet_health() {  # <name>
  st_load "$1"
  if [[ "${ST[role]}" == foreign ]]; then svc_active "mili-paqet@$1.service"; return; fi
  if [[ "${ST[proxy]:-socks}" == forward ]]; then
    local l t; read -r l t < <(_pq_fwd_items "${ST[fwd]:-}"); [[ -n "$l" ]] && ports_listening "$l"; return
  fi
  ports_listening "${ST[socks_port]}"
}
# deeper (watchdog only): the client SOCKS must actually carry traffic
t_paqet_probe() {  # <name>
  st_load "$1"
  if [[ "${ST[role]}" == iran && "${ST[proxy]:-socks}" == socks ]]; then
    curl -fsS --max-time 6 --socks5-hostname "127.0.0.1:${ST[socks_port]}" https://www.gstatic.com/generate_204 -o /dev/null 2>/dev/null
    return
  fi
  t_paqet_health "$1"
}

t_paqet_info() {
  st_load "$1"
  local kcp="${ST[kcp]:-fast}"; [[ "$kcp" == manual ]] && kcp="manual (${ST[kcp_preset]:-normal})"
  ui_kv "kcp" "conn ${ST[conn]:-3} · mode $kcp · MTU ${ST[mtu]:-1350}"
  if [[ "${ST[role]}" == foreign ]]; then
    ui_kv "role" "Foreign · server, raw port :${ST[listen_port]}"
  else
    ui_kv "role" "Iran · client → ${ST[foreign_ip]}:${ST[listen_port]}"
    if [[ "${ST[proxy]:-socks}" == forward ]]; then ui_kv "forward" "${ST[fwd]}"
    else echo; xui_outbound_box "127.0.0.1" "${ST[socks_port]}" "" ""; fi
  fi
  return 0
}

t_paqet_xui() {
  st_load "$1"; local name="$1"
  if [[ "${ST[role]}" == iran && "${ST[proxy]:-socks}" == socks ]]; then
    xui_help_socks "$name" "127.0.0.1" "${ST[socks_port]}" "" ""      # paqet's SOCKS5: no auth
  elif [[ "${ST[role]}" == iran ]]; then
    ui_head "Use '$name' with 3x-ui (port forward)"; ui_note "local ports → foreign: ${ST[fwd]}"
  else
    ui_warn "the 3x-ui SOCKS outbound is on the IRAN server: Manage → its paqet tunnel → 3x-ui JSON helper."
  fi
}

t_paqet_test() {
  st_load "$1"
  if [[ "${ST[role]}" == iran && "${ST[proxy]:-socks}" == socks ]]; then
    doctor_socks 127.0.0.1 "${ST[socks_port]}"
  elif t_paqet_health "$1"; then ui_ok "paqet up"
  else ui_err "paqet down"; return 1; fi
}

# what to type on the other server (paqet has no token blob: IP, port, key)
t_paqet_handoff() {  # <name>
  st_load "$1"
  if [[ "${ST[role]}" == foreign ]]; then
    ui_head "paqet '$1' - type these on the IRAN server"
    ui_note "There: mili → New tunnel → paqet → Iran"
    ui_warn "the key is a secret - share it only with your Iran server"
    echo
    ui_kv "Kharej SERVER IP" "${ST[my_ip]:-$(sys_public_ip4)}"
    ui_kv "SERVER port" "${ST[listen_port]}"
    ui_kv "Encryption key" "${ST[secret]}"
    if [[ "${ST[conn]}" != 3 || "${ST[kcp]}" != fast || "${ST[mtu]}" != 1350 ]]; then
      ui_kv "Same tuning" "connections ${ST[conn]} · KCP ${ST[kcp]}$([[ "${ST[kcp]}" == manual ]] && echo "/${ST[kcp_preset]}") · MTU ${ST[mtu]}"
    fi
    echo; ui_note "Every other question: press Enter."
    ui_note "If this server's provider has a firewall panel (cloud security group), allow TCP ${ST[listen_port]}."
  else
    ui_head "paqet '$1' - Iran side"
    if [[ "${ST[proxy]:-socks}" == socks ]]; then xui_outbound_box "127.0.0.1" "${ST[socks_port]}" "" ""
    else ui_kv "forward" "${ST[fwd]} → ${ST[foreign_ip]}"; fi
  fi
  return 0
}
