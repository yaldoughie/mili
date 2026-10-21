# shellcheck shell=bash
# mili :: tunnels/gre.sh - GRE layer-3 tunnel (kernel iproute2).
# Variants: gre (v4), gre+fou (GRE-in-UDP, evades proto-47 blocks), ip6gre (v6).
# Usage modes: socks (gost on foreign inner IP) | forward (DNAT) | l3 (full exit).
#
# Inner addressing: 10.77.<N>.0/30  -> iran .1, foreign .2  (+ optional ULA).
# This side's role (iran|foreign) decides local vs peer inner IP.

t_register gre
feature "tunnel.gre" free

t_gre_meta() {
  echo "id=gre"
  echo "title=GRE  (kernel L3)"
  echo "tier=free"
  echo "layer=l3"
  echo "roles=iran foreign"
  echo "cores="
}

_gre_if()   { printf 'mgre-%s' "$1"; }
_gre_inner_local() { local n="$1" role="$2"; [[ "$role" == iran ]] && echo "10.77.$n.1" || echo "10.77.$n.2"; }
_gre_inner_peer()  { local n="$1" role="$2"; [[ "$role" == iran ]] && echo "10.77.$n.2" || echo "10.77.$n.1"; }

t_gre_wizard() {  # <role> <level>
  local role="$1" level="$2" n
  ST[peer_ip]="$(ui_ask "Peer (other server) public IP" "${ST[peer_ip]:-}")"
  sys_is_ip4 "${ST[peer_ip]}" || sys_is_host "${ST[peer_ip]}" || { ui_err "invalid peer IP/host"; return 1; }
  ST[my_ip]="$(ui_ask "This server's public IP" "$(sys_public_ip4)")"

  # variant
  echo; ui_info "GRE variant:"
  ui_item 1 "gre" "plain GRE over IPv4 (proto 47)"
  ui_item 2 "gre+fou" "GRE-in-UDP (recommended where proto 47 is blocked)"
  ui_item 3 "ip6gre" "native IPv6 (needs public IPv6 both sides)"
  local gv; gv="$(ui_ask 'variant' "${ST[variant]:-2}")"
  case "$gv" in 1) ST[variant]=gre;; 3) ST[variant]=ip6gre;; *) ST[variant]=fou;; esac
  if [[ "${ST[variant]}" == fou ]]; then
    ST[fou_port]="${ST[fou_port]:-$(sys_rand_port 20000 29999)}"
  fi

  # usage mode
  echo; ui_info "Usage mode:"
  ui_item 1 "socks" "SOCKS5 on foreign inner IP (recommended for x-ui outbound)"
  ui_item 2 "forward" "port-forward Iran public ports -> foreign target"
  ui_item 3 "l3" "full L3 exit (policy-routed egress via foreign)"
  local um; um="$(ui_ask 'mode' "${ST[mode]:-1}")"
  case "$um" in 2) ST[mode]=forward;; 3) ST[mode]=l3;; *) ST[mode]=socks;; esac

  # allocate inner subnet + key (only if not already set, e.g. edit)
  if [[ -z "${ST[inner_n]:-}" ]]; then
    n="$(pool_inner_subnet)" || { ui_err "no free inner subnet"; return 1; }
    ST[inner_n]="$n"
  fi
  [[ -z "${ST[key]:-}" ]] && ST[key]="$(pool_gre_key)"
  ST[inner_local]="$(_gre_inner_local "${ST[inner_n]}" "$role")"
  ST[inner_peer]="$(_gre_inner_peer  "${ST[inner_n]}" "$role")"

  # mode-specific params
  case "${ST[mode]}" in
    socks)
      [[ -z "${ST[socks_port]:-}" ]] && ST[socks_port]="$(sys_rand_port 10800 10999)"
      [[ -z "${ST[socks_user]:-}" ]] && ST[socks_user]="mili"
      [[ -z "${ST[socks_pass]:-}" ]] && ST[socks_pass]="$(sys_rand_token 18)" ;;
    forward)
      ST[fwd]="$(ui_ask 'Forward spec  (lport=rport/proto, comma list)  e.g. 8443=443/tcp,53=53/udp' "${ST[fwd]:-}")" ;;
    l3)
      [[ "$role" == iran ]] && ST[table]="${ST[table]:-$(pool_table_id)}" ;;
  esac

  if [[ "$level" == advanced ]]; then
    ST[mtu]="$(ui_ask 'Tunnel MTU' "${ST[mtu]:-1400}")"
    ST[ttl]="$(ui_ask 'TTL' "${ST[ttl]:-255}")"
  else
    ST[mtu]="${ST[mtu]:-1400}"; ST[ttl]="${ST[ttl]:-255}"
  fi
  return 0
}

# raw interface bring-up (called by mili-l3@ unit via `mili _l3 up <name>`)
t_gre_ifup() {  # <name>
  st_load "$1"
  local name="$1" ifc; ifc="$(_gre_if "$name")"
  run modprobe ip_gre 2>/dev/null || true
  case "${ST[variant]}" in
    fou)
      run modprobe fou 2>/dev/null || true
      run ip fou add port "${ST[fou_port]}" ipproto 47 2>/dev/null || true
      run ip link add "$ifc" type gre local "${ST[my_ip]}" remote "${ST[peer_ip]}" \
        key "${ST[key]}" ttl "${ST[ttl]}" encap fou encap-sport auto encap-dport "${ST[fou_port]}" 2>/dev/null \
        || run ip link add "$ifc" type gre local "${ST[my_ip]}" remote "${ST[peer_ip]}" key "${ST[key]}" ttl "${ST[ttl]}" ;;
    ip6gre)
      run modprobe ip6_gre 2>/dev/null || true
      run ip link add "$ifc" type ip6gre local "${ST[my_ip]}" remote "${ST[peer_ip]}" key "${ST[key]}" ttl "${ST[ttl]}" ;;
    *)
      run ip link add "$ifc" type gre local "${ST[my_ip]}" remote "${ST[peer_ip]}" key "${ST[key]}" ttl "${ST[ttl]}" ;;
  esac
  run ip addr add "${ST[inner_local]}/30" dev "$ifc" 2>/dev/null || true
  run ip link set "$ifc" mtu "${ST[mtu]}" up
  # L3 exit policy routing / masquerade
  if [[ "${ST[mode]}" == l3 ]]; then
    if [[ "${ST[role]}" == foreign ]]; then
      sysctl_enable_forward
      fw_masq "$name" "10.77.${ST[inner_n]}.0/30"
    else
      sysctl_rpfilter_loose "$ifc"
      run ip rule add from "${ST[inner_local]}" table "${ST[table]}" 2>/dev/null || true
      run ip route add default via "${ST[inner_peer]}" dev "$ifc" table "${ST[table]}" 2>/dev/null || true
    fi
  fi
}

t_gre_ifdown() {  # <name>
  st_load "$1"
  local name="$1" ifc; ifc="$(_gre_if "$name")"
  if [[ "${ST[mode]}" == l3 && "${ST[role]}" == iran ]]; then
    run ip rule del from "${ST[inner_local]}" table "${ST[table]}" 2>/dev/null || true
    run ip route flush table "${ST[table]}" 2>/dev/null || true
  fi
  run ip link del "$ifc" 2>/dev/null || true
  [[ "${ST[variant]}" == fou ]] && run ip fou del port "${ST[fou_port]}" 2>/dev/null || true
}

# firewall rules for this tunnel (idempotent; also called by _fw-restore)
t_gre_fw_apply() {  # <name>
  st_load "$1"; local name="$1"
  case "${ST[variant]}" in
    fou) fw_allow "$name" udp "${ST[fou_port]}" "${ST[peer_ip]}"
         fw_ufw_mirror "$name" udp "${ST[fou_port]}" "${ST[peer_ip]}" ;;
    *)   fw_allow_proto "$name" 47 "${ST[peer_ip]}"
         fw_ufw_allow_gre "$name" "${ST[peer_ip]}" ;;
  esac
  fw_mss "$name" "$(_gre_if "$name")" pmtu
  case "${ST[mode]}" in
    socks)
      # SOCKS reachable only across the tunnel (from peer inner IP)
      fw_allow "$name" tcp "${ST[socks_port]}" "${ST[inner_peer]}" ;;
    forward)
      _gre_apply_forwards "$name" ;;
  esac
}

_gre_apply_forwards() {  # <name> : parse ST[fwd] and DNAT to foreign inner IP
  st_load "$1"; local name="$1" spec item lport rport proto
  IFS=',' read -ra items <<<"${ST[fwd]}"
  for item in "${items[@]}"; do
    [[ -z "$item" ]] && continue
    proto="${item##*/}"; item="${item%/*}"
    lport="${item%%=*}"; rport="${item##*=}"
    [[ "$proto" != tcp && "$proto" != udp ]] && proto=tcp
    fw_dnat "$name" "$proto" "$lport" "${ST[inner_peer]}" "$rport"
    fw_allow "$name" "$proto" "$lport"
    fw_ufw_mirror "$name" "$proto" "$lport"
  done
}

t_gre_render() { :; }   # no engine config file; all kernel state

t_gre_up() {  # <name>
  st_load "$1"; local name="$1" unit; unit="mili-l3@$name.service"
  require_root
  t_gre_fw_apply "$name"
  svc_up "$unit"
  # foreign-side SOCKS helper
  if [[ "${ST[mode]}" == socks && "${ST[role]}" == foreign ]]; then
    cores_ensure gost
    socks_render "$name" "${ST[inner_local]}" "${ST[socks_port]}" "${ST[socks_user]}" "${ST[socks_pass]}"
    svc_up "mili-socks@$name.service"
  fi
  # record port claims
  [[ "${ST[variant]}" == fou ]] && ports_claim "$name" udp "${ST[fou_port]}" "0.0.0.0"
  [[ "${ST[mode]}" == socks && "${ST[role]}" == foreign ]] && ports_claim "$name" tcp "${ST[socks_port]}" "${ST[inner_local]}"
}

t_gre_down() {  # <name>
  st_load "$1"; local name="$1"
  svc_down "mili-l3@$name.service"
  [[ "${ST[mode]}" == socks && "${ST[role]}" == foreign ]] && svc_down "mili-socks@$name.service"
  t_gre_ifdown "$name" 2>/dev/null || true
  fw_remove "$name"
}

t_gre_purge() { st_load "$1"; pool_inner_release "${ST[inner_n]}"; pool_meta_release "$1"; }

t_gre_unit() { echo "mili-l3@$1.service"; }

t_gre_health() {  # <name> : ping inner peer across tunnel
  st_load "$1"
  ping -c1 -W2 -I "$(_gre_if "$1")" "${ST[inner_peer]}" >/dev/null 2>&1
}

t_gre_ports() {  # <name> : proto:port:bind list
  st_load "$1"
  [[ "${ST[variant]}" == fou ]] && echo "udp:${ST[fou_port]}:0.0.0.0"
  [[ "${ST[mode]}" == socks ]] && echo "tcp:${ST[socks_port]}:${ST[inner_local]}"
}

t_gre_info() {  # <name>
  st_load "$1"
  ui_kv "variant" "${ST[variant]}"
  ui_kv "mode"    "${ST[mode]}"
  ui_kv "role"    "${ST[role]}"
  ui_kv "peer"    "${ST[peer_ip]}"
  ui_kv "inner"   "${ST[inner_local]} <-> ${ST[inner_peer]} (/30)"
  ui_kv "mtu/ttl" "${ST[mtu]}/${ST[ttl]}"
  [[ "${ST[variant]}" == fou ]] && ui_kv "fou udp" "${ST[fou_port]}"
  case "${ST[mode]}" in
    socks)   ui_kv "socks" "${ST[inner_local]}:${ST[socks_port]} (user ${ST[socks_user]})" ;;
    forward) ui_kv "forward" "${ST[fwd]}" ;;
    l3)      ui_kv "exit" "via foreign MASQUERADE" ;;
  esac
}

t_gre_xui() {  # <name> : 3x-ui outbound helper
  st_load "$1"; local name="$1"
  case "${ST[mode]}" in
    socks)
      # Iran points x-ui at the FOREIGN inner IP (reachable over tunnel)
      local addr; [[ "${ST[role]}" == iran ]] && addr="${ST[inner_peer]}" || addr="${ST[inner_local]}"
      xui_help_socks "$name" "$addr" "${ST[socks_port]}" "${ST[socks_user]}" "${ST[socks_pass]}" ;;
    l3)
      ui_head "Use tunnel '$name' with 3x-ui (L3 exit)"
      ui_info "Freedom outbound bound to this server's inner IP:"
      xui_freedom_json "mili-$name" "${ST[inner_local]}"
      ui_note "Then route selected inbounds to outbound 'mili-$name'." ;;
    forward)
      ui_head "Use tunnel '$name' with 3x-ui (port forward)"
      ui_note "Iran public ports ${ST[fwd]} reach the foreign target over GRE."
      ui_note "Point your subscription Host/address at this Iran server's IP + the local port." ;;
  esac
}

t_gre_test() {  # <name>
  st_load "$1"
  ui_info "ping inner peer ${ST[inner_peer]} over $(_gre_if "$1")"
  if t_gre_health "$1"; then ui_ok "tunnel reachable"; else ui_err "no reply over tunnel"; fi
  if [[ "${ST[mode]}" == socks ]]; then
    local addr; [[ "${ST[role]}" == iran ]] && addr="${ST[inner_peer]}" || addr="${ST[inner_local]}"
    doctor_socks "$addr" "${ST[socks_port]}" "${ST[socks_user]}" "${ST[socks_pass]}"
  fi
}

# ---- pairing ---------------------------------------------------------------
t_gre_pair_export() {  # <name> : emit payload for the OTHER side
  st_load "$1"
  local peerrole; [[ "${ST[role]}" == iran ]] && peerrole=foreign || peerrole=iran
  cat <<EOF
type=gre
name=${ST[name]}
role=$peerrole
variant=${ST[variant]}
mode=${ST[mode]}
inner_n=${ST[inner_n]}
key=${ST[key]}
mtu=${ST[mtu]}
ttl=${ST[ttl]}
fou_port=${ST[fou_port]:-}
my_ip=${ST[peer_ip]}
peer_ip=${ST[my_ip]}
socks_port=${ST[socks_port]:-}
socks_user=${ST[socks_user]:-}
socks_pass=${ST[socks_pass]:-}
fwd=${ST[fwd]:-}
EOF
}

t_gre_pair_import() {  # <payload>
  local p="$1" name role n
  name="$(pair_field "$p" name)"; role="$(pair_field "$p" role)"
  n="$(pair_field "$p" inner_n)"
  ST=(); ST[name]="$name"; ST[type]=gre; ST[role]="$role"
  ST[variant]="$(pair_field "$p" variant)"; ST[mode]="$(pair_field "$p" mode)"
  ST[inner_n]="$n"; ST[key]="$(pair_field "$p" key)"
  ST[mtu]="$(pair_field "$p" mtu)"; ST[ttl]="$(pair_field "$p" ttl)"
  ST[fou_port]="$(pair_field "$p" fou_port)"
  ST[my_ip]="$(pair_field "$p" my_ip)"; ST[peer_ip]="$(pair_field "$p" peer_ip)"
  ST[inner_local]="$(_gre_inner_local "$n" "$role")"
  ST[inner_peer]="$(_gre_inner_peer  "$n" "$role")"
  ST[socks_port]="$(pair_field "$p" socks_port)"
  ST[socks_user]="$(pair_field "$p" socks_user)"
  ST[socks_pass]="$(pair_field "$p" socks_pass)"
  ST[fwd]="$(pair_field "$p" fwd)"
  [[ "${ST[mode]}" == l3 && "$role" == iran ]] && ST[table]="$(pool_table_id)"
  # re-check port availability on this side
  if [[ "${ST[variant]}" == fou ]] && ports_in_use "${ST[fou_port]}"; then
    ui_warn "fou port ${ST[fou_port]} busy here; you must remap and send a patch code"
  fi
  pool_inner_claim "$n" "$name"
  st_save
  t_gre_render "$name"; t_gre_up "$name"
  st_set state up; st_save
}
