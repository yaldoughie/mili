# shellcheck shell=bash
# mili :: tunnels/hedioum.sh - hedioum/Hedioum-Pool-Tunnel (SOCKS, TCP+UDP).
# SINGLETON daemon per machine (mili-hedioum.service). Every hedioum tunnel
# record contributes to one regenerated config. Iran = hub dialing foreign
# egress nodes; Foreign = egress node.
#
# Port policy: never ssh / 80 / x-ui / reserved; remap mimic ports to free
# high ports. Detect a standalone hedioum.service -> offer adopt, never both.
#
# roles: iran (hub) | foreign (egress)
# config: /etc/mili/engines/hedioum/{hedioum.json, nodes/<name>.env}

t_register hedioum
feature "tunnel.hedioum" free

MILI_HED_DIR="$MILI_ETC/engines/hedioum"
MILI_HED_NODES="$MILI_HED_DIR/nodes"
MILI_HED_CFG="$MILI_HED_DIR/hedioum.json"

t_hedioum_meta() {
  echo "id=hedioum"
  echo "title=Hedioum  (pool, mimic SOCKS)"
  echo "tier=free"
  echo "layer=socks"
  echo "roles=iran foreign"
  echo "cores=hedioum"
}

# warn + offer adopt if a non-mili hedioum service exists
_hed_check_standalone() {
  if systemctl list-unit-files 2>/dev/null | grep -qE '^hedioum\.service' && ! systemctl cat mili-hedioum.service >/dev/null 2>&1; then
    ui_warn "a standalone 'hedioum.service' exists. mili will NOT run both."
    ui_note "stop/disable it first, or let mili adopt its config manually."
  fi
}

t_hedioum_wizard() {  # <role> <level>
  local role="$1" level="$2"
  _hed_check_standalone
  if [[ "$role" == foreign ]]; then
    ST[egress_port]="$(ui_ask 'Egress listen port (foreign)' "${ST[egress_port]:-$(ports_alloc_public)}")"
    ST[my_ip]="$(ui_ask 'This foreign server public IP' "$(sys_public_ip4)")"
  else
    ST[foreign_ip]="$(ui_ask 'Foreign egress public IP' "${ST[foreign_ip]:-}")"
    ST[egress_port]="$(ui_ask 'Egress port on foreign' "${ST[egress_port]:-}")"
    ST[socks_port]="${ST[socks_port]:-$(ports_alloc_socks)}"
  fi
  [[ -z "${ST[psk]:-}" ]] && ST[psk]="$(sys_rand_token 24)"

  echo; ui_info "profile: default | high-speed"
  ST[profile]="$(ui_ask 'profile' "${ST[profile]:-default}")"
  ST[persona]="$(ui_ask 'persona (mimic identity)' "${ST[persona]:-chrome}")"

  if [[ "$level" == advanced ]]; then
    ST[pool_min]="$(ui_ask 'pool min' "${ST[pool_min]:-2}")"
    ST[pool_max]="$(ui_ask 'pool max' "${ST[pool_max]:-16}")"
    ST[bw_limit]="$(ui_ask 'bandwidth limit (mbit, 0=off)' "${ST[bw_limit]:-0}")"
    ST[domain]="$(ui_ask 'SNI/domain (blank=self-signed)' "${ST[domain]:-}")"
    ST[decoy]="$(ui_ask 'decoy style (none/web)' "${ST[decoy]:-none}")"
    ST[move_ssh]="$(ui_confirm 'allow SSH-port mimic (--move-ssh)? risky' n && echo yes || echo no)"
  else
    ST[pool_min]="${ST[pool_min]:-2}"; ST[pool_max]="${ST[pool_max]:-16}"
    ST[bw_limit]="${ST[bw_limit]:-0}"; ST[decoy]="${ST[decoy]:-none}"; ST[move_ssh]=no
  fi
  ST[mode]=socks
  # port-policy guard on egress port
  if [[ "$role" == foreign ]] && ! _paqet_guard_port "${ST[egress_port]}" 2>/dev/null; then
    ST[egress_port]="$(ports_alloc_public)"
    ui_warn "egress port remapped to free high port ${ST[egress_port]} (avoids x-ui/reserved)"
  fi
  return 0
}

# regenerate the singleton aggregate config from every hedioum record
t_hedioum_regen() {
  run mkdir -p "$MILI_HED_NODES"
  [[ "${MILI_DRYRUN:-0}" == 1 ]] && { ui_info "[dry] regen hedioum aggregate config"; return 0; }
  local self_role='' name
  # determine this machine's role from the first hedioum record
  while read -r name; do
    [[ -z "$name" ]] && continue
    st_load "$name" >/dev/null 2>&1 || continue
    [[ "$(st_get type)" == hedioum ]] || continue
    self_role="$(st_get role)"; break
  done < <(st_list)

  if [[ "$self_role" == foreign ]]; then
    # single egress config (last foreign record wins core listen params)
    local first; first="$(st_list | while read -r n; do st_load "$n" >/dev/null 2>&1 && [[ "$(st_get type)" == hedioum ]] && { echo "$n"; break; }; done)"
    st_load "$first"
    if sys_has jq; then
      jq -n --arg port "${ST[egress_port]}" --arg psk "${ST[psk]}" --arg persona "${ST[persona]}" \
            --arg profile "${ST[profile]}" --arg domain "${ST[domain]:-}" --arg decoy "${ST[decoy]:-none}" \
        '{role:"egress", listen:("0.0.0.0:"+$port), psk:$psk, persona:$persona, profile:$profile, tls:{domain:$domain}, decoy:$decoy}' >"$MILI_HED_CFG"
    else
      cat >"$MILI_HED_CFG" <<EOF
{ "role":"egress","listen":"0.0.0.0:${ST[egress_port]}","psk":"${ST[psk]}","persona":"${ST[persona]}","profile":"${ST[profile]}","decoy":"${ST[decoy]:-none}" }
EOF
    fi
  else
    # hub: one foreign_nodes[] entry + one socks listener per iran record
    local nodes='' socks='' n sep=''
    while read -r n; do
      [[ -z "$n" ]] && continue
      st_load "$n" >/dev/null 2>&1 || continue
      [[ "$(st_get type)" == hedioum ]] || continue
      nodes+="$sep{\"name\":\"$n\",\"remote\":\"$(st_get foreign_ip):$(st_get egress_port)\",\"psk\":\"$(st_get psk)\",\"persona\":\"$(st_get persona)\",\"profile\":\"$(st_get profile)\",\"pool\":{\"min\":$(st_get pool_min 2),\"max\":$(st_get pool_max 16)}}"
      socks+="$sep{\"name\":\"$n\",\"listen\":\"127.0.0.1:$(st_get socks_port)\",\"node\":\"$n\"}"
      sep=','
    done < <(st_list)
    cat >"$MILI_HED_CFG" <<EOF
{ "role":"hub", "socks":[ $socks ], "foreign_nodes":[ $nodes ] }
EOF
  fi
  chmod 600 "$MILI_HED_CFG" 2>/dev/null || true
}

t_hedioum_svc_exec() {  # (singleton) exec the daemon with aggregate config
  local bin; bin="$(cores_path hedioum-tunnel)"
  [[ -x "$bin" ]] || bin="$(cores_path hedioum)"
  [[ -x "$bin" ]] || die "hedioum core not installed"
  [[ -f "$MILI_HED_CFG" ]] || die "hedioum config missing"
  exec "$bin" -c "$MILI_HED_CFG"
}

t_hedioum_render() { t_hedioum_regen; }

t_hedioum_fw_apply() {  # <name>
  st_load "$1"; local name="$1"
  if [[ "${ST[role]}" == foreign ]]; then
    fw_allow "$name" tcp "${ST[egress_port]}"; fw_allow "$name" udp "${ST[egress_port]}"
    fw_ufw_mirror "$name" tcp "${ST[egress_port]}"; fw_ufw_mirror "$name" udp "${ST[egress_port]}"
  else
    fw_loopback_guard "$name" tcp "${ST[socks_port]}"
  fi
}

t_hedioum_up() {  # <name>
  st_load "$1"; local name="$1"
  require_root; cores_ensure hedioum
  _hed_check_standalone
  t_hedioum_fw_apply "$name"
  t_hedioum_regen
  svc_up "mili-hedioum.service"
  run systemctl restart mili-hedioum.service 2>/dev/null || true
  if [[ "${ST[role]}" == foreign ]]; then
    ports_claim "$name" tcp "${ST[egress_port]}" "0.0.0.0"
    ports_claim "$name" udp "${ST[egress_port]}" "0.0.0.0"
  else
    ports_claim "$name" tcp "${ST[socks_port]}" "127.0.0.1"
  fi
}

t_hedioum_down() {  # <name> : remove this record then regen; stop singleton if none left
  st_load "$1"; local name="$1"
  fw_remove "$name"
  # if no other hedioum records remain, stop the singleton
  local remain=0 n
  while read -r n; do
    [[ -z "$n" || "$n" == "$name" ]] && continue
    st_load "$n" >/dev/null 2>&1 && [[ "$(st_get type)" == hedioum ]] && remain=$((remain+1))
  done < <(st_list)
  st_load "$name"
  if (( remain == 0 )); then
    svc_down "mili-hedioum.service" 2>/dev/null || true
  else
    t_hedioum_regen; run systemctl restart mili-hedioum.service 2>/dev/null || true
  fi
}

t_hedioum_purge() { run rm -f "$MILI_HED_NODES/$1.env" 2>/dev/null || true; }

t_hedioum_unit() { echo "mili-hedioum.service"; }

t_hedioum_health() {  # <name>
  st_load "$1"
  svc_active "mili-hedioum.service" || return 1
  if [[ "${ST[role]}" == iran ]]; then
    ss -Hlnt 2>/dev/null | awk '{print $4}' | grep -qE ":${ST[socks_port]}\$"
  fi
}

t_hedioum_ports() {
  st_load "$1"
  if [[ "${ST[role]}" == foreign ]]; then echo "tcp:${ST[egress_port]}:0.0.0.0"; echo "udp:${ST[egress_port]}:0.0.0.0"
  else echo "tcp:${ST[socks_port]}:127.0.0.1"; fi
}

t_hedioum_info() {
  st_load "$1"
  ui_kv "role" "${ST[role]} (singleton daemon)"
  ui_kv "persona/profile" "${ST[persona]} / ${ST[profile]}"
  ui_kv "pool" "${ST[pool_min]}..${ST[pool_max]}"
  if [[ "${ST[role]}" == foreign ]]; then ui_kv "egress" "0.0.0.0:${ST[egress_port]}"
  else ui_kv "dials" "${ST[foreign_ip]}:${ST[egress_port]}"; ui_kv "socks (Iran)" "127.0.0.1:${ST[socks_port]}"; fi
}

t_hedioum_xui() {
  st_load "$1"; local name="$1"
  if [[ "${ST[role]}" == iran ]]; then
    xui_help_socks "$name" "127.0.0.1" "${ST[socks_port]}" "" ""
  else
    ui_warn "Hedioum SOCKS endpoint is on the IRAN hub (127.0.0.1:${ST[socks_port]})."
  fi
}

t_hedioum_test() {
  st_load "$1"
  [[ "${ST[role]}" == iran ]] && doctor_socks 127.0.0.1 "${ST[socks_port]}" || { t_hedioum_health "$1" && ui_ok "hedioum up" || ui_err "down"; }
}

t_hedioum_pair_export() {
  st_load "$1"
  local peerrole; [[ "${ST[role]}" == foreign ]] && peerrole=iran || peerrole=foreign
  cat <<EOF
type=hedioum
name=${ST[name]}
role=$peerrole
egress_port=${ST[egress_port]}
psk=${ST[psk]}
foreign_ip=${ST[my_ip]:-${ST[foreign_ip]:-}}
persona=${ST[persona]}
profile=${ST[profile]}
pool_min=${ST[pool_min]}
pool_max=${ST[pool_max]}
domain=${ST[domain]:-}
decoy=${ST[decoy]:-none}
EOF
}

t_hedioum_pair_import() {
  local p="$1" name role k
  name="$(pair_field "$p" name)"; role="$(pair_field "$p" role)"
  ST=(); ST[name]="$name"; ST[type]=hedioum; ST[role]="$role"; ST[mode]=socks
  for k in egress_port psk foreign_ip persona profile pool_min pool_max domain decoy; do
    ST[$k]="$(pair_field "$p" "$k")"
  done
  [[ "$role" == foreign ]] && ST[my_ip]="$(sys_public_ip4)"
  [[ "$role" == iran ]] && ST[socks_port]="$(ports_alloc_socks)"
  st_save
  t_hedioum_up "$name"; st_set state up; st_save
}
