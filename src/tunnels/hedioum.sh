# shellcheck shell=bash
# mili :: tunnels/hedioum.sh - hedioum/Hedioum-Pool-Tunnel (mimic SOCKS pool).
#
# NATIVE PAIRING: mili mirrors hedioum's own setup steps and moves ONLY hedioum's
# own v2 pairing token between servers (no mili pairing code).
#   foreign (egress): hedioum-tunnel setup-foreign ...           -> v2 token
#   iran    (hub)   : hedioum-tunnel add-node --alias <name> --token <v2> ...
# hedioum runs its OWN hedioum.service and keeps ONE config per server in
# /etc/hedioum/hedioum.json (role foreign OR iran; an iran hub holds many nodes,
# keyed by alias = the mili tunnel name).
#
# Facts pinned to hedioum v0.11.0 (see cores.sh):
#  - v2 token = base64url_nopad(JSON {v:2, ip, auth(32hex), persona?, sni?, eps{mimic:port}})
#  - setup-*/add-node exit 1 on any error and restart hedioum.service themselves
#  - persona sets are deterministic from the auth key (ported below for preview)

t_register hedioum
feature "tunnel.hedioum" free

HED_CFG="${HED_CFG:-/etc/hedioum/hedioum.json}"
HED_UNIT="hedioum.service"
HED_MIMICS=(ssh tls https-alt smtp imap smtps imaps directadmin docker grafana prometheus cpanel whm webmail postgres mysql)
HED_PERSONAS=(cpanel directadmin devops)

# ============================================================================
# pure helpers (unit-tested in tests/unit/hedioum.bats)
# ============================================================================

_hed_is_hex32() { [[ "$1" =~ ^[A-Fa-f0-9]{32}$ ]]; }
_hed_is_mimic() { [[ " ${HED_MIMICS[*]} " == *" $1 "* ]]; }

_hed_mimic_default_port() {  # <mimic>
  case "$1" in
    ssh) echo 22 ;; tls) echo 443 ;; https-alt) echo 8443 ;; smtp) echo 587 ;;
    imap) echo 143 ;; smtps) echo 465 ;; imaps) echo 993 ;; directadmin) echo 2222 ;;
    docker) echo 5000 ;; grafana) echo 3000 ;; prometheus) echo 9090 ;; cpanel) echo 2083 ;;
    whm) echo 2087 ;; webmail) echo 2096 ;; postgres) echo 5432 ;; mysql) echo 3306 ;;
    *) return 1 ;;
  esac
}
# setup-foreign flag that sets a mimic's public port
_hed_mimic_port_flag() { [[ "$1" == ssh ]] && echo "--listen-port" || echo "--$1-port"; }
# ST key holding a per-mimic port override (state keys can't contain '-')
_hed_port_key() { printf 'port_%s' "${1//-/_}"; }

# ---- hedioum.json readers (Go MarshalIndent layout: top keys at 2 spaces) ----
_hed_cfg_get() {  # <key> [file] -> top-level scalar value
  local f="${2:-$HED_CFG}"
  [[ -r "$f" ]] || return 1
  awk -v k="$1" '
    $0 ~ "^  \"" k "\": " {
      v = $0; sub(/^[^:]*: /, "", v); sub(/,$/, "", v); gsub(/^"|"$/, "", v); print v; exit
    }' "$f"
}
_hed_cfg_role() { _hed_cfg_get role "${1:-$HED_CFG}" 2>/dev/null; }

_hed_cfg_mimics() {  # [file] -> "type port" per configured foreign mimic
  local f="${1:-$HED_CFG}" out
  [[ -r "$f" ]] || return 1
  out="$(awk '
    /^  "mimics": \[/ { m = 1; next }
    m && /^  \]/      { m = 0 }
    m && /^      "type": / { t = $0; sub(/^[^:]*: "/, "", t); sub(/".*$/, "", t) }
    m && /^      "port": / { p = $0; sub(/^[^:]*: /, "", p); sub(/,$/, "", p); if (t != "") print t, p; t = "" }
  ' "$f")"
  if [[ -z "$out" && "$(_hed_cfg_role "$f")" == foreign ]]; then
    # legacy config without mimics: hedioum synthesizes one SSH listener
    local lp; lp="$(_hed_cfg_get foreign_listen_port "$f")"
    out="ssh ${lp:-22}"
  fi
  [[ -n "$out" ]] && printf '%s\n' "$out"
}

_hed_cfg_sni() {  # [file] -> first mimic server_name, else domain (as setup-foreign does)
  local f="${1:-$HED_CFG}" s
  s="$(awk '
    /^  "mimics": \[/ { m = 1; next }
    m && /^  \]/      { m = 0 }
    m && /"server_name": / { v = $0; sub(/^[^:]*: "/, "", v); sub(/".*$/, "", v); if (v != "") { print v; exit } }
  ' "$f" 2>/dev/null)"
  [[ -z "$s" ]] && s="$(_hed_cfg_get domain "$f")"
  printf '%s' "$s"
}

_hed_cfg_nodes() {  # [file] -> one hub node alias per line
  local f="${1:-$HED_CFG}"
  [[ -r "$f" ]] || return 0
  awk '
    /^  "foreign_nodes": \[/ { m = 1; next }
    m && /^  \]/             { m = 0 }
    m && /^      "alias": /  { v = $0; sub(/^[^:]*: "/, "", v); sub(/",?$/, "", v); print v }
  ' "$f"
}
_hed_cfg_has_node()   { _hed_cfg_nodes "${2:-$HED_CFG}" | grep -qxF -- "$1"; }
_hed_cfg_node_count() { _hed_cfg_nodes "${1:-$HED_CFG}" | grep -c . ; }

# ---- v2 pairing token ------------------------------------------------------
# _hed_token_decode <str>
#   0 = valid v2  -> sets HT_IP HT_AUTH HT_PERSONA HT_SNI HT_EPS("type:port ...")
#   2 = legacy v1 bare 32-hex auth key (HT_AUTH set)
#   1 = invalid  -> HT_ERR holds hedioum's own wording
_hed_token_decode() {
  local s json v eps e port
  s="$(printf '%s' "$1" | tr -d '[:space:]')"
  HT_IP='' HT_AUTH='' HT_PERSONA='' HT_SNI='' HT_EPS='' HT_ERR=''
  [[ -z "$s" ]] && { HT_ERR="empty token"; return 1; }
  if _hed_is_hex32 "$s"; then HT_AUTH="$s"; return 2; fi
  [[ "$s" =~ ^[A-Za-z0-9_+/=-]+$ ]] && json="$(_b64url_dec "$s")"
  if [[ "$json" != \{* ]]; then
    HT_ERR="token is neither a v1 hex token nor a valid v2 pairing token"; return 1
  fi
  v="$(printf '%s' "$json" | sed -n 's/.*"v":\([0-9][0-9]*\).*/\1/p')"
  if [[ "$v" != 2 ]]; then
    HT_ERR="unsupported pairing token version ${v:-?} (want 2)"; return 1
  fi
  HT_IP="$(printf '%s' "$json"      | sed -n 's/.*"ip":"\([^"]*\)".*/\1/p')"
  HT_AUTH="$(printf '%s' "$json"    | sed -n 's/.*"auth":"\([^"]*\)".*/\1/p')"
  HT_PERSONA="$(printf '%s' "$json" | sed -n 's/.*"persona":"\([^"]*\)".*/\1/p')"
  HT_SNI="$(printf '%s' "$json"     | sed -n 's/.*"sni":"\([^"]*\)".*/\1/p')"
  eps="$(printf '%s' "$json"        | sed -n 's/.*"eps":{\([^}]*\)}.*/\1/p')"
  HT_EPS="$(printf '%s' "$eps" | tr ',' '\n' | sed -n 's/^"\([a-z-]*\)":\([0-9-]*\)$/\1:\2/p' | paste -sd' ' -)"
  _hed_is_hex32 "$HT_AUTH" || { HT_ERR="pairing token has an invalid auth key"; return 1; }
  [[ -n "$HT_IP" ]]        || { HT_ERR="pairing token has no exit IP"; return 1; }
  [[ -n "$HT_EPS" ]]       || { HT_ERR="pairing token has no endpoints"; return 1; }
  for e in $HT_EPS; do
    port="${e#*:}"
    if ! [[ "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
      HT_ERR="pairing token endpoint \"${e%%:*}\" has invalid port $port"; return 1
    fi
  done
  return 0
}

_hed_eps_count() { local -a a=($1); printf '%s' "${#a[@]}"; }
_hed_eps_pretty() { printf '%s' "$1" | sed 's/ /, /g'; }

# _hed_token_encode <ip> <auth> <persona> <sni> <eps "type:port ...">
# byte-identical to Go json.Marshal(pairing.Token) + base64.RawURLEncoding
_hed_token_encode() {
  local ip="$1" auth="$2" persona="$3" sni="$4" eps="$5" json body='' e
  for e in $(printf '%s\n' $eps | LC_ALL=C sort -t: -k1,1); do
    [[ -n "$body" ]] && body+=','
    body+="\"${e%%:*}\":${e#*:}"
  done
  json="{\"v\":2,\"ip\":\"$ip\",\"auth\":\"$auth\""
  [[ -n "$persona" ]] && json+=",\"persona\":\"$persona\""
  [[ -n "$sni" ]] && json+=",\"sni\":\"$sni\""
  json+=",\"eps\":{$body}}"
  printf '%s' "$json" | _b64url_enc
}

# _hed_token_build <exit-ip> [file] : the token for the foreign config on disk
_hed_token_build() {
  local ip="$1" f="${2:-$HED_CFG}" auth persona sni eps
  [[ -n "$ip" && "$(_hed_cfg_role "$f")" == foreign ]] || return 1
  auth="$(_hed_cfg_get auth_token "$f")"
  persona="$(_hed_cfg_get persona "$f")"
  sni="$(_hed_cfg_sni "$f")"
  eps="$(_hed_cfg_mimics "$f" | awk '{printf "%s%s:%s", (NR>1?" ":""), $1, $2}')"
  [[ -n "$auth" && -n "$eps" ]] || return 1
  _hed_token_encode "$ip" "$auth" "$persona" "$sni" "$eps"
}

# hedioum's own printed token, if present in setup-foreign output (auth must match)
_hed_token_from_output() {  # <file> <auth>
  local line
  while IFS= read -r line; do
    line="$(printf '%s' "$line" | sed -E $'s/\x1b\\[[0-9;]*m//g' | tr -d '[:space:]')"
    [[ "$line" =~ ^[A-Za-z0-9_-]{40,}$ ]] || continue
    _hed_token_decode "$line" && [[ "$HT_AUTH" == "$2" ]] && { printf '%s' "$line"; return 0; }
  done <"$1"
  return 1
}

# ---- persona (port of internal/persona/persona.go) --------------------------
_hed_sha256() { sha256sum | awk '{print $1}'; }

_hed_persona_auto() {  # <seed>
  local h; h="$(printf 'hedioum-persona\0%s' "$1" | _hed_sha256)"
  printf '%s' "${HED_PERSONAS[$(( 16#${h:0:2} % 3 ))]}"
}

_hed_persona_resolve() {  # <name> <seed> -> comma list, ssh first (= persona.Resolve)
  local name="$1" seed="$2" core pool m k sorted
  case "$name" in
    cpanel)      core="tls cpanel whm webmail"
                 pool="https-alt smtp smtps imaps imap postgres mysql docker" ;;
    directadmin) core="tls directadmin"
                 pool="https-alt smtp smtps imaps imap postgres mysql docker grafana" ;;
    devops)      core="tls https-alt docker grafana prometheus"
                 pool="postgres mysql smtp smtps imap imaps" ;;
    *) return 1 ;;
  esac
  local -a set=(ssh $core)
  sorted="$(for m in $pool; do
              k="$(printf 'hedioum-fill\0%s\0%s' "$seed" "$m" | _hed_sha256)"
              printf '%s %s\n' "${k:0:16}" "$m"
            done | LC_ALL=C sort -k1,1 -k2,2 | awk '{print $2}')"
  for m in $sorted; do
    (( ${#set[@]} - 1 >= 9 )) && break
    [[ " ${set[*]} " == *" $m "* ]] || set+=("$m")
  done
  (( ${#set[@]} - 1 == 9 )) || return 1
  local IFS=,; printf '%s' "${set[*]}"
}

# "all" or a comma list -> validated canonical comma list (on error: prints the reason, rc 1)
_hed_expand_mimics() {  # <spec>
  local spec="${1// /}" m out=()
  if [[ "$spec" == all ]]; then local IFS=,; printf '%s' "${HED_MIMICS[*]}"; return 0; fi
  for m in ${spec//,/ }; do
    _hed_is_mimic "$m" || { printf 'unknown mimic "%s" (want one of %s|all)' "$m" "$(IFS='|'; echo "${HED_MIMICS[*]}")"; return 1; }
    [[ " ${out[*]} " == *" $m "* ]] || out+=("$m")
  done
  (( ${#out[@]} )) || { printf 'no mimics selected'; return 1; }
  local IFS=,; printf '%s' "${out[*]}"
}

# ============================================================================
# system helpers
# ============================================================================
_hed_bin() { cores_bin_ok hedioum-tunnel && { cores_path hedioum-tunnel; return 0; }; return 1; }

# binary + hedioum's own systemd unit (idempotent: refreshes the /usr/local/bin copy)
_hed_install() {
  cores_ensure hedioum || { ui_err "could not install the hedioum core"; return 1; }
  local b out
  b="$(_hed_bin)" || { ui_err "hedioum binary missing"; return 1; }
  out="$(run "$b" install 2>&1)" || { ui_err "hedioum-tunnel install failed:"; printf '%s\n' "$out" | tail -n 5 | sed 's/^/    /'; return 1; }
}

# mili hedioum tunnels on this box, optionally by role (reads files; never clobbers ST)
_hed_tunnels() {  # [role] [exclude-name]
  local f n
  for f in "$MILI_TUNDIR"/*.conf; do
    [[ -f "$f" ]] || continue
    grep -qx 'type=hedioum' "$f" || continue
    [[ -n "${1:-}" ]] && ! grep -qx "role=$1" "$f" && continue
    n="${f##*/}"; n="${n%.conf}"
    [[ "$n" == "${2:-}" ]] && continue
    printf '%s\n' "$n"
  done
}

_hed_sshd_port() { ports_sshd 2>/dev/null | head -n1; }

# the operator's SSH session is proxied by hedioum's SSH mimic (sshd sees 127.0.0.1)
_hed_via_mimic() { [[ "${SSH_CONNECTION:-}" == 127.0.0.1\ * || "${SSH_CONNECTION:-}" == ::1\ * ]]; }

# run a root shell snippet detached from this session after <delay>s (survives a dropped SSH)
_hed_detached() {  # <delay> <script>
  local delay="$1" script="$2"
  if [[ "${MILI_DRYRUN:-0}" == 1 ]]; then printf '%s[dry]%s detached(%ss): %s\n' "${C_GRY:-}" "${C_RST:-}" "$delay" "$script" >&2; return 0; fi
  if sys_has systemd-run; then
    systemd-run --quiet --collect --unit "mili-hedioum-$(date +%s)-$RANDOM" \
      --on-active="${delay}s" /bin/bash -c "$script" >/dev/null 2>&1 && return 0
  fi
  setsid /bin/bash -c "sleep $delay; $script" </dev/null >/dev/null 2>&1 &
}

# systemctl on hedioum.service; detached when it would cut the operator's session
_hed_svc() {  # <systemctl args...>
  if [[ "${ST[role]:-}" == foreign ]] && _hed_via_mimic; then
    ui_warn "you are connected through the hedioum SSH mimic: this session drops in ~5s."
    ui_note "reconnect the same way after ~10s (or straight to OpenSSH: ssh -p ${ST[decoy_port]:-2022} ...)."
    _hed_detached 5 "systemctl $*"
    return 0
  fi
  run systemctl "$@" >/dev/null 2>&1
}

_hed_wait_active() {  # [seconds]
  local i
  for (( i = 0; i < ${1:-8}; i++ )); do svc_active "$HED_UNIT" && return 0; sleep 1; done
  svc_active "$HED_UNIT"
}

_hed_alias() { printf '%s' "${ST[alias]:-${ST[name]}}"; }

# planned foreign endpoints from the wizard answers ("type:port ...")
_hed_plan_eps() {
  local m p k out=()
  for m in ${ST[mimics]//,/ }; do
    if [[ "$m" == ssh ]]; then p="${ST[ssh_port]:-22}"
    else k="$(_hed_port_key "$m")"; p="${ST[$k]:-$(_hed_mimic_default_port "$m")}"; fi
    out+=("$m:$p")
  done
  printf '%s' "${out[*]}"
}

# foreign token: the stored one while it still matches the config, else rebuilt
_hed_foreign_token() {
  local built stored="${ST[token]:-}" bip beps bauth ip
  ip="${ST[public_ip]:-${ST[my_ip]:-}}"            # my_ip = states from before native pairing
  [[ -z "$ip" ]] && ip="$(sys_public_ip4)"
  [[ -z "${ST[public_ip]:-}" && -n "$ip" ]] && ST[public_ip]="$ip"
  built="$(_hed_token_build "$ip" 2>/dev/null)"
  if [[ -n "$built" ]]; then
    if [[ -n "$stored" ]] && _hed_token_decode "$built"; then
      bip="$HT_IP" beps="$HT_EPS" bauth="$HT_AUTH"
      if _hed_token_decode "$stored" && [[ "$HT_IP" == "$bip" && "$HT_EPS" == "$beps" && "$HT_AUTH" == "$bauth" ]]; then
        printf '%s' "$stored"; return 0
      fi
    fi
    if [[ "$built" != "$stored" ]]; then ST[token]="$built"; st_save; fi
    printf '%s' "$built"; return 0
  fi
  # no config readable: only hand out a stored token that is a real v2 token
  if [[ -n "$stored" ]] && _hed_token_decode "$stored"; then printf '%s' "$stored"; return 0; fi
  return 1
}

# ============================================================================
# meta
# ============================================================================
t_hedioum_meta() {
  echo "id=hedioum"
  echo "title=Hedioum  (mimic SOCKS pool)"
  echo "tier=free"
  echo "layer=socks"
  echo "roles=foreign iran"
  echo "primary=foreign"
  echo "twoway=no"
  echo "cores=hedioum"
  echo "pairing=native"                 # hedioum's own token is the only pairing artifact
  echo "handoff_label=Show Hedioum token"
  echo "first_hint=Set up the FOREIGN server first: it prints the Hedioum token you paste on Iran."
}

t_hedioum_unit() { echo "$HED_UNIT"; }

# a pasted string that hedioum's hub accepts -> the role that consumes it
t_hedioum_accepts_token() {  # <str>
  local rc; _hed_token_decode "$1"; rc=$?
  (( rc == 0 || rc == 2 )) && { echo iran; return 0; }
  return 1
}

# ============================================================================
# wizard (mirrors hedioum's own setup wizard, question for question)
# ============================================================================
t_hedioum_wizard() {  # <role> [level]
  if [[ "$1" == foreign ]]; then _hed_wizard_foreign; else _hed_wizard_iran; fi
}

_hed_wizard_foreign() {
  local crole other
  crole="$(_hed_cfg_role)"
  if [[ "$crole" == iran ]]; then
    ui_err "this server is already a hedioum IRAN hub — one server can't be both roles."; return 1
  fi
  other="$(_hed_tunnels foreign "${ST[name]}" | head -n1)"
  if [[ -n "$other" ]]; then
    ui_err "hedioum foreign already runs here as tunnel '$other' (one per server). Edit that one."; return 1
  fi

  # hedioum already configured outside mili -> adopt it or reconfigure it
  if [[ -z "${ST[auth]:-}" && "$crole" == foreign ]]; then
    ui_info "hedioum is already set up as FOREIGN on this server."
    ui_select 0 $'Use existing setup\tkeep its token — Iran hubs stay paired' \
                $'Reconfigure\tanswer the setup questions (same auth key)'
    case "$SEL" in
      1) ST[adopt]=yes
         ST[auth]="$(_hed_cfg_get auth_token)"
         ST[persona]="$(_hed_cfg_get persona)"
         ST[mimics]="$(_hed_cfg_mimics | awk '{printf "%s%s", (NR>1?",":""), $1}')"
         ST[ssh_port]="$(_hed_cfg_mimics | awk '$1=="ssh"{print $2}')"
         ST[decoy_port]="$(_hed_cfg_get decoy_port)"
         ST[domain]="$(_hed_cfg_get domain)"
         ST[egress_mode]="$(_hed_cfg_get egress_ip_mode)"
         ST[decoy_style]="$(_hed_cfg_get decoy_style)"
         # OpenSSH sitting on the decoy port while the SSH mimic has 22 => it was moved
         if [[ "${ST[ssh_port]:-}" == 22 && "$(_hed_sshd_port)" == "${ST[decoy_port]:-x}" ]]; then
           ST[ssh_moved]=yes; ST[sshd_orig_port]=22
         fi
         _hed_ask_ip
         return 0 ;;
      2) ST[auth]="$(_hed_cfg_get auth_token)" ;;
      *) return 1 ;;
    esac
  fi
  unset 'ST[adopt]'

  # 1) public IP (embedded in the token)
  _hed_ask_ip

  # 2) persona — seeded from the auth key, so mili can show the exact set now
  ST[auth]="${ST[auth]:-$(sys_rand_hex 16)}"
  local pre=0 c set name
  case "${ST[persona_choice]:-auto}" in auto) pre=0 ;; cpanel) pre=1 ;; directadmin) pre=2 ;; devops) pre=3 ;; custom) pre=4 ;; esac
  echo; ui_info "Server persona (shapes the whole on-wire footprint):"
  ui_select "$pre" $'auto\trecommended — coherent persona from the token' \
                   $'cpanel\tcPanel hosting box' $'directadmin\tDirectAdmin hosting box' \
                   $'devops\tdocker / grafana / prometheus box' $'custom\tchoose mimics yourself'
  case "$SEL" in 1) c=auto ;; 2) c=cpanel ;; 3) c=directadmin ;; 4) c=devops ;; 5) c=custom ;; *) return 1 ;; esac
  ST[persona_choice]="$c"
  if [[ "$c" == custom ]]; then
    ui_note "mimics: ${HED_MIMICS[*]}  (or 'all')"
    local r
    while :; do
      set="$(ui_ask 'Mimics (comma list or all)' "${ST[mimics]:-ssh,tls}")"
      if r="$(_hed_expand_mimics "$set")"; then set="$r"; break; fi
      ui_err "$r"
    done
    if [[ ",$set," =~ ,(cpanel|whm|webmail), && ",$set," == *,directadmin,* ]]; then
      ui_warn "incoherent mimic set: cPanel family and DirectAdmin on one host (proceeding anyway)."
    fi
    ST[persona]=''; ST[mimics]="$set"
    ui_ok "Custom mimics: ${set//,/, }"
  else
    name="$c"; [[ "$c" == auto ]] && name="$(_hed_persona_auto "${ST[auth]}")"
    set="$(_hed_persona_resolve "$name" "${ST[auth]}")" || { ui_err "persona $name failed to resolve"; return 1; }
    ST[persona]="$name"; ST[mimics]="$set"
    ui_ok "Persona \"$name\": ${set//,/, }"
  fi

  # 3) SSH mimic (only when ssh is in the set)
  local taken=() lp sshd dp who
  if [[ ",${ST[mimics]}," == *,ssh,* ]]; then
    sshd="$(_hed_sshd_port)"
    while :; do
      lp="$(ui_ask_port 'SSH mimic public port' "${ST[ssh_port]:-22}")"
      if [[ "$lp" == "$sshd" ]]; then
        if ui_confirm "Move OpenSSH off port $lp to free it for the SSH mimic?" y; then
          while :; do
            dp="$(ui_ask_port 'Decoy sshd port (OpenSSH is moved here)' "${ST[decoy_port]:-2022}")"
            if [[ "$dp" == "$lp" ]]; then ui_err "decoy port must differ from $lp"; continue; fi
            if who="$(ports_busy_reason "$dp" "${ST[name]}" hedioum)"; then ui_err "port $dp is busy ($who)"; continue; fi
            break
          done
          ST[move_ssh]=yes; ST[ssh_moved]=yes; ST[sshd_orig_port]="$lp"; ST[decoy_port]="$dp"
          ui_note "OpenSSH moves to $dp; the mimic on $lp forwards real SSH logins there."
          break
        fi
        ui_err "port $lp is OpenSSH's — pick another SSH mimic port (or move OpenSSH)."
        continue
      fi
      if who="$(ports_busy_reason "$lp" "${ST[name]}" hedioum)"; then
        ui_err "port $lp is busy ($who)."; continue
      fi
      # OpenSSH stays put: the mimic's decoy backend IS the real sshd, so probes see real OpenSSH
      ST[move_ssh]=no; ST[decoy_port]="$sshd"
      [[ "$lp" != 22 ]] && ui_warn "SSH mimic on port $lp: it is most convincing on 22."
      break
    done
    ST[ssh_port]="$lp"; taken+=("$lp" "${ST[decoy_port]}")
  else
    ST[move_ssh]=no
  fi

  # 4) every other mimic port must be free (x-ui/xray/nginx often hold 443 etc.)
  local m k p def alt
  for m in ${ST[mimics]//,/ }; do
    [[ "$m" == ssh ]] && continue
    k="$(_hed_port_key "$m")"; def="$(_hed_mimic_default_port "$m")"; p="${ST[$k]:-$def}"
    while :; do
      who=''
      if [[ " ${taken[*]} " == *" $p "* ]]; then who="used by another mimic"
      else who="$(ports_busy_reason "$p" "${ST[name]}" hedioum)" || who=''; fi
      [[ -z "$who" ]] && break
      alt="$(ports_free_public "${taken[@]}")"
      ui_warn "$m mimic port $p is busy ($who)."
      p="$(ui_ask_port "Port for the $m mimic" "$alt")"
    done
    taken+=("$p")
    if [[ "$p" == "$def" ]]; then unset "ST[$k]"; else ST[$k]="$p"; fi
  done

  # 5) IPv6 egress (opt-in, only when this server has IPv6)
  local v6
  ST[egress_mode]="${ST[egress_mode]:-ipv4}"
  if v6="$(sys_public_ip6 2>/dev/null)"; then
    if ui_confirm "Detected IPv6 ($v6). Allow outbound traffic over IPv6 too?" "$([[ "${ST[egress_mode]}" != ipv4 ]] && echo y || echo n)"; then
      ui_select "$([[ "${ST[egress_mode]}" == ipv6 ]] && echo 1 || echo 0)" \
        $'Dual\tprefer IPv4, fall back to IPv6' $'IPv6 only'
      [[ "$SEL" == 2 ]] && ST[egress_mode]=ipv6 || ST[egress_mode]=dual
    else
      ST[egress_mode]=ipv4
    fi
  fi

  # 6) TLS certificate
  echo; ui_info "TLS certificate"
  ui_note "A domain pointed at THIS server gets a real Let's Encrypt cert (much harder"
  ui_note "to fingerprint). Without one everything works with a self-signed cert."
  local d
  while :; do
    d="$(ui_ask "Domain for a real certificate (blank = self-signed${ST[domain]:+, - to clear})" "${ST[domain]:-}")"
    [[ "$d" == - ]] && d=''
    [[ -z "$d" ]] || sys_is_host "$d" || { ui_err "not a valid domain"; continue; }
    break
  done
  ST[domain]="$d"
  if [[ -n "$d" ]]; then
    ST[acme_email]="$(ui_ask "Let's Encrypt account email (optional)" "${ST[acme_email]:-}")"
    if ! getent ahostsv4 "$d" 2>/dev/null | awk '{print $1}' | grep -qx "${ST[public_ip]}"; then
      ui_warn "$d does not resolve to ${ST[public_ip]} yet — the cert is issued once DNS points here."
    fi
  else
    unset 'ST[acme_email]'
    ui_warn "Using a self-signed certificate. A domain is recommended when possible."
  fi

  # 7) web-decoy style
  echo; ui_info "Web-decoy style for unauthorized probes:"
  ui_select "$([[ "${ST[decoy_style]:-apache}" == directadmin ]] && echo 1 || echo 0)" \
    $'apache\tApache default page' $'directadmin\tDirectAdmin hosting box'
  [[ "$SEL" == 2 ]] && ST[decoy_style]=directadmin || ST[decoy_style]=apache
  return 0
}

_hed_ask_ip() {
  local ip
  while :; do
    ip="$(ui_ask 'Confirm server public IPv4' "${ST[public_ip]:-$(sys_public_ip4)}")"
    sys_is_ip4 "$ip" && break
    ui_err "enter this server's public IPv4"
  done
  ST[public_ip]="$ip"
}

_hed_wizard_iran() {
  if [[ "$(_hed_cfg_role)" == foreign ]]; then
    ui_err "this server is a hedioum FOREIGN node — one server can't be both roles."; return 1
  fi
  local tok="${MILI_PREFILL_TOKEN:-}" rc
  MILI_PREFILL_TOKEN=''
  if [[ -z "$tok" && -n "${ST[token]:-}" ]]; then
    ui_confirm "Keep the current pairing token?" y && tok="${ST[token]}"
  fi

  # 1) pairing token (hedioum v2; a legacy bare auth key also works)
  while :; do
    if [[ -z "$tok" ]]; then
      ui_info "Paste the Hedioum pairing token printed on the FOREIGN server."
      tok="$(ui_ask 'Pairing token' '')"
      [[ -z "$tok" ]] && return 1
    fi
    _hed_token_decode "$tok"; rc=$?
    case "$rc" in
      0) ui_ok "Pairing token: ${HT_PERSONA:-custom} persona, $(_hed_eps_count "$HT_EPS") endpoints @ $HT_IP"; break ;;
      2) ui_warn "legacy token (bare auth key): the foreign IP and persona must be given."; break ;;
      *) ui_err "$HT_ERR"; tok='' ;;
    esac
  done
  ST[token]="$(printf '%s' "$tok" | tr -d '[:space:]')"
  if (( rc == 0 )); then
    unset 'ST[legacy]'
    ST[exit_ip]="$HT_IP"; ST[persona]="$HT_PERSONA"; ST[eps]="$HT_EPS"
  else
    ST[legacy]=yes
    local ip pname eps='' m
    while :; do
      ip="$(ui_ask 'Foreign egress IP (IPv4 or IPv6) or hostname' "${ST[exit_ip]:-}")"
      [[ -n "$ip" && "$ip" != *[[:space:]/\\]* ]] && break
      ui_err "not a valid IP or hostname"
    done
    ST[exit_ip]="$ip"
    ui_info "Match the foreign's persona:"
    ui_select 0 $'auto\tfrom the token (foreign used auto)' $'cpanel' $'directadmin' $'devops'
    case "$SEL" in 1) pname="$(_hed_persona_auto "$HT_AUTH")" ;; 2) pname=cpanel ;; 3) pname=directadmin ;; 4) pname=devops ;; *) return 1 ;; esac
    for m in $(_hed_persona_resolve "$pname" "$HT_AUTH" | tr ',' ' '); do
      eps+="${eps:+ }$m:$(_hed_mimic_default_port "$m")"
    done
    ST[persona]="$pname"; ST[eps]="$eps"
    ui_ok "Persona \"$pname\" → $(_hed_eps_count "$eps") endpoints toward $ip"
  fi

  # 2) node alias = tunnel name (must be unique on this hub)
  local editing=0 a
  [[ -n "${ST[socks_port]:-}" ]] && editing=1     # Edit of an existing node
  ST[alias]="${ST[alias]:-${ST[name]}}"
  while (( !editing )) && _hed_cfg_has_node "${ST[alias]}"; do
    ui_warn "this hub already has a node named '${ST[alias]}'."
    a="$(ui_ask 'Node alias' "${ST[name]}$(sys_rand_hex 1)")"
    [[ -n "$a" ]] && ST[alias]="$a"
  done

  # 3) local SOCKS5 port (the 3x-ui outbound target)
  local p who
  while :; do
    p="$(ui_ask_port 'Local SOCKS5 port (for the 3x-ui outbound)' "${ST[socks_port]:-$(ports_alloc_socks "${ST[name]}")}")"
    if [[ "$p" != "${ST[socks_port]:-}" ]] && who="$(ports_who "$p")"; then ui_err "port $p is busy ($who)"; continue; fi
    if who="$(ports_busy_reason "$p" "${ST[name]}" hedioum)"; then ui_err "port $p is busy ($who)"; continue; fi
    break
  done
  ST[socks_port]="$p"

  # 4) connection pool (hedioum defaults)
  ST[min]="$(ui_ask_int 'Min physical connections (warm-up pool)' "${ST[min]:-10}" 1)"
  ST[max]="$(ui_ask_int 'Max physical connections (scale limit)' "${ST[max]:-20}" "${ST[min]}")"
  ST[bw]="$(ui_ask_int 'Bandwidth limit per connection (Mbps)' "${ST[bw]:-8}" 1)"
  ST[jitter]="$(ui_ask_int 'Bandwidth jitter for DPI evasion (Mbps)' "${ST[jitter]:-2}" 0)"

  # 5) optional TUN interface
  if ui_confirm "Also expose this node as a TUN network interface? (advanced; SOCKS stays on)" "$([[ "${ST[tun]:-}" == yes ]] && echo y || echo n)"; then
    ST[tun]=yes
    ST[tun_name]="$(ui_ask 'TUN interface name (blank = auto)' "${ST[tun_name]:-}")"
    ST[tun_addr]="$(ui_ask 'TUN gateway CIDR (blank = auto)' "${ST[tun_addr]:-}")"
    ui_confirm "Run a DNS forwarder on the TUN gateway (:53, resolves through the tunnel)?" "$([[ "${ST[dns]:-}" == yes ]] && echo y || echo n)" && ST[dns]=yes || ST[dns]=no
    ui_confirm "Transparent gateway mode? (forward LAN transit into the tunnel — MikroTik/router)" "$([[ "${ST[gateway]:-}" == yes ]] && echo y || echo n)" && ST[gateway]=yes || ST[gateway]=no
  else
    ST[tun]=no; ST[dns]=no; ST[gateway]=no; unset 'ST[tun_name]' 'ST[tun_addr]'
  fi
  return 0
}

t_hedioum_summary() {
  if [[ "${ST[role]}" == foreign ]]; then
    ui_kv "Role" "Foreign (egress)"
    ui_kv "Public IPv4" "${ST[public_ip]}"
    if [[ "${ST[adopt]:-}" == yes ]]; then
      ui_kv "Setup" "use the existing hedioum config (no changes)"
      return 0
    fi
    ui_kv "Persona" "${ST[persona]:-custom}$([[ "${ST[persona_choice]:-}" == auto ]] && echo ' (auto)')"
    ui_kv "Mimics" "$(_hed_eps_pretty "$(_hed_plan_eps)")"
    if [[ ",${ST[mimics]}," == *,ssh,* ]]; then
      if [[ "${ST[move_ssh]:-}" == yes ]]; then ui_kv "SSH" "mimic :${ST[ssh_port]} · OpenSSH moves to :${ST[decoy_port]}"
      else ui_kv "SSH" "mimic :${ST[ssh_port]} · probes see OpenSSH :${ST[decoy_port]}"; fi
    fi
    ui_kv "Egress" "${ST[egress_mode]:-ipv4}"
    ui_kv "Certificate" "$([[ -n "${ST[domain]:-}" ]] && echo "Let's Encrypt · ${ST[domain]}" || echo self-signed)"
    ui_kv "Web decoy" "${ST[decoy_style]:-apache} · HTTP :80 off (kept free)"
  else
    ui_kv "Role" "Iran (hub)"
    ui_kv "Foreign" "${ST[exit_ip]} · ${ST[persona]:-custom} · $(_hed_eps_count "${ST[eps]}") endpoints"
    ui_kv "Node alias" "$(_hed_alias)"
    ui_kv "SOCKS5" "127.0.0.1:${ST[socks_port]}"
    ui_kv "Pool" "min ${ST[min]} · max ${ST[max]} · ${ST[bw]}±${ST[jitter]} Mbps"
    [[ "${ST[tun]:-}" == yes ]] && ui_kv "TUN" "${ST[tun_name]:-auto} ${ST[tun_addr]:-auto}$([[ "${ST[dns]}" == yes ]] && echo ' +dns')$([[ "${ST[gateway]}" == yes ]] && echo ' +gateway')"
  fi
  return 0
}

# ============================================================================
# provision (create / Edit only) — runs hedioum's own setup commands
# ============================================================================
t_hedioum_provision() {  # <name>   (ST already holds the wizard answers)
  require_root
  # adopting an existing foreign: leave the operator's installed hedioum binary alone
  if [[ "${ST[adopt]:-}" != yes || ! -x /usr/local/bin/hedioum-tunnel ]]; then
    _hed_install || return 1
  fi
  if [[ "${ST[role]}" == foreign ]]; then _hed_provision_foreign "$1"; else _hed_provision_iran "$1"; fi
}

_hed_provision_foreign() {
  local name="$1" b log old="${ST[token]:-}" rc=0 m k e tok out_tok
  b="$(_hed_bin)"; log="$MILI_LOGDIR/hedioum-$name.setup.log"
  mkdir -p "$MILI_LOGDIR" 2>/dev/null || true

  # claim the planned ports up front (state survives a dropped session)
  ports_release "$name"
  for e in $(_hed_plan_eps); do ports_claim "$name" tcp "${e#*:}" 0.0.0.0; done

  if [[ "${ST[adopt]:-}" != yes ]]; then
    local -a a=(setup-foreign --token "${ST[auth]}" --public-ip "${ST[public_ip]}"
                --egress-mode "${ST[egress_mode]:-ipv4}" --decoy-style "${ST[decoy_style]:-apache}"
                --http-decoy-port 0)
    if [[ "${ST[persona_choice]:-}" == custom ]]; then a+=(--mimics "${ST[mimics]}")
    else a+=(--persona "${ST[persona]}"); fi
    if [[ ",${ST[mimics]}," == *,ssh,* ]]; then
      a+=(--listen-port "${ST[ssh_port]}" --decoy-port "${ST[decoy_port]}")
      [[ "${ST[move_ssh]:-}" == yes ]] && a+=(--move-ssh)
    fi
    for m in ${ST[mimics]//,/ }; do
      [[ "$m" == ssh ]] && continue
      k="$(_hed_port_key "$m")"
      [[ -n "${ST[$k]:-}" ]] && a+=("$(_hed_mimic_port_flag "$m")" "${ST[$k]}")
    done
    [[ -n "${ST[domain]:-}" ]] && a+=(--domain "${ST[domain]}")
    [[ -n "${ST[acme_email]:-}" ]] && a+=(--acme-email "${ST[acme_email]}")

    st_save
    if _hed_via_mimic; then
      ui_warn "you are connected through the hedioum SSH mimic: hedioum restarts at the end of"
      ui_note "setup and this session will drop. Reconnect, then open the tunnel → '${ST[name]}' → Show Hedioum token."
    fi
    echo; ui_info "running: hedioum-tunnel ${a[*]/${ST[auth]}/••••}"
    run "$b" "${a[@]}" 2>&1 | tee "$log" | sed 's/^/    /'
    rc=${PIPESTATUS[0]}
    if (( rc != 0 )); then
      ui_err "hedioum setup-foreign failed (exit $rc). Full output: $log"
      [[ "$(_hed_cfg_role)" == foreign ]] || run systemctl disable --now "$HED_UNIT" >/dev/null 2>&1 || true
      return 1
    fi
    [[ "${ST[move_ssh]:-}" == yes ]] && ST[move_ssh]=no   # done once; keep ssh_moved for Delete
  fi
  unset 'ST[adopt]'
  [[ "${MILI_DRYRUN:-0}" == 1 ]] && { st_save; ui_note "dry-run: verification skipped"; return 0; }

  if [[ "$(_hed_cfg_role)" != foreign ]]; then
    ui_err "no foreign config in $HED_CFG after setup — stopping hedioum so it can't crash-loop."
    run systemctl disable --now "$HED_UNIT" >/dev/null 2>&1 || true
    return 1
  fi

  # the pairing token: built from the live config, cross-checked with hedioum's own print
  tok="$(_hed_token_build "${ST[public_ip]}")" || { ui_err "could not build the pairing token from $HED_CFG"; return 1; }
  if [[ -f "$log" ]] && out_tok="$(_hed_token_from_output "$log" "${ST[auth]}")" && [[ "$out_tok" != "$tok" ]]; then
    ui_warn "token differs from the one hedioum printed — using hedioum's."
    tok="$out_tok"
  fi
  ST[token]="$tok"
  st_save

  run systemctl enable "$HED_UNIT" >/dev/null 2>&1 || true
  svc_active "$HED_UNIT" || run systemctl start "$HED_UNIT" >/dev/null 2>&1 || true

  # reconcile port claims with what hedioum actually runs, then verify
  ports_release "$name"
  while read -r m k; do [[ -n "$k" ]] && ports_claim "$name" tcp "$k" 0.0.0.0; done < <(_hed_cfg_mimics)
  _hed_verify_foreign || return 1
  if [[ -n "$old" && "$old" != "$tok" ]]; then
    ui_warn "the pairing token CHANGED — paste the new one on every Iran server using this foreign."
  fi
  return 0
}

_hed_verify_foreign() {
  local m p i who bad=0
  _hed_wait_active 8 || { ui_err "hedioum.service is not running — see: journalctl -u $HED_UNIT -n 30"; return 1; }
  while read -r m p; do
    [[ -z "$p" ]] && continue
    for (( i = 0; i < 6; i++ )); do
      who="$(ports_who "$p")" && [[ "$who" == hedioum* || "$who" == '?' ]] && break
      who=''; sleep 1
    done
    if [[ -n "$who" ]]; then ui_ok "$m mimic listening on :$p"
    else ui_err "$m mimic NOT listening on :$p$(w="$(ports_who "$p")" && echo " (held by $w)")"; bad=1; fi
  done < <(_hed_cfg_mimics)
  if [[ "${ST[ssh_moved]:-}" == yes ]]; then
    if ports_listening "${ST[decoy_port]:-2022}"; then ui_ok "OpenSSH on :${ST[decoy_port]:-2022}"
    else ui_warn "OpenSSH not seen on :${ST[decoy_port]:-2022} — check before closing this session!"; fi
  fi
  (( bad == 0 )) || ui_note "logs: journalctl -u $HED_UNIT -n 50"
  return "$bad"
}

_hed_add_node() {  # uses ST; upserts this node on the hub (add-node == setup-iran)
  local b rc log
  b="$(_hed_bin)" || { ui_err "hedioum binary missing"; return 1; }
  log="$MILI_LOGDIR/hedioum-${ST[name]}.setup.log"; mkdir -p "$MILI_LOGDIR" 2>/dev/null || true
  local -a a=(add-node --alias "$(_hed_alias)" --token "${ST[token]}" --socks-port "${ST[socks_port]}"
              --min "${ST[min]:-10}" --max "${ST[max]:-20}" --bw "${ST[bw]:-8}" --jitter "${ST[jitter]:-2}")
  [[ "${ST[legacy]:-}" == yes ]] && a+=(--target-ip "${ST[exit_ip]}" --persona "${ST[persona]}")
  if [[ "${ST[tun]:-}" == yes ]]; then
    a+=(--tun)
    [[ -n "${ST[tun_name]:-}" ]] && a+=(--tun-name "${ST[tun_name]}")
    [[ -n "${ST[tun_addr]:-}" ]] && a+=(--tun-addr "${ST[tun_addr]}")
    [[ "${ST[dns]:-}" == yes ]] && a+=(--dns)
    [[ "${ST[gateway]:-}" == yes ]] && a+=(--gateway)
  fi
  ui_info "running: hedioum-tunnel add-node --alias $(_hed_alias) --socks-port ${ST[socks_port]} --token ••••"
  run "$b" "${a[@]}" 2>&1 | tee -a "$log" | sed 's/^/    /'
  rc=${PIPESTATUS[0]}
  if (( rc != 0 )); then
    ui_err "hedioum add-node failed (exit $rc). Output: $log"
    [[ "${MILI_DRYRUN:-0}" != 1 ]] && (( $(_hed_cfg_node_count) == 0 )) && run systemctl disable --now "$HED_UNIT" >/dev/null 2>&1
    return 1
  fi
  return 0
}

_hed_provision_iran() {
  local name="$1" i b
  st_save
  _hed_add_node || return 1
  ports_release "$name"
  ports_claim "$name" tcp "${ST[socks_port]}" 127.0.0.1
  fw_loopback_guard "$name" tcp "${ST[socks_port]}"
  [[ "${MILI_DRYRUN:-0}" == 1 ]] && { ui_note "dry-run: verification skipped"; return 0; }
  run systemctl enable "$HED_UNIT" >/dev/null 2>&1 || true
  _hed_wait_active 8 || { ui_err "hedioum.service is not running — see: journalctl -u $HED_UNIT -n 30"; return 1; }
  for (( i = 0; i < 10; i++ )); do ports_listening "${ST[socks_port]}" && break; sleep 1; done
  if ! ports_listening "${ST[socks_port]}"; then
    ui_err "SOCKS 127.0.0.1:${ST[socks_port]} is not listening — see: journalctl -u $HED_UNIT -n 30"; return 1
  fi
  ui_ok "SOCKS5 listening on 127.0.0.1:${ST[socks_port]}"
  echo; ui_info "probing every endpoint of the foreign:"
  b="$(_hed_bin)"
  run "$b" probe --node "$(_hed_alias)" 2>&1 | sed 's/^/    /'
  if (( PIPESTATUS[0] != 0 )); then
    ui_warn "some endpoints are unreachable (blocked port or foreign down) — the pool uses the rest."
  fi
  return 0
}

# ============================================================================
# lifecycle (Start / Stop / Restart / Delete never re-run setup)
# ============================================================================
t_hedioum_up() {  # <name>
  st_load "$1"; local name="$1" i
  require_root
  if [[ "${ST[role]}" == foreign ]]; then
    [[ "$(_hed_cfg_role)" == foreign ]] || { ui_err "hedioum foreign config is missing — use Edit to set it up again."; return 1; }
    run systemctl enable --now "$HED_UNIT" >/dev/null 2>&1 || true
    [[ "${MILI_DRYRUN:-0}" == 1 ]] && return 0
    _hed_wait_active 8
    return
  fi
  [[ "$(_hed_cfg_role)" == foreign ]] && { ui_err "this server is a hedioum FOREIGN node"; return 1; }
  if ! _hed_cfg_has_node "$(_hed_alias)"; then
    _hed_bin >/dev/null || _hed_install || return 1
    _hed_add_node || return 1
  fi
  run systemctl enable --now "$HED_UNIT" >/dev/null 2>&1 || true
  ports_claim "$name" tcp "${ST[socks_port]}" 127.0.0.1
  fw_loopback_guard "$name" tcp "${ST[socks_port]}"
  [[ "${MILI_DRYRUN:-0}" == 1 ]] && return 0
  _hed_wait_active 8 || return 1
  for (( i = 0; i < 10; i++ )); do ports_listening "${ST[socks_port]}" && return 0; sleep 1; done
  ui_err "SOCKS 127.0.0.1:${ST[socks_port]} not listening"; return 1
}

t_hedioum_down() {  # <name>
  st_load "$1"
  if [[ "${ST[role]}" == foreign ]]; then
    [[ "${ST[ssh_moved]:-}" == yes ]] && ui_warn "while hedioum is stopped, SSH only answers on OpenSSH's port ${ST[decoy_port]:-2022}."
    st_set state down; st_save            # saved first: the session may drop below
    _hed_svc disable --now "$HED_UNIT"
    return 0
  fi
  # iran: drop only THIS node; the shared service keeps serving the others
  local b; b="$(_hed_bin 2>/dev/null)"
  if [[ -n "$b" ]] && _hed_cfg_has_node "$(_hed_alias)"; then
    run "$b" remove-node --alias "$(_hed_alias)" >/dev/null 2>&1 || true
  fi
  (( $(_hed_cfg_node_count) == 0 )) && run systemctl disable --now "$HED_UNIT" >/dev/null 2>&1
  fw_remove "$1"
  return 0
}

t_hedioum_restart() {  # <name> : one systemd job (safe even through the SSH mimic)
  st_load "$1"
  if [[ "${ST[role]}" == iran ]] && ! _hed_cfg_has_node "$(_hed_alias)"; then
    t_hedioum_up "$1"; return
  fi
  _hed_svc restart "$HED_UNIT"
  [[ "${MILI_DRYRUN:-0}" == 1 ]] || _hed_via_mimic || _hed_wait_active 8
}

# full teardown for Delete (replaces down+purge)
t_hedioum_remove() {  # <name>
  st_load "$1"
  if [[ "${ST[role]}" != foreign ]]; then t_hedioum_down "$1"; return 0; fi
  local bk="$MILI_ETC/backups"
  mkdir -p "$bk" 2>/dev/null && cp -f "$HED_CFG" "$bk/hedioum-$1-$(date +%s).json" 2>/dev/null \
    && ui_note "hedioum config backed up to $bk/"
  if [[ "${ST[ssh_moved]:-}" == yes && -n "${ST[sshd_orig_port]:-}" ]]; then
    local orig="${ST[sshd_orig_port]}"
    ui_warn "restoring OpenSSH to port $orig (runs detached in ~5s; your SSH session may drop)."
    ui_note "reconnect on :$orig after ~10s. Fallback: ssh -p ${ST[decoy_port]:-2022} ..."
    _hed_detached 5 "systemctl disable --now $HED_UNIT; rm -f $HED_CFG; \
sed -i -E 's/^#?Port[[:space:]]+[0-9]+/Port $orig/' /etc/ssh/sshd_config; \
systemctl restart ssh || systemctl restart sshd"
  else
    _hed_svc disable --now "$HED_UNIT"
    run rm -f "$HED_CFG"
  fi
  return 0
}

t_hedioum_fw_apply() {
  st_load "$1"
  [[ "${ST[role]}" == iran && -n "${ST[socks_port]:-}" ]] && fw_loopback_guard "$1" tcp "${ST[socks_port]}"
}

t_hedioum_health() {  # <name>
  st_load "$1"
  svc_active "$HED_UNIT" || return 1
  if [[ "${ST[role]}" == iran ]]; then
    ports_listening "${ST[socks_port]:-0}"
  else
    local m p
    while read -r m p; do [[ -n "$p" ]] && { ports_listening "$p" || return 1; }; done < <(_hed_cfg_mimics 2>/dev/null)
    return 0
  fi
}

t_hedioum_ports() {
  st_load "$1"
  if [[ "${ST[role]}" == iran ]]; then
    [[ -n "${ST[socks_port]:-}" ]] && echo "tcp:${ST[socks_port]}:127.0.0.1"
  else
    local m p; while read -r m p; do [[ -n "$p" ]] && echo "tcp:$p:0.0.0.0"; done < <(_hed_cfg_mimics 2>/dev/null)
  fi
}

t_hedioum_info() {
  st_load "$1"
  if [[ "${ST[role]}" == foreign ]]; then
    ui_kv "role" "foreign (egress) · native hedioum.service"
    ui_kv "public IPv4" "${ST[public_ip]:-?}"
    # hedioum's config is the source of truth; ST is the fallback before setup ran
    local eps persona domain egress
    eps="$(_hed_cfg_mimics 2>/dev/null | awk '{printf "%s%s:%s", (NR>1?", ":""), $1, $2}')"
    persona="$(_hed_cfg_get persona 2>/dev/null)"; persona="${persona:-${ST[persona]:-}}"
    domain="$(_hed_cfg_get domain 2>/dev/null)";   domain="${domain:-${ST[domain]:-}}"
    egress="$(_hed_cfg_get egress_ip_mode 2>/dev/null)"; egress="${egress:-${ST[egress_mode]:-ipv4}}"
    ui_kv "persona" "${persona:-custom}"
    ui_kv "mimics" "${eps:-$(_hed_eps_pretty "$(_hed_plan_eps)")}"
    if [[ "${ST[ssh_moved]:-}" == yes ]]; then ui_kv "OpenSSH" "moved to :${ST[decoy_port]} (restored on Delete)"; fi
    ui_kv "certificate" "$([[ -n "$domain" ]] && echo "Let's Encrypt · $domain" || echo self-signed)"
    ui_kv "egress" "$egress"
    ui_kv "pairing" "$([[ -n "$(_hed_foreign_token 2>/dev/null)" ]] && echo "token ready → 'Show Hedioum token'" || echo 'no token (Edit to set up)')"
  else
    ui_kv "role" "iran (hub) · node '$(_hed_alias)'"
    ui_kv "foreign" "${ST[exit_ip]:-?} · ${ST[persona]:-custom} · $(_hed_eps_count "${ST[eps]:-}") endpoints"
    ui_kv "pool" "min ${ST[min]:-10} · max ${ST[max]:-20} · ${ST[bw]:-8}±${ST[jitter]:-2} Mbps"
    [[ "${ST[tun]:-}" == yes ]] && ui_kv "TUN" "${ST[tun_name]:-auto} ${ST[tun_addr]:-auto}"
    echo; xui_outbound_box "127.0.0.1" "${ST[socks_port]:-?}" "" ""
  fi
}

t_hedioum_xui() {
  st_load "$1"
  if [[ "${ST[role]}" == iran ]]; then
    xui_help_socks "$1" "127.0.0.1" "${ST[socks_port]}" "" ""
  else
    ui_warn "the Hedioum SOCKS endpoint lives on the IRAN hub (127.0.0.1:<socks-port>)."
  fi
}

t_hedioum_test() {
  st_load "$1"
  local b; b="$(_hed_bin 2>/dev/null)"
  if svc_active "$HED_UNIT"; then ui_ok "hedioum.service active"; else ui_err "hedioum.service not active"; fi
  if [[ "${ST[role]}" == iran ]]; then
    [[ -n "$b" ]] && { run "$b" probe --node "$(_hed_alias)" 2>&1 | sed 's/^/    /' || true; }
    doctor_socks 127.0.0.1 "${ST[socks_port]}" || true
  else
    local m p
    while read -r m p; do
      [[ -z "$p" ]] && continue
      if ports_listening "$p"; then ui_ok "$m :$p listening"; else ui_err "$m :$p NOT listening"; fi
    done < <(_hed_cfg_mimics 2>/dev/null)
    [[ -n "$b" ]] && { run "$b" check-ip 2>&1 | sed 's/^/    /' || true; }
  fi
}

# what to carry to the other server
t_hedioum_handoff() {  # <name>
  st_load "$1"
  if [[ "${ST[role]}" == foreign ]]; then
    local tok
    tok="$(_hed_foreign_token)" || { ui_err "no pairing token yet — the foreign setup did not finish (Edit to retry)."; return 1; }
    pair_present "$tok" "Hedioum pairing token — tunnel '$1'"
    if _hed_token_decode "$tok"; then
      ui_kv "carries" "exit $HT_IP · ${HT_PERSONA:-custom} persona · $(_hed_eps_count "$HT_EPS") endpoints"
    fi
    echo; ui_info "Next, on the IRAN server:"
    ui_note "mili → New tunnel → Hedioum → Iran → paste this token."
    ui_note "(plain hedioum works too: hedioum-tunnel setup-iran --alias NAME --token <token> --socks-port N)"
  else
    ui_head "Hedioum node '$(_hed_alias)' — Iran hub"
    ui_kv "foreign" "${ST[exit_ip]:-?} · ${ST[persona]:-custom} · $(_hed_eps_count "${ST[eps]:-}") endpoints"
    echo; xui_outbound_box "127.0.0.1" "${ST[socks_port]:-?}" "" ""
    ui_note "token in use (copy it to add this foreign to another hub):"
    printf '    %s%s%s\n' "${C_YEL:-}" "${ST[token]}" "${C_RST:-}"
  fi
}
