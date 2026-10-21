#!/usr/bin/env bash
# mili - unified anti-DPI tunnel manager (Iran <-> Foreign), 3x-ui friendly.
# This is the entry point. In a built dist/mili.sh all lib/* and tunnels/* are
# concatenated ABOVE this marker by build.sh; when run from source it sources
# them relative to this file.
#
# @MILI_VERSION@ is replaced by build.sh.
MILI_VERSION="@MILI_VERSION@"
[[ "$MILI_VERSION" == @*@ ]] && MILI_VERSION="0.0.0-dev"

set -o pipefail

# ---- source libs when running from source tree -----------------------------
if [[ -z "${MILI_BUNDLED:-}" ]]; then
  _self="${BASH_SOURCE[0]}"
  _dir="$(cd "$(dirname "$_self")" && pwd)"
  for _f in ui log sys state sysctl ports fw svc features fetch cores pair socks xui watchdog doctor optimize backup; do
    # shellcheck disable=SC1090
    . "$_dir/lib/$_f.sh"
  done
  for _f in "$_dir"/tunnels/*.sh; do [[ -e "$_f" ]] && . "$_f"; done
fi

ui_init
sys_detect_os
sys_detect_arch

# ============================================================================
# generic tunnel lifecycle
# ============================================================================

# bring a tunnel up: render configs, claim resources, firewall, start services.
mili_up() {   # <name>
  local name="$1" type
  st_load "$name" || { ui_err "unknown tunnel: $name"; return 1; }
  type="$(st_get type)"
  fw_init
  t_has "$type" render && t_call "$type" render "$name"
  t_call "$type" up "$name"
  st_set state up; st_save
  ui_ok "tunnel '$name' is up"
}

mili_down() {  # <name>
  local name="$1" type
  st_load "$name" || { ui_err "unknown tunnel: $name"; return 1; }
  type="$(st_get type)"
  t_call "$type" down "$name"
  st_set state down; st_save
  ui_ok "tunnel '$name' stopped"
}

mili_restart() { mili_down "$1" >/dev/null 2>&1; mili_up "$1"; }

mili_delete() {  # <name>
  local name="$1" type
  st_load "$name" || { ui_err "unknown tunnel: $name"; return 1; }
  type="$(st_get type)"
  ui_warn "deleting tunnel '$name' (type $type) - removes its services, firewall rules and config"
  ui_confirm "really delete '$name'?" n || return 1
  t_call "$type" down "$name" >/dev/null 2>&1 || true
  t_has "$type" purge && t_call "$type" purge "$name" >/dev/null 2>&1 || true
  fw_remove "$name"
  ports_release "$name"
  pool_meta_release "$name"
  socks_remove "$name"
  st_delete_file "$name"
  ui_ok "tunnel '$name' deleted"
}

# ============================================================================
# new tunnel wizard (generic driver; per-type wizard fills ST)
# ============================================================================
# short role descriptions (kept narrow so the selector never wraps)
_role_hint() {  # <type> <role>
  case "$2" in
    iran)    printf 'entry · next to 3x-ui' ;;
    foreign) printf 'exit · egress abroad' ;;
    *)       printf '%s' "$2" ;;
  esac
}

mili_new_tunnel() {
  ui_clear; ui_head "New tunnel"
  ui_note "You configure THIS server here. It produces ONE pairing code."
  ui_note "On the OTHER server, run mili → 'Import pairing code' and paste it."
  echo

  # ---- 1) tunnel type (arrow) ----
  local -a order=(gre grefrp backhaul paqet hedioum frp "${MILI_TYPES[@]}")
  local -a types=() labels=(); local t seen='' title tier badge star
  for t in "${order[@]}"; do
    [[ " $seen " == *" $t "* ]] && continue
    declare -F "t_${t}_meta" >/dev/null 2>&1 || continue
    types+=("$t"); seen="$seen $t"
    title="$(t_meta_field "$t" title)"; tier="$(t_meta_field "$t" tier)"
    star=''; case "$t" in gre|grefrp|backhaul|paqet|hedioum) star='★ ';; esac
    badge=''; [[ "$tier" == premium ]] && badge='premium'
    labels+=("$star$title"$'\t'"$badge")
  done
  labels+=("Cancel"$'\t')
  ui_select 0 "${labels[@]}"
  (( SEL==0 || SEL > ${#types[@]} )) && return 0
  local type="${types[$((SEL-1))]}"
  feature_gate "tunnel.$type" || { ui_pause; return 1; }

  # ---- 2) which server is THIS one (arrow) ----
  local roles; roles="$(t_meta_field "$type" roles)"; roles="${roles:-iran foreign}"
  local -a rarr=($roles) rlabels=()
  local r pre=0 idx=0
  for r in "${rarr[@]}"; do
    rlabels+=("$(printf '%s' "${r^}")"$'\t'"$(_role_hint "$type" "$r")")
    [[ "$r" == "${MILI_DEFAULT_ROLE:-}" ]] && pre=$idx
    ((idx++))
  done
  echo; ui_info "Which server is this?"
  ui_select "$pre" "${rlabels[@]}"
  (( SEL==0 )) && return 0
  local role="${rarr[$((SEL-1))]}"

  # ---- pairing direction: only the PRIMARY side generates the code ----
  local primary; primary="$(t_meta_field "$type" primary)"; primary="${primary:-foreign}"
  if [[ "$role" != "$primary" ]]; then
    ui_clear; ui_head "New $(t_meta_field "$type" title) — $(printf '%s' "${role^}") side"
    ui_info "This is the SECOND server. Set up the $primary server first;"
    ui_info "it prints a pairing code. Paste that code here to finish this side."
    echo
    mili_import_code
    return
  fi

  # ---- 3) name ----
  local name
  while :; do
    name="$(ui_ask 'Tunnel name (a-z0-9, max 10)' "$type$(sys_rand_hex 1)")"
    st_valid_name "$name" || { ui_err "invalid name"; continue; }
    st_exists "$name" && { ui_err "name already exists"; continue; }
    break
  done

  # ---- 4) basic/advanced (arrow) ----
  echo; ui_info "Option detail:"
  ui_select 0 $'Basic\trecommended defaults, fewest questions' $'Advanced\texpose transport / tuning knobs'
  local level=basic; [[ "$SEL" == 2 ]] && level=advanced

  # ---- 5) role-specific wizard ----
  ST=(); ST[name]="$name"; ST[type]="$type"; ST[role]="$role"; ST[created]="$(date -Iseconds 2>/dev/null || date)"
  echo; ui_head "Configure $(t_meta_field "$type" title) — $(printf '%s' "${role^}") side"
  t_call "$type" wizard "$role" "$level" || { ui_err "wizard aborted"; ui_pause; return 1; }

  # ---- 6) summary ----
  echo; ui_head "Summary"
  local k
  for k in $(printf '%s\n' "${!ST[@]}" | sort); do
    [[ "$k" =~ (PASS|SECRET|KEY|PSK|TOKEN|pass|secret|psk|token) ]] && { ui_kv "$k" "••••••••"; continue; }
    ui_kv "$k" "${ST[$k]}"
  done
  echo
  ui_confirm "Apply and start this tunnel now?" y || { ui_warn "not applied"; ui_pause; return 1; }

  st_save
  require_root
  fw_init
  svc_install_templates
  t_has "$type" render && t_call "$type" render "$name"
  t_call "$type" up "$name"
  st_set state up; st_save
  ui_ok "tunnel '$name' created and started"

  # ---- 7) pairing code (generator side emits ONE code carrying its own IP) ----
  if t_has "$type" pair_export; then
    echo; mili_export_code "$name"
    local tw; tw="$(t_meta_field "$type" twoway)"
    echo
    if [[ "$tw" == yes ]]; then
      ui_info "Next steps:"
      ui_note "1) On the OTHER server: mili → New tunnel → $(t_meta_field "$type" title) → the other side → paste this code."
      ui_note "2) That server prints a REPLY code. Bring it back here:"
      ui_note "   mili → 'Import pairing code' → paste the reply. Then this tunnel comes up."
    else
      ui_info "Next: on the OTHER server run mili → New tunnel → pick the other side → paste this code. Done."
    fi
  else
    ui_note "This tunnel type needs no pairing."
  fi
  ui_pause
}

# ============================================================================
# pairing
# ============================================================================
mili_export_code() {  # <name>
  local name="$1" type payload pass=''
  st_load "$name" || { ui_err "unknown tunnel"; return 1; }
  type="$(st_get type)"
  t_has "$type" pair_export || { ui_warn "$type has no pairing"; return 1; }
  # hedioum: a code without the token is useless — capture it now if missing
  if [[ "$type" == hedioum && "$(st_get role)" == foreign && -z "$(st_get token)" ]]; then
    ui_warn "no hedioum token stored yet for '$name'."
    ui_note "paste the token hedioum printed during 'setup-foreign' (see Logs)."
    local tk; tk="$(ui_ask 'Hedioum pairing token' '')"
    [[ -z "$tk" ]] && { ui_err "token required to generate a pairing code"; return 1; }
    st_set token "$tk"; st_save
  fi
  payload="$(t_call "$type" pair_export "$name")"
  if ui_confirm "Encrypt the pairing code with a passphrase?" n; then
    pass="$(ui_ask_secret 'Passphrase')"
  fi
  local code; code="$(printf '%s' "$payload" | pair_encode "$pass")"
  pair_present "$code" "Pairing code for tunnel '$name'"
}

mili_import_code() {  # [code]
  ui_head "Import pairing / reply code"
  local code="${1:-}" pass=''
  [[ -z "$code" ]] && code="$(ui_ask 'Paste the code' '')"
  [[ -z "$code" ]] && return 1
  [[ "$code" == mili1e:* ]] && pass="$(ui_ask_secret 'Passphrase')"
  local payload; payload="$(pair_decode "$code" "$pass")" || { ui_pause; return 1; }
  local type name reply
  type="$(pair_field "$payload" type)"
  name="$(pair_field "$payload" name)"
  reply="$(pair_field "$payload" reply)"
  [[ -z "$type" || -z "$name" ]] && { ui_err "code missing type/name"; ui_pause; return 1; }
  t_has "$type" pair_import || { ui_err "unknown tunnel type in code: $type"; ui_pause; return 1; }
  require_root; fw_init; svc_install_templates

  # ---- a REPLY code: finalize the tunnel WE generated earlier ----
  if [[ "$reply" == 1 ]]; then
    st_exists "$name" || { ui_err "no local tunnel '$name' to finalize (generate it here first)"; ui_pause; return 1; }
    t_has "$type" pair_finalize || { ui_err "$type has no finalize step"; ui_pause; return 1; }
    ui_info "finalizing tunnel '$name' with the peer's address"
    t_call "$type" pair_finalize "$payload" || { ui_err "finalize failed"; ui_pause; return 1; }
    ui_ok "tunnel '$name' is now fully paired and up"
    ui_pause; return 0
  fi

  # ---- a normal pairing code: configure THIS (second) side ----
  ui_info "importing $type tunnel '$name'"
  t_call "$type" pair_import "$payload" || { ui_err "import failed"; ui_pause; return 1; }
  ui_ok "imported tunnel '$name'"

  # two-way tunnels: hand back a reply code carrying this side's address
  local tw; tw="$(t_meta_field "$type" twoway)"
  if [[ "$tw" == yes ]] && t_has "$type" pair_reply; then
    echo; ui_head "REPLY code — paste this on the FIRST server"
    ui_note "That server is waiting for it (mili → Import pairing code)."
    echo
    local rp; rp="$(t_call "$type" pair_reply "$name" | pair_encode "")"
    printf '%s%s%s\n' "${C_YEL:-}" "$rp" "${C_RST:-}"
    if sys_has qrencode && [[ -t 1 ]]; then echo; qrencode -t ANSIUTF8 "$rp" 2>/dev/null || true; fi
  fi
  ui_pause
}

# ============================================================================
# tunnel management screen
# ============================================================================
mili_manage() {
  local sel=0
  while :; do
    ui_clear; ui_head "Tunnels"
    local names=(); mapfile -t names < <(st_list)
    if [[ ${#names[@]} -eq 0 ]]; then ui_note "no tunnels yet — create one from the main menu"; ui_pause; return; fi
    printf '  %s↑/↓ select · Enter open · q back%s\n\n' "$C_GRY" "$C_RST"
    local n type st labels=()
    for n in "${names[@]}"; do
      st_load "$n"; type="$(st_get type)"
      if t_has "$type" health && t_call "$type" health "$n" >/dev/null 2>&1; then st="${C_GRN}● up${C_RST}"; else st="${C_RED}● down${C_RST}"; fi
      labels+=("$(printf '%-12s %b' "$n" "$st")"$'\t'"$type · ${ST[role]:-}")
    done
    labels+=("Back"$'\t')
    ui_select "$sel" "${labels[@]}"
    sel=$(( SEL>0 ? SEL-1 : sel ))
    (( SEL==0 || SEL > ${#names[@]} )) && return
    mili_tunnel_actions "${names[$((SEL-1))]}"
  done
}

mili_tunnel_actions() {  # <name>
  local name="$1" type sel=0
  st_load "$name"; type="$(st_get type)"
  while :; do
    ui_clear; ui_head "Tunnel: $name  ($type)"
    # live connection status banner
    local hstate hcolor hicon
    if t_has "$type" health && t_call "$type" health "$name" >/dev/null 2>&1; then
      hstate="CONNECTED"; hcolor="$C_GRN"; hicon="●"
    else
      hstate="NOT CONNECTED"; hcolor="$C_RED"; hicon="●"
    fi
    printf '  %s %s LINK: %s %s%s\n' "$hcolor" "$hicon" "$hstate" "$(grep -q '^state=up' "$MILI_TUNDIR/$name.conf" 2>/dev/null && printf '(started)' || printf '(stopped)')" "$C_RST"
    ui_hr 64
    t_has "$type" info && t_call "$type" info "$name"
    echo
    ui_select "$sel" \
      $'Start' $'Stop' $'Restart' \
      $'Logs (follow)' \
      $'3x-ui JSON helper' \
      $'Test (socks / ping)' \
      $'Show pairing code' \
      $'Edit / re-render' \
      $'Delete' \
      $'Back'
    sel=$(( SEL>0 ? SEL-1 : sel ))
    case "$SEL" in
      1) mili_up "$name"; ui_pause ;;
      2) mili_down "$name"; ui_pause ;;
      3) mili_restart "$name"; ui_pause ;;
      4) local u; u="$(t_has "$type" unit && t_call "$type" unit "$name")"; [[ -n "$u" ]] && svc_logs_follow "$u" || { ui_warn "no unit"; ui_pause; } ;;
      5) st_load "$name"; t_has "$type" xui && t_call "$type" xui "$name"; ui_pause ;;
      6) t_has "$type" test && t_call "$type" test "$name" || ui_warn "no test for $type"; ui_pause ;;
      7) mili_export_code "$name"; ui_pause ;;
      8) t_has "$type" wizard && { st_load "$name"; t_call "$type" wizard "$(st_get role)" advanced && st_save && mili_restart "$name"; }; ui_pause ;;
      9) mili_delete "$name" && return ;;
      10|0) return ;;
    esac
    st_load "$name"
  done
}

# ============================================================================
# dashboard header + main menu
# ============================================================================
# Fast header: counts come from the stored `state` field (no live probing, no
# per-tunnel systemctl calls). Public IPv4 is cached after the first call.
mili_header() {
  ui_clear
  ui_banner "unified anti-DPI tunnel manager  v$MILI_VERSION"
  local total=0 up=0 n
  while read -r n; do
    [[ -z "$n" ]] && continue
    ((total++))
    grep -q '^state=up' "$MILI_TUNDIR/$n.conf" 2>/dev/null && ((up++))
  done < <(st_list)
  echo
  printf '  %s  %s  %s\n' "$(mili_edition_badge)" \
    "$(ui_badge "$(hostname -s 2>/dev/null || hostname)" "$C_BLU")" \
    "$(ui_badge "x-ui: $(xui_status_line)" "$C_MAG")"
  ui_kv "Public IPv4" "$(sys_public_ip4)"
  [[ "${MILI_PUBIP6:-}" != "" && "${MILI_PUBIP6:-}" != none ]] && ui_kv "Public IPv6" "$MILI_PUBIP6"
  ui_kv "Role default" "${MILI_DEFAULT_ROLE:-not set}"
  ui_kv "Tunnels" "$(printf '%s%s up%s / %s%s stopped%s  (%s total)' "$C_GRN" "$up" "$C_RST" "$C_GRY" "$((total-up))" "$C_RST" "$total")"
  if [[ -n "${MILI_PORT_ALERT:-}" ]]; then
    ui_err "PORT CONFLICT detected - open 'Ports & conflicts'"
  fi
  ui_hr 64
}

mili_menu() {
  require_root
  st_dir_init; ports_db_init
  # one-shot public IP fetch so the first draw isn't blocked repeatedly
  sys_public_ip4 >/dev/null 2>&1 &
  local sel=0
  while :; do
    # cheap port-conflict flag, refreshed once per full redraw
    ports_audit >/dev/null 2>&1 && MILI_PORT_ALERT='' || MILI_PORT_ALERT=1
    mili_header
    printf '  %snavigate %s↑/↓%s   select %sEnter%s   quit %sq%s\n\n' \
      "$C_GRY" "$C_CYN" "$C_GRY" "$C_CYN" "$C_GRY" "$C_CYN" "$C_RST"
    ui_select "$sel" \
      $'★ New tunnel\tcreate + get pairing code' \
      $'Import pairing code\tpaste code from the other server' \
      $'Manage tunnels\tstart · stop · logs · x-ui JSON · delete' \
      $'3x-ui helper\tdetected panel / inbounds / recipes' \
      $'Ports & conflicts\tregistry + live audit' \
      $'Cores (binaries)\tinstall · update · rollback · offline' \
      $'Network optimizer\tBBR · fq · MTU finder' \
      $'Diagnostics\tdoctor · connectivity · bundle' \
      $'Backup & restore' \
      $'Settings' \
      $'Edition / License' \
      $'Update mili' \
      $'Uninstall' \
      $'Exit'
    sel=$(( SEL>0 ? SEL-1 : sel ))
    case "$SEL" in
      1) mili_new_tunnel ;;
      2) mili_import_code ;;
      3) mili_manage ;;
      4) mili_menu_xui ;;
      5) mili_menu_ports ;;
      6) mili_menu_cores ;;
      7) mili_menu_optimize ;;
      8) doctor_run; ui_pause ;;
      9) mili_menu_backup ;;
      10) mili_menu_settings ;;
      11) mili_menu_edition ;;
      12) mili_update; ui_pause ;;
      13) mili_menu_uninstall ;;
      14) ui_clear; exit 0 ;;
      0) ui_confirm "Quit mili?" y && { ui_clear; exit 0; } ;;
    esac
  done
}

mili_menu_xui() {
  ui_clear; ui_head "3x-ui helper"
  if ! xui_installed; then ui_warn "3x-ui not detected"; else
    ui_kv "status" "$(xui_status_line)"
    echo; ui_info "inbounds:"
    xui_inbounds 2>/dev/null | while IFS='|' read -r t p pr; do ui_note "- $t (port $p, $pr)"; done
    echo; ui_info "mili tunnels with ready SOCKS outbound JSON: open each tunnel -> '3x-ui JSON helper'"
  fi
  ui_pause
}

mili_menu_ports() {
  ui_clear; ui_head "Ports & conflicts"
  ui_info "mili-claimed ports:"
  if [[ -s "$MILI_PORTSDB" ]]; then
    awk -F'|' 'NF>=3 && $3 ~ /^[0-9]+$/ {printf "  %-12s %-5s %-6s %s\n",$1,$2,$3,$4}' "$MILI_PORTSDB"
  else ui_note "none"; fi
  echo; ui_info "audit:"
  if ports_audit; then ui_ok "no conflicts"; fi
  echo; ui_info "reserved (never used): ${MILI_RESERVED[*]}"
  echo; if ui_confirm "Find a free public port?" n; then ui_kv "free public" "$(ports_alloc_public)"; fi
  ui_pause
}

mili_menu_cores() {
  local cores=(frp backhaul paqet hedioum gost rathole hysteria singbox) sel=0
  while :; do
    ui_clear; ui_head "Cores (binaries)"
    ui_note "Enter on a core installs/updates it to the pinned version."
    echo
    local c v inst labels=()
    for c in "${cores[@]}"; do
      v="$(cores_version "$c")"; inst="$(cores_installed_version "$c" 2>/dev/null)"
      if [[ -n "$inst" ]]; then labels+=("$(printf '%-10s' "$c")"$'\t'"v$v · ${C_GRN}installed $inst${C_RST}")
      else labels+=("$(printf '%-10s' "$c")"$'\t'"v$v · not installed"); fi
    done
    labels+=("Build offline bundle"$'\t' "Import offline bundle"$'\t' \
             "Peer serve (foreign)"$'\t' "Peer pull (iran)"$'\t' "Back"$'\t')
    ui_select "$sel" "${labels[@]}"
    sel=$(( SEL>0 ? SEL-1 : sel ))
    local base=${#cores[@]}
    if (( SEL>=1 && SEL<=base )); then require_root; cores_install "${cores[$((SEL-1))]}"; ui_pause
    else case $(( SEL-base )) in
      1) fetch_bundle; ui_pause ;;
      2) local t; t="$(ui_ask 'Path to bundle tar.gz' '')"; fetch_bundle_import "$t"; ui_pause ;;
      3) fetch_peer_serve; ui_pause ;;
      4) local code; code="$(ui_ask 'Pull code' '')"; fetch_peer_pull "$code"; ui_pause ;;
      *) return ;;
    esac; fi
  done
}

mili_menu_optimize() {
  ui_clear; ui_head "Network optimizer"
  optimize_status; echo
  ui_select 0 $'Apply tuning\tBBR + fq + buffers' $'Revert tuning' $'MTU finder' $'Back'
  case "$SEL" in
    1) require_root; optimize_apply; ui_pause ;;
    2) require_root; optimize_revert; ui_pause ;;
    3) local h; h="$(ui_ask 'Target host/IP' '1.1.1.1')"; doctor_mtu "$h"; ui_pause ;;
  esac
}

mili_menu_backup() {
  ui_clear; ui_head "Backup & restore"
  ui_select 0 $'Create backup' $'List backups' $'Restore' $'Back'
  case "$SEL" in
    1) require_root; backup_create >/dev/null; ui_pause ;;
    2) backup_list; ui_pause ;;
    3) local t; t="$(ui_ask 'Backup path' "$(backup_list 2>/dev/null | head -n1)")"; require_root; backup_restore "$t"; ui_pause ;;
  esac
}

mili_menu_settings() {
  ui_clear; ui_head "Settings"
  ui_kv "Default role"   "${MILI_DEFAULT_ROLE:-(unset)}"
  ui_kv "GH proxies"     "$MILI_GH_PROXIES"
  ui_kv "Mirror"         "${MILI_MIRROR:-(none)}"
  ui_kv "Color mode"     "$MILI_COLORMODE"
  echo
  ui_select 0 $'Set default role\tiran / foreign' $'Set GitHub proxy prefixes' $'Set mirror base URL' $'Back'
  case "$SEL" in
    1) ui_select 0 $'iran' $'foreign'; [[ "$SEL" == 1 ]] && mili_conf_set MILI_DEFAULT_ROLE iran; [[ "$SEL" == 2 ]] && mili_conf_set MILI_DEFAULT_ROLE foreign; ui_pause ;;
    2) local p; p="$(ui_ask 'Space-separated proxy prefixes' "$MILI_GH_PROXIES")"; mili_conf_set MILI_GH_PROXIES "$p"; ui_pause ;;
    3) local m; m="$(ui_ask 'Mirror base URL' "$MILI_MIRROR")"; mili_conf_set MILI_MIRROR "$m"; ui_pause ;;
  esac
}

mili_conf_set() {  # <KEY> <VALUE> : persist to mili.conf
  st_dir_init
  local key="$1" val="$2" tmp; tmp="$(mktemp)"
  { grep -vE "^$key=" "$MILI_CONF" 2>/dev/null; printf '%s=%q\n' "$key" "$val"; } >"$tmp"
  mv -f "$tmp" "$MILI_CONF"; chmod 600 "$MILI_CONF" 2>/dev/null || true
  export "$key=$val"
  ui_ok "saved $key"
}

mili_menu_edition() {
  ui_clear; ui_head "Edition / License"
  ui_kv "Edition" "$(mili_edition)"
  echo; ui_note "All features are FREE in this version."
  ui_note "Premium tier (reserved features, licensing) is planned - hooks are in place."
  ui_pause
}

mili_menu_uninstall() {
  ui_clear; ui_head "Uninstall"
  ui_select 0 $'Remove ONE tunnel\topens Manage → Delete' $'Remove EVERYTHING\tall tunnels + mili (x-ui untouched)' $'Back'
  case "$SEL" in
    1) mili_manage ;;
    2) mili_uninstall_all ;;
  esac
}

# ============================================================================
# install / update / uninstall
# ============================================================================
mili_update() {
  require_root
  ui_info "re-running install bootstrap to fetch the latest mili"
  local url="${MILI_SELF_URL:-https://raw.githubusercontent.com/yaldoughie/mili/main/install.sh}"
  if curl -fsSL "$url" -o /tmp/mili-install.sh 2>/dev/null; then
    bash /tmp/mili-install.sh && ui_ok "mili updated"
  else
    ui_warn "could not reach update URL (set MILI_SELF_URL); current version kept"
  fi
}

mili_uninstall_all() {
  ui_err "This removes ALL mili tunnels, services, firewall rules, sysctl files and /etc/mili."
  ui_warn "3x-ui and its data are NOT touched."
  ui_confirm "Type-confirm: remove everything mili?" n || return 1
  require_root
  local n type
  while read -r n; do
    [[ -z "$n" ]] && continue
    st_load "$n"; type="$(st_get type)"
    t_call "$type" down "$n" >/dev/null 2>&1 || true
    t_has "$type" purge && t_call "$type" purge "$n" >/dev/null 2>&1 || true
  done < <(st_list)
  # stop & remove units
  systemctl stop 'mili-*' 2>/dev/null || true
  systemctl disable mili-fw.service mili-watchdog.timer 2>/dev/null || true
  rm -f /etc/systemd/system/mili-*.service /etc/systemd/system/mili-*.timer 2>/dev/null || true
  systemctl daemon-reload 2>/dev/null || true
  fw_teardown
  sysctl_remove_all; run sysctl --system >/dev/null 2>&1 || true
  rm -rf /opt/mili /etc/mili /var/log/mili /etc/logrotate.d/mili 2>/dev/null || true
  rm -f /usr/local/bin/mili 2>/dev/null || true
  ui_ok "mili fully removed. Verify: iptables-save | grep -i mili ; systemctl list-units 'mili*'"
}

# ============================================================================
# hidden service dispatchers (called by systemd units)
# ============================================================================
# mili _svc <engine> <name> : exec the engine in foreground for its unit
mili_svc_exec() {
  local engine="$1" name="$2"
  case "$engine" in
    socks)    socks_exec "$name" ;;
    frps|frpc)
      local _cfg="$MILI_ETC/engines/$engine/$name.toml" _bin
      _bin="$(cores_path "$engine")"
      [[ -x "$_bin" ]] || die "frp core not installed"
      [[ -f "$_cfg" ]] || die "frp config missing: $_cfg"
      exec "$_bin" -c "$_cfg" ;;
    backhaul)
      local _cfg="$MILI_ETC/engines/backhaul/$name.toml" _bin
      _bin="$(cores_path backhaul)"
      [[ -x "$_bin" && -f "$_cfg" ]] || die "backhaul core/config missing"
      exec "$_bin" -c "$_cfg" ;;
    paqet)
      local _cfg="$MILI_ETC/engines/paqet/$name.conf" _bin
      _bin="$(cores_path paqet)"
      [[ -x "$_bin" && -f "$_cfg" ]] || die "paqet core/config missing"
      exec "$_bin" -c "$_cfg" ;;
    *)
      # generic: module provides t_<type>_svc_exec that execs the core
      local type; st_load "$name" >/dev/null 2>&1 && type="$(st_get type)"
      if [[ -n "${type:-}" ]] && t_has "$type" svc_exec; then
        t_call "$type" svc_exec "$name" "$engine"
      else
        die "no svc_exec for engine $engine / tunnel $name"
      fi ;;
  esac
}

mili_fw_restore() {
  st_dir_init; fw_init
  local n type
  while read -r n; do
    [[ -z "$n" ]] && continue
    st_load "$n"; type="$(st_get type)"
    t_has "$type" fw_apply && t_call "$type" fw_apply "$n" || true
  done < <(st_list)
}

# ============================================================================
# CLI
# ============================================================================
mili_cli() {
  local cmd="$1"; shift || true
  case "$cmd" in
    status|list)
      local n type st
      printf '%-12s %-10s %-6s\n' NAME TYPE STATE
      while read -r n; do
        [[ -z "$n" ]] && continue
        st_load "$n"; type="$(st_get type)"
        if t_has "$type" health && t_call "$type" health "$n" >/dev/null 2>&1; then st=up; else st=down; fi
        printf '%-12s %-10s %-6s\n' "$n" "$type" "$st"
      done < <(st_list) ;;
    up)      mili_up "$1" ;;
    down)    mili_down "$1" ;;
    restart) mili_restart "$1" ;;
    logs)    st_load "$1"; local ty; ty="$(st_get type)"; local u; u="$(t_call "$ty" unit "$1")"; svc_logs_follow "$u" ;;
    import)  mili_import_code "$1" ;;
    export)  mili_export_code "$1" ;;
    ports)   ports_audit && ui_ok "no conflicts" ;;
    doctor)  doctor_run ;;
    cores)   case "$1" in install) cores_install "$2";; bundle) fetch_bundle "$2";; *) ui_info "cores: install <c> | bundle";; esac ;;
    update)  mili_update ;;
    uninstall) mili_uninstall_all ;;
    version) echo "mili $MILI_VERSION" ;;
    _svc)        mili_svc_exec "$@" ;;
    _l3)         local _op="$1" _nm="$2"; st_load "$_nm" || die "unknown tunnel $_nm"; t_call "$(st_get type)" "if$_op" "$_nm" ;;
    _up)         mili_up "$1" ;;
    _down)       mili_down "$1" ;;
    _watchdog)   watchdog_run ;;
    _fw-restore) mili_fw_restore ;;
    ''|menu) mili_menu ;;
    *) ui_err "unknown command: $cmd"; echo "try: mili status|up|down|restart|logs|import|export|ports|doctor|cores|update|uninstall|version"; return 1 ;;
  esac
}

# load persisted config
[[ -r "$MILI_CONF" ]] && { set -a; . "$MILI_CONF"; set +a; }

mili_cli "$@"
