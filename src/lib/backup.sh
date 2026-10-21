# shellcheck shell=bash
# mili :: backup.sh - backup/restore of /etc/mili (state, configs, pki).

backup_create() {  # [out.tar.gz]
  local out="${1:-$MILI_ETC/backups/mili-$(date +%Y%m%d-%H%M%S).tar.gz}"
  run mkdir -p "$(dirname "$out")"
  run tar -czf "$out" -C "$(dirname "$MILI_ETC")" "$(basename "$MILI_ETC")" \
    --exclude='*/backups/*' --exclude='*/cache/*' 2>/dev/null
  ui_ok "backup -> $out"
  printf '%s' "$out"
}

backup_list() {
  ls -1t "$MILI_ETC/backups"/*.tar.gz 2>/dev/null || ui_note "no backups found"
}

# restore: extract state then re-render + re-apply firewall/services
backup_restore() {  # <tar.gz>
  local tar="$1"
  [[ -f "$tar" ]] || { ui_err "no such backup: $tar"; return 1; }
  ui_warn "restore overwrites current /etc/mili state"
  ui_confirm "proceed with restore from $(basename "$tar")?" n || return 1
  run tar -xzf "$tar" -C "$(dirname "$MILI_ETC")"
  ui_ok "state restored; re-applying firewall + services"
  fw_init
  # re-render and bring up every tunnel from restored state
  local name type
  while read -r name; do
    [[ -z "$name" ]] && continue
    st_load "$name" || continue
    type="$(st_get type)"
    t_has "$type" render && t_call "$type" render "$name" || true
    t_has "$type" up && t_call "$type" up "$name" || true
  done < <(st_list)
  ui_ok "restore complete"
}
