# shellcheck shell=bash
# mili :: watchdog.sh - health loop, auto-restart, fw/ufw self-heal, port audit.
# Invoked by mili-watchdog.timer every 60s via `mili _watchdog`.

MILI_WDLOG="${MILI_WDLOG:-$MILI_LOGDIR/watchdog.log}"
MILI_WD_FAILS="$MILI_ETC/.wdfails"   # name -> consecutive fail count

_wd_log() { mkdir -p "$MILI_LOGDIR" 2>/dev/null || true; printf '%s %s\n' "$(date '+%F %T')" "$*" >>"$MILI_WDLOG" 2>/dev/null || true; }
_wd_fails_get() { grep -E "^$1 " "$MILI_WD_FAILS" 2>/dev/null | awk '{print $2}'; }
_wd_fails_set() {
  local name="$1" n="$2" tmp; tmp="$(mktemp)"
  { grep -vE "^$name " "$MILI_WD_FAILS" 2>/dev/null; printf '%s %s\n' "$name" "$n"; } >"$tmp"
  mv -f "$tmp" "$MILI_WD_FAILS"
}

watchdog_run() {
  # 1. self-heal firewall hooks (cheap, idempotent)
  fw_rehook 2>/dev/null || true

  # 2. per-tunnel health
  local name type cur fails
  while read -r name; do
    [[ -z "$name" ]] && continue
    st_load "$name" || continue
    # only watch tunnels the operator started (never revive a stopped one)
    [[ "$(st_get state)" == up ]] || continue
    type="$(st_get type)"
    # 'probe' = deeper liveness check (watchdog only); 'health' = cheap (menu)
    local chk=health; t_has "$type" probe && chk=probe
    t_has "$type" "$chk" || continue
    if t_call "$type" "$chk" "$name" >/dev/null 2>&1; then
      _wd_fails_set "$name" 0
    else
      fails=$(_wd_fails_get "$name"); fails=$(( ${fails:-0} + 1 ))
      _wd_fails_set "$name" "$fails"
      _wd_log "health fail $name ($fails)"
      if (( fails >= 3 )); then
        _wd_log "restarting $name after $fails fails"
        # restart the UNIT only (never re-run the wizard/setup path)
        local u=''; t_has "$type" unit && u="$(t_call "$type" unit "$name" 2>/dev/null)"
        [[ -n "$u" ]] && systemctl restart "$u" >/dev/null 2>&1 || true
        _wd_fails_set "$name" 0
      fi
    fi
  done < <(st_list)

  # 3. port audit (clash with newly-added x-ui inbound etc.)
  if ! ports_audit >/dev/null 2>&1; then
    _wd_log "PORT CONFLICT detected (see 'mili ports')"
  fi

  # 4. note x-ui appearance (ensures ufw mirrors still present next run)
  if xui_installed 2>/dev/null; then
    : # future: re-mirror ufw rules if missing; fw_rehook already guarantees chains
  fi
}
