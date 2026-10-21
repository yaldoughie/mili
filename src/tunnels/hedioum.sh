# shellcheck shell=bash
# mili :: tunnels/hedioum.sh - hedioum/Hedioum-Pool-Tunnel (mimic SOCKS pool).
#
# Hedioum is a self-managing CLI, NOT a config-file daemon. It installs and runs
# its OWN `hedioum.service`. mili drives it:
#   foreign (egress): `hedioum-tunnel setup-foreign ...`  -> prints a token
#   iran (hub)      : `hedioum-tunnel setup-iran --token <TOKEN> --socks-port P`
# The hedioum token IS the pairing secret; mili carries it inside its pair code.
#
# roles: iran (hub) | foreign (egress, generates token)

t_register hedioum
feature "tunnel.hedioum" free

_hed_bin() {
  local b; b="$(cores_path hedioum-tunnel)"
  cores_bin_ok hedioum-tunnel && { printf '%s' "$b"; return 0; }
  return 1
}

# true once hedioum has written its config (the daemon needs it, else it loops)
_hed_configured() {
  local d
  for d in /etc/hedioum /root/.config/hedioum /root/.hedioum /var/lib/hedioum; do
    # any non-empty regular file counts as "configured"
    [[ -n "$(find "$d" -type f ! -empty 2>/dev/null | head -n1)" ]] && return 0
  done
  return 1
}

# pull the pairing token out of setup-foreign output (several heuristics)
_hed_extract_token() {
  local out="$1" tok
  tok="$(printf '%s' "$out" | grep -iE 'token|pair' | grep -oE '[A-Za-z0-9+/=_.:-]{16,}' | tail -n1)"
  [[ -z "$tok" ]] && tok="$(printf '%s' "$out" | grep -oE '[A-Za-z0-9+/=_.:-]{24,}' | tail -n1)"
  printf '%s' "$tok"
}

# ensure binary present + hedioum's own service installed, and reachable in PATH
_hed_prepare() {
  cores_ensure hedioum || return 1
  local b; b="$(_hed_bin)" || { ui_err "hedioum binary missing"; return 1; }
  # expose on PATH for hedioum's own service unit
  [[ -e /usr/local/bin/hedioum-tunnel ]] || run ln -sfn "$b" /usr/local/bin/hedioum-tunnel
  # hedioum sets up its own systemd service + /etc/hedioum on first install
  if ! systemctl list-unit-files 2>/dev/null | grep -q '^hedioum\.service'; then
    run "$b" install >/dev/null 2>&1 || true
  fi
  return 0
}

t_hedioum_meta() {
  echo "id=hedioum"
  echo "title=Hedioum  (mimic SOCKS pool)"
  echo "tier=free"
  echo "layer=socks"
  echo "roles=iran foreign"
  echo "primary=foreign"        # foreign generates the token
  echo "twoway=no"              # iran only needs the token (carries foreign IP)
  echo "cores=hedioum"
}

t_hedioum_unit() { echo "hedioum.service"; }

t_hedioum_wizard() {  # <role> <level>  (only the FOREIGN side runs this)
  local role="$1" level="$2"
  if [[ "$role" != foreign ]]; then
    # iran is configured by importing the token; nothing to ask here
    ST[socks_port]="${ST[socks_port]:-$(ports_alloc_socks)}"
    ST[alias]="${ST[alias]:-$(hostname -s 2>/dev/null || echo iran)}"
    return 0
  fi
  ST[my_ip]="$(sys_public_ip4)"
  [[ "$level" == advanced ]] && ST[my_ip]="$(ui_ask 'This foreign server public IP (auto)' "${ST[my_ip]}")"
  ui_ok "this foreign server public IP: ${ST[my_ip]} (embedded in the token)"
  ST[persona]="$(ui_ask 'persona (auto|cpanel|directadmin|devops)' "${ST[persona]:-auto}")"
  ST[domain]="$(ui_ask 'domain for Lets Encrypt (blank = self-signed)' "${ST[domain]:-}")"
  ST[egress_mode]="$(ui_ask 'egress IP mode (ipv4|ipv6|dual)' "${ST[egress_mode]:-ipv4}")"
  if [[ "$level" == advanced ]]; then
    ST[move_ssh]="$(ui_confirm 'move SSH into the mimic set (--move-ssh)? advanced/risky' n && echo yes || echo no)"
    ST[mimics]="$(ui_ask 'mimics (all | comma list | blank=persona default)' "${ST[mimics]:-}")"
  else
    ST[move_ssh]=no; ST[mimics]=''
  fi
  return 0
}

t_hedioum_render() { :; }   # hedioum owns its config

# FOREIGN: run setup-foreign, capture the token into ST[token]
t_hedioum_up() {  # <name>
  st_load "$1"; local name="$1"
  require_root
  _hed_prepare || { ui_err "hedioum not ready"; return 1; }
  local b; b="$(_hed_bin)"

  if [[ "${ST[role]}" == foreign ]]; then
    # already set up with a token and running? don't re-run (would rotate token)
    if [[ -n "${ST[token]:-}" ]] && systemctl is-active --quiet hedioum.service 2>/dev/null; then
      ui_ok "hedioum egress already configured (token stored)"
    else
      local ip; ip="${ST[my_ip]:-$(sys_public_ip4)}"
      # real setup-foreign flags (confirmed against the binary's -help):
      #   --egress-mode (not --egress), --public-ip, --http-decoy-port,
      #   --listen-port (SSH mimic), --move-ssh, --mimics, --domain, --persona
      local -a a=(setup-foreign --persona "${ST[persona]:-auto}"
                  --egress-mode "${ST[egress_mode]:-ipv4}"
                  --public-ip "$ip"
                  --http-decoy-port 0)            # keep port 80 free (ACME/x-ui)
      [[ -n "${ST[domain]:-}" ]] && a+=(--domain "${ST[domain]}")
      if [[ "${ST[move_ssh]:-no}" == yes ]]; then
        a+=(--move-ssh)                            # relocate real sshd; SSH mimic takes 22
      else
        # don't fight the real sshd on :22 — put the SSH mimic on a free high port
        local sshmimic; sshmimic="$(ports_alloc_public)"
        a+=(--listen-port "$sshmimic")
        ST[ssh_mimic_port]="$sshmimic"
      fi
      [[ -n "${ST[mimics]:-}" ]] && a+=(--mimics "${ST[mimics]}")
      ui_info "running: hedioum-tunnel ${a[*]}"
      local out; out="$(run "$b" "${a[@]}" 2>&1)"
      printf '%s\n' "$out" | sed 's/^/    /'
      printf '%s\n' "$out" >"$MILI_ETC/engines/hedioum-$name.out" 2>/dev/null || true
      ST[token]="$(_hed_extract_token "$out")"
      # fallback: ask the operator to paste it from the output above
      if [[ -z "${ST[token]}" ]]; then
        ui_warn "could not auto-detect the pairing token in the output above."
        ui_note "copy the token string hedioum printed and paste it here."
        ST[token]="$(ui_ask 'Hedioum pairing token' '')"
      fi
      if [[ -z "${ST[token]}" ]]; then
        ui_err "no token — Iran side cannot pair. Fix setup-foreign and retry."
        run systemctl disable --now hedioum.service >/dev/null 2>&1 || true
        st_save; return 1
      fi
      ui_ok "pairing token stored"
      st_save
    fi
    _hed_finish "$name" "$out" || return 1
  else
    # iran hub (reached via import). The ONLY reliable success signal is that a
    # config file appears; a bad token writes nothing and the daemon loops.
    [[ -z "${ST[token]:-}" ]] && { ui_err "no token stored - import the foreign pairing code instead"; return 1; }
    local out
    ui_info "running: hedioum-tunnel setup-iran --alias ${ST[alias]:-iran} --socks-port ${ST[socks_port]} --token ***"
    out="$(run "$b" setup-iran --alias "${ST[alias]:-iran}" --token "${ST[token]}" --socks-port "${ST[socks_port]}" 2>&1)"
    printf '%s\n' "$out" | sed 's/^/    /'
    ports_claim "$name" tcp "${ST[socks_port]}" "127.0.0.1"
    fw_loopback_guard "$name" tcp "${ST[socks_port]}"
    _hed_finish "$name" "$out" || return 1
  fi
}

# verify config was actually written; start the daemon only then. Otherwise
# save the output, STOP the crash-loop, and tell the operator exactly why.
_hed_finish() {  # <name> <setup-output>
  local name="$1" out="$2" log="$MILI_LOGDIR/hedioum-$name.setup.log"
  mkdir -p "$MILI_LOGDIR" 2>/dev/null || true
  printf '%s\n' "$out" >"$log" 2>/dev/null || true
  if _hed_configured; then
    run systemctl enable --now hedioum.service >/dev/null 2>&1 || true
    ui_ok "hedioum configured; service started"
    return 0
  fi
  # no config -> setup did not take. Kill the loop and explain.
  run systemctl disable --now hedioum.service >/dev/null 2>&1 || true
  ui_err "hedioum did NOT write a config (daemon would crash-loop) — stopped it."
  ui_note "setup output saved to: $log"
  ui_note "most common cause: the pairing token is wrong/expired."
  ui_note "fix: regenerate on the foreign server, import the FRESH code here."
  echo; ui_info "setup said:"; printf '%s\n' "$out" | tail -n 15 | sed 's/^/    /'
  return 1
}

t_hedioum_down() {  # <name>
  st_load "$1"
  # hedioum.service is shared; only stop it if this is the only hedioum tunnel
  local n others=0
  while read -r n; do
    [[ -z "$n" || "$n" == "$1" ]] && continue
    st_load "$n" >/dev/null 2>&1 && [[ "$(st_get type)" == hedioum ]] && others=$((others+1))
  done < <(st_list)
  st_load "$1"
  fw_remove "$1"
  if (( others == 0 )); then
    run systemctl disable --now hedioum.service 2>/dev/null || true
  fi
}

t_hedioum_purge() { :; }
t_hedioum_fw_apply() {
  st_load "$1"
  [[ "${ST[role]}" == iran && -n "${ST[socks_port]:-}" ]] && fw_loopback_guard "$1" tcp "${ST[socks_port]}"
}

t_hedioum_health() {  # <name>
  st_load "$1"
  systemctl is-active --quiet hedioum.service 2>/dev/null || return 1
  if [[ "${ST[role]}" == iran && -n "${ST[socks_port]:-}" ]]; then
    ss -Hlnt 2>/dev/null | awk '{print $4}' | grep -qE ":${ST[socks_port]}\$"
  fi
}

t_hedioum_ports() {
  st_load "$1"
  [[ "${ST[role]}" == iran && -n "${ST[socks_port]:-}" ]] && echo "tcp:${ST[socks_port]}:127.0.0.1"
}

t_hedioum_info() {
  st_load "$1"
  ui_kv "role" "${ST[role]} (native hedioum.service)"
  ui_kv "persona" "${ST[persona]:-auto}"
  [[ -n "${ST[domain]:-}" ]] && ui_kv "domain" "${ST[domain]}"
  if [[ "${ST[role]}" == iran ]]; then
    ui_kv "alias" "${ST[alias]:-iran}"
    echo; xui_outbound_box "127.0.0.1" "${ST[socks_port]:-?}" "" ""
  else
    ui_kv "egress mode" "${ST[egress_mode]:-ipv4}"
    [[ -n "${ST[token]:-}" ]] && ui_kv "token" "captured (show via pairing code)"
  fi
}

t_hedioum_xui() {
  st_load "$1"
  if [[ "${ST[role]}" == iran ]]; then
    xui_help_socks "$1" "127.0.0.1" "${ST[socks_port]}" "" ""
  else
    ui_warn "Hedioum SOCKS endpoint lives on the IRAN hub (127.0.0.1:<socks-port>)."
  fi
}

t_hedioum_test() {
  st_load "$1"
  if systemctl is-active --quiet hedioum.service 2>/dev/null; then ui_ok "hedioum.service active"; else ui_err "hedioum.service not active"; fi
  local b; b="$(_hed_bin 2>/dev/null)"
  if [[ -n "$b" ]]; then
    if [[ "${ST[role]}" == iran ]]; then run "$b" probe --node "${ST[alias]:-iran}" 2>&1 | sed 's/^/    /' || true
    else run "$b" check-ip 2>&1 | sed 's/^/    /' || true; fi
  fi
  [[ "${ST[role]}" == iran ]] && doctor_socks 127.0.0.1 "${ST[socks_port]}" || true
}

# FOREIGN exports the hedioum token; IRAN imports it and runs setup-iran
t_hedioum_pair_export() {
  st_load "$1"
  cat <<EOF
type=hedioum
name=${ST[name]}
role=iran
token=${ST[token]:-}
persona=${ST[persona]:-auto}
domain=${ST[domain]:-}
egress_mode=${ST[egress_mode]:-ipv4}
EOF
}

t_hedioum_pair_import() {
  local p="$1" name
  name="$(pair_field "$p" name)"
  ST=(); ST[name]="$name"; ST[type]=hedioum; ST[role]=iran
  ST[token]="$(pair_field "$p" token)"
  ST[persona]="$(pair_field "$p" persona)"
  ST[domain]="$(pair_field "$p" domain)"
  ST[egress_mode]="$(pair_field "$p" egress_mode)"
  [[ -z "${ST[token]}" ]] && { ui_err "pairing code has no hedioum token"; return 1; }
  ST[alias]="$(hostname -s 2>/dev/null || echo iran)"
  ST[socks_port]="$(ports_alloc_socks)"
  st_save
  t_hedioum_up "$name"; st_set state up; st_save
}
