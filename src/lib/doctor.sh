# shellcheck shell=bash
# mili :: doctor.sh - diagnostics, MTU finder, socks/connectivity tests, bundle.

doctor_run() {
  ui_head "mili doctor"
  ui_kv "OS"        "$MILI_OS_NAME ($MILI_OS $MILI_OS_VER)"
  ui_kv "Arch"      "$MILI_ARCH"
  sys_os_supported || ui_warn "distro not in tested matrix (Ubuntu 20.04+/Debian 11+)"
  ui_kv "Public v4" "$(sys_public_ip4)"
  local v6; v6=$(sys_public_ip6 2>/dev/null) && ui_kv "Public v6" "$v6"
  ui_kv "Default if" "$(sys_default_iface) via $(sys_default_gw)"

  echo; ui_info "dependencies:"
  local d
  for d in iproute2:ip iptables:iptables curl:curl jq:jq sqlite3:sqlite3 openssl:openssl tar:tar; do
    local pkg="${d%%:*}" cmd="${d##*:}"
    if sys_has "$cmd"; then ui_ok "$pkg"; else ui_warn "$pkg missing"; fi
  done

  echo; ui_info "kernel features:"
  modprobe ip_gre 2>/dev/null && ui_ok "GRE module available" || ui_warn "ip_gre not loadable (GRE may be unavailable)"
  modprobe fou 2>/dev/null && ui_ok "FOU module available" || ui_note "fou not loadable (GRE+FOU mode unavailable)"
  [[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" == 1 ]] && ui_ok "ip_forward on" || ui_note "ip_forward off (set when an L3/forward tunnel is created)"
  sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr && ui_ok "BBR active" || ui_note "BBR not active (see Network optimizer)"

  echo; ui_info "3x-ui:"
  ui_kv "status" "$(xui_status_line)"

  echo; ui_info "tunnels:"
  local name
  while read -r name; do
    [[ -z "$name" ]] && continue
    st_load "$name" || continue
    local type st; type="$(st_get type)"
    if t_has "$type" health && t_call "$type" health "$name" >/dev/null 2>&1; then st="${C_GRN}up${C_RST}"; else st="${C_RED}down${C_RST}"; fi
    printf '  %-12s %-10s %b\n' "$name" "$type" "$st"
  done < <(st_list)
}

# MTU finder: largest payload that passes unfragmented to a host
doctor_mtu() {  # <host>
  local host="${1:-}" lo=1200 hi=1500 best=0 mid
  [[ -z "$host" ]] && { ui_err "usage: doctor_mtu <host-or-ip>"; return 1; }
  ui_info "probing path MTU to $host (binary search)"
  while (( lo <= hi )); do
    mid=$(( (lo+hi)/2 ))
    if ping -c1 -W2 -M do -s $(( mid-28 )) "$host" >/dev/null 2>&1; then
      best=$mid; lo=$(( mid+1 ))
    else
      hi=$(( mid-1 ))
    fi
  done
  if (( best > 0 )); then
    ui_ok "path MTU to $host = $best (suggest tunnel MTU $(( best-40 )) for GRE)"
  else
    ui_warn "could not determine MTU (host may block ICMP)"
  fi
}

# test a SOCKS endpoint: reachability + exit IP
doctor_socks() {  # <addr> <port> [user] [pass]
  local addr="$1" port="$2" user="${3:-}" pass="${4:-}" auth=''
  [[ -n "$user" ]] && auth="$user:$pass@"
  ui_info "testing SOCKS $addr:$port"
  if curl -fsS --max-time 8 --socks5-hostname "${auth}${addr}:${port}" https://www.gstatic.com/generate_204 -o /dev/null 2>/dev/null; then
    ui_ok "connectivity OK"
    local xip; xip=$(curl -fsS --max-time 8 --socks5-hostname "${auth}${addr}:${port}" https://api.ipify.org 2>/dev/null)
    ui_kv "exit IP" "${xip:-unknown}"
  else
    ui_err "SOCKS test failed"
    return 1
  fi
}

# collect a support bundle (logs + state, secrets redacted)
doctor_bundle() {
  local out="/root/mili-doctor-$(date +%Y%m%d-%H%M%S).tar.gz" tmp
  tmp="$(mktemp -d)"
  mkdir -p "$tmp/mili"
  cp -r "$MILI_LOGDIR" "$tmp/mili/logs" 2>/dev/null || true
  cp -r "$MILI_ETC" "$tmp/mili/etc" 2>/dev/null || true
  # redact secrets
  find "$tmp/mili/etc" -type f 2>/dev/null | while read -r f; do
    sed -i -E 's/(PASS|SECRET|KEY|TOKEN|PSK|privatekey)=.*/\1=<redacted>/I' "$f" 2>/dev/null || true
  done
  { echo "=== systemd mili units ==="; systemctl list-units 'mili*' --no-pager 2>/dev/null
    echo "=== iptables mili ==="; iptables-save 2>/dev/null | grep -i mili
    echo "=== ss ==="; ss -lntu 2>/dev/null; } >"$tmp/mili/system.txt"
  tar -czf "$out" -C "$tmp" mili 2>/dev/null
  rm -rf "$tmp"
  ui_ok "doctor bundle -> $out (secrets redacted)"
}
