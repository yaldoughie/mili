# shellcheck shell=bash
# mili :: sysctl.sh - sysctl ONLY under /etc/sysctl.d/90-mili*.conf
# Never touches /etc/sysctl.conf or x-ui's 99-bbr-x-ui.conf.

MILI_SYSCTL_PORTS="/etc/sysctl.d/90-mili-ports.conf"
MILI_SYSCTL_FWD="/etc/sysctl.d/90-mili-forward.conf"
MILI_SYSCTL_TUNE="/etc/sysctl.d/91-mili-tune.conf"

_sysctl_reload() {
  if [[ -f "$1" ]]; then run sysctl -p "$1" >/dev/null 2>&1 || true; fi
}

# enable IPv4/IPv6 forwarding (needed for L3 exit / MASQUERADE / DNAT)
sysctl_enable_forward() {
  run bash -c "cat > '$MILI_SYSCTL_FWD' <<EOF
# mili: packet forwarding for tunnels (safe, additive)
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF"
  _sysctl_reload "$MILI_SYSCTL_FWD"
}

# write reserved local ports so the kernel's ephemeral allocator never
# steals a mili port. $1 = comma list like "20000-20010,10801"
sysctl_set_reserved_ports() {
  local list="$1"
  if [[ -z "$list" ]]; then
    [[ -f "$MILI_SYSCTL_PORTS" ]] && run rm -f "$MILI_SYSCTL_PORTS"
    return 0
  fi
  run bash -c "cat > '$MILI_SYSCTL_PORTS' <<EOF
# mili: reserve tunnel ports from the ephemeral range (managed, do not edit)
net.ipv4.ip_local_reserved_ports = $list
EOF"
  _sysctl_reload "$MILI_SYSCTL_PORTS"
}

# per-interface rp_filter loosening (needed for asymmetric routing via tunnels)
# $1 = iface
sysctl_rpfilter_loose() {
  local ifc="$1"
  [[ -z "$ifc" ]] && return 0
  run sysctl -qw "net.ipv4.conf.$ifc.rp_filter=2" 2>/dev/null || true
  # persist additively in the forward file footer
  if [[ -f "$MILI_SYSCTL_FWD" ]] && ! grep -q "conf.$ifc.rp_filter" "$MILI_SYSCTL_FWD" 2>/dev/null; then
    run bash -c "printf 'net.ipv4.conf.%s.rp_filter = 2\n' '$ifc' >> '$MILI_SYSCTL_FWD'"
  fi
}

sysctl_remove_all() {
  run rm -f "$MILI_SYSCTL_PORTS" "$MILI_SYSCTL_FWD" "$MILI_SYSCTL_TUNE" 2>/dev/null || true
}
