# shellcheck shell=bash
# mili :: sysctl.sh - sysctl ONLY in mili's own /etc/sysctl.d files.
# Never touches /etc/sysctl.conf or x-ui's 99-bbr-x-ui.conf.
#
# Reserved ports live in zz-mili-ports.conf so they load AFTER BackPack's
# zz-backpack.conf: the kernel keeps ONE ip_local_reserved_ports list and the
# last file wins, so mili writes the union (its ports + BackPack's) there.

MILI_SYSCTL_PORTS="${MILI_SYSCTL_PORTS:-/etc/sysctl.d/zz-mili-ports.conf}"
MILI_SYSCTL_PORTS_OLD="/etc/sysctl.d/90-mili-ports.conf"
BP_SYSCTL_FILE="${BP_SYSCTL_FILE:-/etc/sysctl.d/zz-backpack.conf}"
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
  [[ -f "$MILI_SYSCTL_PORTS_OLD" ]] && run rm -f "$MILI_SYSCTL_PORTS_OLD"
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
  run rm -f "$MILI_SYSCTL_PORTS" "$MILI_SYSCTL_PORTS_OLD" "$MILI_SYSCTL_FWD" "$MILI_SYSCTL_TUNE" 2>/dev/null || true
}

# BackPack's own reserved list (its optimizer rewrites it on every tunnel create)
sysctl_backpack_reserved() {
  [[ -r "$BP_SYSCTL_FILE" ]] || return 0
  awk -F'=' '$1 ~ /^[[:space:]]*net\.ipv4\.ip_local_reserved_ports[[:space:]]*$/ { gsub(/[[:space:]]/, "", $2); print $2 }' "$BP_SYSCTL_FILE" | tail -n1
}

# "1,3-5" + "4,8" -> "1,3-5,8" : expand, dedupe, collapse runs (as the kernel writes it)
sysctl_ports_union() {  # <list>...
  printf '%s\n' "$@" | tr ',' '\n' | awk -F'-' '
    /^[0-9]+(-[0-9]+)?$/ { lo = $1 + 0; hi = (NF > 1 ? $2 + 0 : lo); if (hi - lo > 65535) next
                           for (p = lo; p <= hi; p++) if (p >= 1 && p <= 65535) print p }' |
    sort -un | awk '
      NR == 1 { s = $1; e = $1; next }
      $1 == e + 1 { e = $1; next }
      { printf "%s%s", sep, (s == e ? s : s "-" e); sep = ","; s = $1; e = $1 }
      END { if (NR) printf "%s%s", sep, (s == e ? s : s "-" e) }'
}
