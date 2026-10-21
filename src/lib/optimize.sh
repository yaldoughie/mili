# shellcheck shell=bash
# mili :: optimize.sh - optional, reversible network tuning (BBR + fq + buffers).
# Writes ONLY /etc/sysctl.d/91-mili-tune.conf. qdisc only ever 'fq'.
# Never touches /etc/sysctl.conf or x-ui's 99-bbr-x-ui.conf.

optimize_status() {
  ui_kv "congestion" "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo ?)"
  ui_kv "qdisc"      "$(sysctl -n net.core.default_qdisc 2>/dev/null || echo ?)"
  if [[ -f "$MILI_SYSCTL_TUNE" ]]; then ui_ok "mili tuning profile active ($MILI_SYSCTL_TUNE)"; else ui_note "mili tuning profile not applied"; fi
}

optimize_apply() {
  if ! modprobe tcp_bbr 2>/dev/null && ! sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr; then
    ui_warn "BBR not available in this kernel; applying buffer tuning only"
  fi
  run bash -c "cat > '$MILI_SYSCTL_TUNE' <<EOF
# mili network tuning (reversible: delete this file + sysctl --system)
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_fastopen = 3
net.core.netdev_max_backlog = 5000
EOF"
  run sysctl --system >/dev/null 2>&1 || true
  ui_ok "tuning applied"
  optimize_status
}

optimize_revert() {
  [[ -f "$MILI_SYSCTL_TUNE" ]] && run rm -f "$MILI_SYSCTL_TUNE"
  run sysctl --system >/dev/null 2>&1 || true
  ui_ok "mili tuning removed (x-ui/system sysctl untouched)"
}
