# shellcheck shell=bash
# mili :: svc.sh - systemd units. Template units installed once; instances
# enabled per tunnel. All names mili-* (never collide with x-ui).

MILI_UNITDIR="/etc/systemd/system"
MILI_BIN="/usr/local/bin/mili"

_svc_reload() { run systemctl daemon-reload; }

# write a unit file only if content changed
svc_write_unit() {  # <unit-filename> <content>
  local name="$1" content="$2" path="$MILI_UNITDIR/$1"
  if [[ -f "$path" ]] && [[ "$(cat "$path" 2>/dev/null)" == "$content" ]]; then
    return 0
  fi
  if [[ "${MILI_DRYRUN:-0}" == 1 ]]; then
    ui_info "[dry] would write unit $path"; printf '%s\n' "$content"; return 0
  fi
  printf '%s\n' "$content" >"$path"
  _svc_reload
}

# install all template units (idempotent). ExecStart uses a per-type launcher
# script that mili renders into /etc/mili/engines. For engine daemons we point
# at the installed core via /opt/mili/bin symlinks.
svc_install_templates() {
  local common="Restart=always
RestartSec=3
LimitNOFILE=1048576
StartLimitIntervalSec=0"

  # generic engine template: mili-<engine>@<name>
  # launched via: mili _svc <engine> <name>  (reads config, execs core)
  local engines=(frps frpc backhaul paqet rathole hy2 singbox gost socks)
  local e
  for e in "${engines[@]}"; do
    svc_write_unit "mili-$e@.service" "[Unit]
Description=mili $e tunnel instance %i
After=network-online.target mili-fw.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=$MILI_BIN _svc $e %i
$common

[Install]
WantedBy=multi-user.target"
  done

  # L3 oneshot (GRE / WG up & down)
  svc_write_unit "mili-l3@.service" "[Unit]
Description=mili L3 tunnel %i
After=network-online.target mili-fw.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$MILI_BIN _l3 up %i
ExecStop=$MILI_BIN _l3 down %i

[Install]
WantedBy=multi-user.target"

  # hedioum singleton
  svc_write_unit "mili-hedioum.service" "[Unit]
Description=mili Hedioum pool tunnel (singleton)
After=network-online.target mili-fw.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=$MILI_BIN _svc hedioum main
$common

[Install]
WantedBy=multi-user.target"

  # firewall restore at boot (rebuilds chains from state)
  svc_write_unit "mili-fw.service" "[Unit]
Description=mili firewall chains restore
After=network-online.target ufw.service firewalld.service
Wants=network-online.target
Before=mili-l3@.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$MILI_BIN _fw-restore

[Install]
WantedBy=multi-user.target"

  # watchdog service + timer
  svc_write_unit "mili-watchdog.service" "[Unit]
Description=mili watchdog (health, self-heal, port audit)
After=network-online.target

[Service]
Type=oneshot
ExecStart=$MILI_BIN _watchdog"

  svc_write_unit "mili-watchdog.timer" "[Unit]
Description=mili watchdog timer

[Timer]
OnBootSec=60
OnUnitActiveSec=60
AccuracySec=10

[Install]
WantedBy=timers.target"

  run systemctl enable --now mili-fw.service       >/dev/null 2>&1 || true
  run systemctl enable --now mili-watchdog.timer   >/dev/null 2>&1 || true
}

# instance control helpers
svc_unit_for() {  # <engine> <name> -> unit string
  printf 'mili-%s@%s.service' "$1" "$2"
}
svc_enable()  { run systemctl enable  "$1" >/dev/null 2>&1 || true; }
svc_start()   { run systemctl start   "$1"; }
svc_stop()    { run systemctl stop    "$1" 2>/dev/null || true; }
svc_restart() { run systemctl restart "$1"; }
svc_disable() { run systemctl disable "$1" >/dev/null 2>&1 || true; }
svc_up()      { svc_enable "$1"; svc_start "$1"; }
svc_down()    { svc_stop "$1"; svc_disable "$1"; }
svc_active()  { systemctl is-active --quiet "$1"; }
svc_status()  { systemctl is-active "$1" 2>/dev/null || echo inactive; }
svc_logs()    { run journalctl -u "$1" -n "${2:-80}" --no-pager; }
svc_logs_follow() { journalctl -u "$1" -f --no-pager; }
