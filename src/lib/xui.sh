# shellcheck shell=bash
# mili :: xui.sh - READ-ONLY 3x-ui detection + copy-ready outbound JSON/steps.
# mili NEVER writes to x-ui DB/API/service. It only reads and prints guidance.

XUI_DB=/etc/x-ui/x-ui.db
XUI_BIN=/usr/local/x-ui/x-ui

xui_installed() { [[ -x "$XUI_BIN" || -f "$XUI_DB" ]]; }
xui_running()   { systemctl is-active --quiet x-ui 2>/dev/null; }

xui_panel_port() {
  [[ -x "$XUI_BIN" ]] || return 1
  "$XUI_BIN" setting -show true 2>/dev/null | awk -F': *' '/[Pp]ort/{print $2; exit}'
}

# list inbound tags + ports (read-only). prints "tag|port|protocol"
xui_inbounds() {
  [[ -r "$XUI_DB" ]] && sys_has sqlite3 || return 1
  sqlite3 -readonly "$XUI_DB" \
    "select tag||'|'||port||'|'||protocol from inbounds;" 2>/dev/null
}

xui_status_line() {
  if ! xui_installed; then printf 'not installed'; return; fi
  local p st; p=$(xui_panel_port 2>/dev/null)
  st=$(xui_running && echo running || echo stopped)
  printf '%s (panel:%s)' "$st" "${p:-?}"
}

# produce a SOCKS outbound JSON block for a tunnel's local SOCKS endpoint
xui_socks_json() {  # <tag> <addr> <port> <user> <pass>
  local tag="$1" addr="$2" port="$3" user="$4" pass="$5"
  cat <<EOF
{
  "tag": "$tag",
  "protocol": "socks",
  "settings": {
    "servers": [
      {
        "address": "$addr",
        "port": $port,
        "users": [ { "user": "$user", "pass": "$pass" } ]
      }
    ]
  }
}
EOF
}

# freedom outbound bound to an inner IP (for L3 exit via sendThrough)
xui_freedom_json() {  # <tag> <inner-ip>
  cat <<EOF
{
  "tag": "$1",
  "protocol": "freedom",
  "sendThrough": "$2",
  "settings": {}
}
EOF
}

# routing rule skeleton that steers inbound tags to the mili outbound
xui_routing_json() {  # <outbound-tag> <inboundTag1,inboundTag2,...>
  local ob="$1" inbs="$2" arr
  arr=$(printf '%s' "$inbs" | awk -F, '{for(i=1;i<=NF;i++){printf "\"%s\"%s",$i,(i<NF?", ":"")}}')
  cat <<EOF
{
  "type": "field",
  "inboundTag": [ $arr ],
  "outboundTag": "$ob"
}
EOF
}

# full on-screen helper for one tunnel (SOCKS mode)
xui_help_socks() {  # <name> <addr> <port> <user> <pass>
  local name="$1" addr="$2" port="$3" user="$4" pass="$5"
  ui_head "Use tunnel '$name' with 3x-ui (SOCKS outbound)"
  if ! xui_installed; then
    ui_warn "3x-ui not detected on this server. Steps still apply once installed."
  else
    ui_kv "x-ui status" "$(xui_status_line)"
    echo; ui_info "detected inbound tags you can route:"
    xui_inbounds 2>/dev/null | while IFS='|' read -r t p pr; do ui_note "- $t  (port $p, $pr)"; done
  fi
  echo; ui_info "1) Outbound JSON  (Panel -> Xray Configs -> Outbounds -> + -> JSON):"
  xui_socks_json "mili-$name" "$addr" "$port" "$user" "$pass"
  echo; ui_info "2) Routing rule  (place BEFORE the geoip:private -> blocked rule):"
  xui_routing_json "mili-$name" "<your-inbound-tag>"
  echo; ui_note "3) Save -> Restart Xray. 4) Test from menu (curl --socks5-hostname)."
}
