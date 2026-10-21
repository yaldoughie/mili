# shellcheck shell=bash
# mili :: socks.sh - exit-SOCKS helper (gost) used by forward-only / L3 tunnels.
#
# Forward-only engines (Backhaul, FRP, GRE+FRP) and L3 (GRE) do not speak SOCKS
# themselves. On the FOREIGN side mili runs a gost SOCKS5 server; the tunnel
# forwards an Iran localhost port to it. On Iran that localhost port IS the
# SOCKS endpoint the user adds to x-ui as an outbound.
#
# Config file per tunnel: /etc/mili/engines/socks/<name>.env
#   SOCKS_BIND, SOCKS_PORT, SOCKS_USER, SOCKS_PASS

MILI_SOCKS_DIR="$MILI_ETC/engines/socks"

# write a socks helper config (foreign side). bind defaults to inner IP or 127.0.0.1
socks_render() {  # <name> <bind> <port> <user> <pass>
  run mkdir -p "$MILI_SOCKS_DIR"
  local name="$1" bind="$2" port="$3" user="$4" pass="$5"
  local f; f="$MILI_SOCKS_DIR/$name.env"
  if [[ "${MILI_DRYRUN:-0}" == 1 ]]; then
    ui_info "[dry] would write $f (socks $bind:$port)"; return 0
  fi
  cat >"$f" <<EOF
SOCKS_BIND=$bind
SOCKS_PORT=$port
SOCKS_USER=$user
SOCKS_PASS=$pass
EOF
  chmod 600 "$f"
}

# build the gost command for mili-socks@<name> (called by _svc dispatcher)
socks_exec() {  # <name>
  local name="$1" gost f; f="$MILI_SOCKS_DIR/$name.env"
  [[ -f "$f" ]] || die "socks config missing: $f"
  # shellcheck disable=SC1090
  . "$f"
  gost="$(cores_path gost)"
  [[ -x "$gost" ]] || die "gost core not installed"
  if [[ -n "${SOCKS_USER:-}" ]]; then
    exec "$gost" -L "socks5://${SOCKS_USER}:${SOCKS_PASS}@${SOCKS_BIND}:${SOCKS_PORT}?udp=true"
  fi
  # no user = no auth (loopback-only helper reached only through the tunnel)
  exec "$gost" -L "socks5://${SOCKS_BIND}:${SOCKS_PORT}?udp=true"
}

socks_remove() { run rm -f "$MILI_SOCKS_DIR/$1.env" 2>/dev/null || true; }

# the gost client URL string a forwarder points at (for frpc socks5 plugin etc.)
socks_url() {  # <bind> <port> <user> <pass>
  printf 'socks5://%s:%s@%s:%s?udp=true' "$3" "$4" "$1" "$2"
}
