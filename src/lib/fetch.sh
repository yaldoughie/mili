# shellcheck shell=bash
# mili :: fetch.sh - multi-source downloader + checksum verify + bundle + peer.
#
# Source chain (order from settings, default below):
#   github -> github proxy prefixes -> MILI_MIRROR -> custom URL -> local -> peer
# Each core manifest supplies a github asset URL; this layer tries alternatives.

MILI_CACHE="${MILI_CACHE:-$MILI_ETC/cache}"
# editable in settings; space-separated prefixes prepended to a github URL
MILI_GH_PROXIES="${MILI_GH_PROXIES:-https://ghproxy.net/ https://mirror.ghproxy.com/ https://gh-proxy.com/}"
MILI_MIRROR="${MILI_MIRROR:-}"          # user's own releases base (placeholder)
MILI_LOCAL_DIR="${MILI_LOCAL_DIR:-$MILI_ETC/offline}"

_dl() {  # <url> <out> -> 0 on success
  local url="$1" out="$2"
  # short, bounded: a dead/404 source fails fast instead of hanging minutes
  curl -fL --connect-timeout 8 --max-time 90 --retry 1 --retry-max-time 20 -o "$out" "$url" 2>/dev/null
}

# fetch_url <github-url> <out> : try chain until one works
fetch_url() {
  local ghurl="$1" out="$2" base name p
  name="$(basename "$ghurl")"
  mkdir -p "$(dirname "$out")" 2>/dev/null || true

  ui_info "fetching $name"
  # 1. direct github
  _dl "$ghurl" "$out" && { ui_ok "got $name (github)"; return 0; }
  # 2. github proxies
  for p in $MILI_GH_PROXIES; do
    _dl "${p}${ghurl}" "$out" && { ui_ok "got $name (proxy ${p%%/*})"; return 0; }
  done
  # 3. own mirror
  if [[ -n "$MILI_MIRROR" ]]; then
    _dl "${MILI_MIRROR%/}/$name" "$out" && { ui_ok "got $name (mirror)"; return 0; }
  fi
  # 4. local offline dir
  if [[ -f "$MILI_LOCAL_DIR/$name" ]]; then
    cp -f "$MILI_LOCAL_DIR/$name" "$out" && { ui_ok "got $name (offline)"; return 0; }
  fi
  ui_err "all sources failed for $name"
  return 1
}

# fetch with explicit custom URL override
fetch_custom() { _dl "$1" "$2" && ui_ok "got $(basename "$2") (custom url)"; }

# verify_sha256 <file> <expected-hex>  ('' or 'skip' = skip)
verify_sha256() {
  local file="$1" want="$2" got
  [[ -z "$want" || "$want" == skip ]] && { ui_note "checksum skipped for $(basename "$file")"; return 0; }
  got=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
  if [[ "$got" == "$want" ]]; then ui_ok "sha256 verified"; return 0; fi
  ui_err "sha256 mismatch for $(basename "$file")"
  ui_note "want $want"
  ui_note "got  $got"
  return 1
}

# ---- offline bundle --------------------------------------------------------
# bundle every installed core into a tar for air-gapped transfer
fetch_bundle() {  # [out.tar.gz]
  local out="${1:-/root/mili-cores-$(date +%Y%m%d).tar.gz}"
  [[ -d /opt/mili/bin ]] || { ui_err "no cores installed"; return 1; }
  run tar -czf "$out" -C /opt/mili bin store && ui_ok "bundle -> $out"
}
fetch_bundle_import() {  # <tar.gz>
  local tar="$1"
  [[ -f "$tar" ]] || { ui_err "no such file: $tar"; return 1; }
  run mkdir -p /opt/mili
  run tar -xzf "$tar" -C /opt/mili && ui_ok "cores imported from $tar"
}

# ---- peer serve / pull (polished in pass 2; basic path here) ---------------
# foreign: serve /opt/mili/bin over a temporary authenticated http (gost);
# prints a mili-cores: code. iran: pull by code. Requires gost core present.
fetch_peer_serve() {
  local port user pass code gost=/opt/mili/bin/gost
  [[ -x "$gost" ]] || { ui_warn "gost core required for peer serve (install in Cores menu)"; return 1; }
  port=$(ports_alloc_internal) || { ui_err "no free port"; return 1; }
  user=mili; pass=$(sys_rand_token 20)
  ui_info "serving /opt/mili/bin on :$port for 10 minutes"
  fw_allow "coreserve" tcp "$port"
  ( "$gost" -L "http://$user:$pass@0.0.0.0:$port/?dir=/opt/mili/bin" >/dev/null 2>&1 &
    local sp=$!; sleep 600; kill "$sp" 2>/dev/null ) &
  code=$(printf 'mili-cores:%s|%s|%s|%s' "$(sys_public_ip4)" "$port" "$user" "$pass" | base64 -w0 2>/dev/null || \
         printf 'mili-cores:%s|%s|%s|%s' "$(sys_public_ip4)" "$port" "$user" "$pass" | base64)
  echo
  ui_ok "share this pull code (valid 10 min):"
  printf '  %s%s%s\n' "$C_YEL" "$code" "$C_RST"
}
fetch_peer_pull() {  # <code>
  local code="${1#mili-cores:}" dec ip port user pass
  dec=$(printf '%s' "${1#mili-cores:}" | base64 -d 2>/dev/null) || dec="$1"
  IFS='|' read -r ip port user pass <<<"${dec#mili-cores:}"
  [[ -n "$ip" && -n "$port" ]] || { ui_err "bad pull code"; return 1; }
  ui_info "pulling cores from $ip:$port"
  run mkdir -p /opt/mili/bin
  curl -fsSL "http://$user:$pass@$ip:$port/" 2>/dev/null | grep -oE 'href="[^"]+"' | sed 's/href="//;s/"//' \
    | while read -r item; do
        [[ "$item" == ../ || -z "$item" ]] && continue
        curl -fsSL "http://$user:$pass@$ip:$port/$item" -o "/opt/mili/bin/$item" 2>/dev/null && ui_ok "pulled $item"
      done
}
