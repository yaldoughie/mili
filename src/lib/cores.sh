# shellcheck shell=bash
# mili :: cores.sh - core binary manifest + install / update / rollback.
#
# Layout:  /opt/mili/bin/<core>/<ver>/<binary>   (versioned)
#          /opt/mili/bin/<core>  -> symlink to active binary (rollback = repoint)
# Manifest fields resolved per core + arch. Versions are PINNED & tested.
# NOTE: asset-name patterns flagged "verify" in the plan are confirmed at
# install time by the multi-source fetcher; adjust here if upstream renames.

MILI_OPT="/opt/mili"
MILI_COREBIN="$MILI_OPT/bin"

# cores_manifest <core> -> prints: VER REPO ASSET ARCHMAP EXTRACT BINARIES
# ASSET uses %V (version without v) and %A (mapped arch). BINARIES space list.
cores_version() {
  case "$1" in
    frp)      echo "0.71.1" ;;
    backhaul) echo "0.7.2" ;;
    paqet)    echo "1.0.0-alpha.21" ;;
    hedioum)  echo "0.11.0" ;;
    gost)     echo "3.3.0" ;;
    rathole)  echo "0.5.0" ;;
    hysteria) echo "2.13.0" ;;
    singbox)  echo "1.10.3" ;;
    *) return 1 ;;
  esac
}

# map mili arch -> core-specific arch token
_core_arch() {  # <core> <miliarch>
  local core="$1" a="$2"
  case "$core" in
    frp|gost|hysteria|singbox|paqet)
      case "$a" in amd64) echo amd64;; arm64) echo arm64;; armv7) echo arm;; *) echo "$a";; esac ;;
    backhaul)
      case "$a" in amd64) echo amd64;; arm64) echo arm64;; *) echo "$a";; esac ;;
    rathole)
      case "$a" in amd64) echo x86_64;; arm64) echo aarch64;; armv7) echo armv7;; *) echo "$a";; esac ;;
    *) echo "$a" ;;
  esac
}

# download URL (github) for a core
cores_url() {  # <core>
  local core="$1" v a; v=$(cores_version "$core") || return 1
  a=$(_core_arch "$core" "$MILI_ARCH")
  case "$core" in
    frp)      echo "https://github.com/fatedier/frp/releases/download/v$v/frp_${v}_linux_${a}.tar.gz" ;;
    backhaul) echo "https://github.com/Musixal/Backhaul/releases/download/v$v/backhaul_linux_${a}.tar.gz" ;;
    gost)     echo "https://github.com/go-gost/gost/releases/download/v$v/gost_${v}_linux_${a}.tar.gz" ;;
    paqet)    echo "https://github.com/hanselime/paqet/releases/download/v$v/paqet_linux_${a}.tar.gz" ;;
    hedioum)  echo "https://github.com/hedioum/Hedioum-Pool-Tunnel/releases/download/v$v/hedioum-tunnel_linux_${a}.tar.gz" ;;
    rathole)  echo "https://github.com/rapiz1/rathole/releases/download/v$v/rathole-${a}-unknown-linux-musl.zip" ;;
    hysteria) echo "https://github.com/apernet/hysteria/releases/download/app/v$v/hysteria-linux-${a}" ;;
    singbox)  echo "https://github.com/SagerNet/sing-box/releases/download/v$v/sing-box-${v}-linux-${a}.tar.gz" ;;
    *) return 1 ;;
  esac
}

# binaries produced by a core and their final symlink names
cores_binaries() {  # <core>
  case "$1" in
    frp)      echo "frps frpc" ;;
    backhaul) echo "backhaul" ;;
    gost)     echo "gost" ;;
    paqet)    echo "paqet" ;;
    hedioum)  echo "hedioum-tunnel" ;;
    rathole)  echo "rathole" ;;
    hysteria) echo "hysteria" ;;
    singbox)  echo "sing-box" ;;
    *) return 1 ;;
  esac
}

cores_installed_version() {  # <core> -> prints installed ver or empty
  local core="$1" link="$MILI_COREBIN/$core"
  # first binary of the set acts as the probe
  local first; first=$(cores_binaries "$core" | awk '{print $1}')
  link="$MILI_COREBIN/$first"
  [[ -L "$link" ]] || return 1
  readlink "$link" 2>/dev/null | sed -E "s#.*/$core/([^/]+)/.*#\1#"
}

cores_is_installed() {  # <core>
  local first; first=$(cores_binaries "$1" | awk '{print $1}')
  [[ -x "$MILI_COREBIN/$first" ]]
}

# install (or reinstall) a core at its pinned version
cores_install() {  # <core>
  local core="$1" v url bins b arch dst tmp f
  v=$(cores_version "$core") || { ui_err "unknown core: $core"; return 1; }
  url=$(cores_url "$core")   || { ui_err "no url for: $core"; return 1; }
  bins=$(cores_binaries "$core")
  dst="$MILI_COREBIN/$core/$v"
  run mkdir -p "$dst"
  tmp="$(mktemp -d)"; f="$tmp/$(basename "$url")"

  fetch_url "$url" "$f" || { rm -rf "$tmp"; return 1; }

  # extract by type
  case "$f" in
    *.tar.gz|*.tgz) tar -xzf "$f" -C "$tmp" 2>/dev/null || { ui_err "extract failed"; rm -rf "$tmp"; return 1; } ;;
    *.zip)          unzip -oq "$f" -d "$tmp" 2>/dev/null || { ui_err "unzip failed"; rm -rf "$tmp"; return 1; } ;;
    *)              cp -f "$f" "$tmp/$(echo "$bins" | awk '{print $1}')" ;;  # raw binary (hysteria)
  esac

  # locate each expected binary anywhere under tmp and place it
  for b in $bins; do
    local found; found=$(find "$tmp" -type f -name "$b" 2>/dev/null | head -n1)
    [[ -z "$found" ]] && found=$(find "$tmp" -type f -iname "$b*" 2>/dev/null | head -n1)
    if [[ -z "$found" ]]; then ui_err "binary '$b' not found in $core archive"; rm -rf "$tmp"; return 1; fi
    run cp -f "$found" "$dst/$b"
    run chmod +x "$dst/$b"
    run ln -sfn "$dst/$b" "$MILI_COREBIN/$b"
  done
  rm -rf "$tmp"
  ui_ok "$core $v installed"
}

cores_ensure() { cores_is_installed "$1" || cores_install "$1"; }

# rollback: repoint symlinks to another installed version
cores_versions_present() {  # <core>
  ls -1 "$MILI_COREBIN/$1" 2>/dev/null | grep -vE '^[a-z-]+$' || true
}
cores_rollback() {  # <core> <ver>
  local core="$1" ver="$2" b
  [[ -d "$MILI_COREBIN/$core/$ver" ]] || { ui_err "version $ver not present"; return 1; }
  for b in $(cores_binaries "$core"); do
    [[ -f "$MILI_COREBIN/$core/$ver/$b" ]] && run ln -sfn "$MILI_COREBIN/$core/$ver/$b" "$MILI_COREBIN/$b"
  done
  ui_ok "$core rolled back to $ver"
}

cores_path() { printf '%s' "$MILI_COREBIN/$1"; }   # path to active binary symlink
