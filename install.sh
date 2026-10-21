#!/usr/bin/env bash
# mili installer / bootstrap.
# Fetches dist/mili.sh (GitHub raw -> proxies -> mirror), installs to
# /usr/local/bin/mili, sets up dirs + systemd templates. x-ui safe.
set -euo pipefail

REPO="${MILI_REPO:-yaldoughie/mili}"
BRANCH="${MILI_BRANCH:-main}"
RAW="https://raw.githubusercontent.com/$REPO/$BRANCH/dist/mili.sh"
PROXIES="${MILI_GH_PROXIES:-https://ghproxy.net/ https://gh-proxy.com/}"
MIRROR="${MILI_MIRROR:-}"
DEST=/usr/local/bin/mili

c_g=$'\e[32m'; c_y=$'\e[33m'; c_r=$'\e[31m'; c_0=$'\e[0m'
say() { printf '%s==>%s %s\n' "$c_g" "$c_0" "$*"; }
warn() { printf '%s[!]%s %s\n' "$c_y" "$c_0" "$*"; }
err() { printf '%s[x]%s %s\n' "$c_r" "$c_0" "$*" >&2; }

[[ "${EUID:-$(id -u)}" -eq 0 ]] || { err "run as root (sudo)"; exit 1; }

command -v curl >/dev/null 2>&1 || { apt-get update -qq && apt-get install -y -qq curl; }

tmp="$(mktemp)"
got=0
say "downloading mili"
if curl -fsSL "$RAW" -o "$tmp" 2>/dev/null; then got=1; say "fetched from GitHub"; fi
if [[ $got -eq 0 ]]; then
  for p in $PROXIES; do
    if curl -fsSL "${p}${RAW}" -o "$tmp" 2>/dev/null; then got=1; say "fetched via proxy"; break; fi
  done
fi
if [[ $got -eq 0 && -n "$MIRROR" ]]; then
  curl -fsSL "${MIRROR%/}/mili.sh" -o "$tmp" 2>/dev/null && got=1 && say "fetched from mirror"
fi
if [[ $got -eq 0 ]]; then
  err "could not download mili.sh"
  warn "offline install: copy dist/mili.sh to $DEST, chmod +x, run 'mili'"
  exit 1
fi

# sanity check
head -1 "$tmp" | grep -q bash || { err "downloaded file is not a script"; exit 1; }
bash -n "$tmp" || { err "syntax check failed on downloaded script"; exit 1; }

install -m 0755 "$tmp" "$DEST"
rm -f "$tmp"
say "installed to $DEST"

# base deps (idempotent)
say "installing base dependencies"
DEBIAN_FRONTEND=noninteractive apt-get update -qq || warn "apt update failed"
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  iproute2 iptables curl jq sqlite3 openssl ca-certificates tar unzip kmod || warn "some deps failed"

say "mili installed. Run:  mili"
printf '  %sx-ui is never modified by mili. Install order does not matter.%s\n' "$c_y" "$c_0"
