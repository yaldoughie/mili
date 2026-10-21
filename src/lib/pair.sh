# shellcheck shell=bash
# mili :: pair.sh - pairing code encode/decode (+ optional passphrase) + QR.
#
# Payload = flat "key=value" lines (one record describing what side B needs).
# Wire:   mili1:  <base64url(gzip(payload))>              (plain)
#         mili1e: <base64url(openssl aes-256 pbkdf2 ..)>   (passphrase)
# A checksum line (CKSUM=) is injected so import can detect corruption.

_b64url_enc() { base64 -w0 2>/dev/null | tr '+/' '-_' | tr -d '='; }
_b64url_dec() {
  local s; s="$(printf '%s' "$1" | tr '\-_' '+/')"
  local pad=$(( ${#s} % 4 )); (( pad )) && s="$s$(printf '=%.0s' $(seq $((4-pad))))"
  printf '%s' "$s" | base64 -d 2>/dev/null
}

# checksum is newline-insensitive (grep re-adds a trailing newline on decode)
_payload_cksum() { tr -d '\n' | sha256sum | awk '{print substr($1,1,16)}'; }

# pair_encode <passphrase-or-empty> < payload-on-stdin  -> prints code
pair_encode() {
  local pass="${1:-}" payload cks
  payload="$(cat)"
  cks="$(printf '%s' "$payload" | _payload_cksum)"
  payload="$payload
CKSUM=$cks"
  if [[ -n "$pass" ]]; then
    local enc
    enc="$(printf '%s' "$payload" | gzip -c | openssl enc -aes-256-cbc -pbkdf2 -salt -pass "pass:$pass" 2>/dev/null | _b64url_enc)"
    printf 'mili1e:%s' "$enc"
  else
    printf 'mili1:%s' "$(printf '%s' "$payload" | gzip -c | _b64url_enc)"
  fi
}

# pair_decode <code> [passphrase] -> prints payload (without CKSUM line), verifies
pair_decode() {
  local code="$1" pass="${2:-}" body raw cks_have cks_calc
  case "$code" in
    mili1:*)  body="${code#mili1:}"
              raw="$(_b64url_dec "$body" | gunzip -c 2>/dev/null)" ;;
    mili1e:*) [[ -z "$pass" ]] && { ui_err "encrypted code needs a passphrase"; return 2; }
              body="${code#mili1e:}"
              raw="$(_b64url_dec "$body" | openssl enc -d -aes-256-cbc -pbkdf2 -pass "pass:$pass" 2>/dev/null | gunzip -c 2>/dev/null)" ;;
    *) ui_err "not a mili pairing code"; return 2 ;;
  esac
  [[ -z "$raw" ]] && { ui_err "failed to decode (wrong passphrase or corrupt code)"; return 2; }
  cks_have="$(printf '%s' "$raw" | grep '^CKSUM=' | cut -d= -f2)"
  cks_calc="$(printf '%s' "$raw" | grep -v '^CKSUM=' | _payload_cksum)"
  if [[ -n "$cks_have" && "$cks_have" != "$cks_calc" ]]; then
    ui_err "pairing code checksum mismatch"; return 3
  fi
  printf '%s' "$raw" | grep -v '^CKSUM='
}

# read a field out of a decoded payload:  pair_field <payload> <key>
pair_field() { printf '%s\n' "$1" | awk -F= -v k="$2" '$1==k{sub(/^[^=]*=/,""); print; exit}'; }

# show code as text + QR (if qrencode present)
pair_present() {  # <code> [title]
  local code="$1" title="${2:-Pairing code}"
  ui_head "$title"
  ui_warn "this code contains secrets - share only with the paired server"
  echo
  printf '%s%s%s\n' "${C_YEL:-}" "$code" "${C_RST:-}"
  echo
  if sys_has qrencode && [[ -t 1 ]]; then
    qrencode -t ANSIUTF8 "$code" 2>/dev/null || true
  fi
}
