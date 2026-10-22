# shellcheck shell=bash
# mili :: tunnels/backpack.sh - AminMGMT/BackPack v1.8.5, reverse tunnels.
#
# NATIVE flow (no mili pairing code). mili asks BackPack's own Iran wizard
# questions, in BackPack's order and wording, then hands the answers to
# BackPack itself and moves only BackPack's own setup link between servers:
#   IRAN    (server, listens): backpack node exec  {"op":"apply", NewTunnel}
#           -> /etc/backpack/<name>.toml + backpack-<name>.service, written and
#              validated by BackPack's own code (the path its web panel uses).
#           mili then shows the backpack:// setup link, built from that config
#           exactly as BackPack's shareLinkOf builds it (format 2, byte-identical).
#   FOREIGN (kharej, dials):   backpack link apply --name <name> '<link>'
#           (BackPack's own non-interactive kharej setup).
#
# Usage on top (mili addition, as for Backhaul):
#   socks   - Iran forwards 127.0.0.1:<iran_socks> (loopback only) to the kharej's
#             127.0.0.1:<proxy>, where BackPack's built-in SOCKS5 proxy runs
#             (backpack proxy enable socks5 <proxy>). 3x-ui on Iran -> 127.0.0.1:<iran_socks>.
#   forward - BackPack's own Forwarded Ports list.
#
# Facts pinned to v1.8.5: one built-in proxy per server; every create runs
# BackPack's optimizer (/etc/sysctl.d/zz-backpack.conf, its own reserved-ports
# list - mili unions its ports back in, see ports_sync_reserved).

t_register backpack
feature "tunnel.backpack" free

BP_BIN="${BP_BIN:-/usr/local/bin/backpack}"
BP_ETC="${BP_ETC:-/etc/backpack}"
BP_UNITDIR="${BP_UNITDIR:-/etc/systemd/system}"
BP_VERSION="1.8.5"
BP_CHARSET="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
# setup-link field ids, never reordered (sharelinkv2.go shareFieldIDs). v1.8.5
# writes 0..35; 36.. are newer builds' managed-HTTPS fields, read but never written.
BP_FIELDS=(k f n t tr e sni p h pr po u m mt li pi fd fp pa gk lm am sp su sd ss sl si sa mv hs rh rm ft fw ed
           hi hu hp hid hn hpa hh hk hsid hca)
BP_FIELDS_V185=36
BP_WORDS=(reverse direct iran kharej tcp tcpmux stealth pck ws wss wsmux wssmux kcp quic udp
          xdi sni spoof gre balance turbo aggressive throughput)

# ============================================================================
# transport facts (internal/manage/spec/transport.go)
# ============================================================================
_bp_is_mux()      { [[ " tcpmux wsmux wssmux kcp pck " == *" $1 "* ]]; }
_bp_is_kcp()      { [[ " kcp pck " == *" $1 "* ]]; }
_bp_is_datagram() { [[ " udp kcp quic pck " == *" $1 "* ]]; }
_bp_is_ws()       { [[ " ws wss wsmux wssmux " == *" $1 "* ]]; }
_bp_needs_tls()   { [[ "$1" == wss || "$1" == wssmux ]]; }
_bp_proxy_proto_ok() { [[ " tcp tcpmux kcp wsmux wssmux stealth quic pck " == *" $1 "* ]]; }
_bp_valid_transport() { [[ " tcp tcpmux stealth pck udp kcp quic ws wsmux wss wssmux " == *" $1 "* ]]; }
# the tunnel port is a UDP socket for these (pck builds its own TCP segments)
_bp_port_proto() { case "$1" in udp|kcp|quic) echo udp ;; *) echo tcp ;; esac; }

_bp_transport_label() {
  case "$1" in
    tcp) echo "TCP" ;; tcpmux) echo "TCP Mux" ;; stealth) echo "TCP + Stealth" ;; pck) echo "TCP + PCK" ;;
    udp) echo "UDP" ;; kcp) echo "UDP + KCP + FEC" ;; quic) echo "UDP + QUIC" ;;
    ws) echo "WS" ;; wsmux) echo "WS Mux" ;; wss) echo "WSS" ;; wssmux) echo "WSS Mux" ;;
    *) echo "$1" ;;
  esac
}

_bp_preset_label() {
  case "$1" in
    balance) echo Balance ;; turbo) echo Turbo ;; aggressive) echo Aggressive ;; throughput) echo Throughput ;;
    '') echo Custom ;; *) echo "$1" ;;
  esac
}

# ============================================================================
# setup link codec (sharelink.go + sharelinkv2.go, v1.8.5) - pure, bats-tested
# ============================================================================
declare -gA BL=()          # one decoded / to-be-encoded link, keyed by field tag
declare -ga BPB=()         # byte buffer (decimal 0..255)
declare -gA BP_CI=() BP_B62W=()
declare -ga BP_CRCT=()

_bp_kind() {  # <tag> -> s|i|u|b|p|l
  case "$1" in
    m|mt|fd|fp|pa|lm|mv|rh|rm|fw) echo i ;;
    gk) echo u ;;
    u|sl|si|sa) echo b ;;
    am) echo p ;;
    hs|ft) echo l ;;
    *) echo s ;;
  esac
}

_bp_ci_init() {
  (( ${#BP_CI[@]} )) && return 0
  local i; for (( i = 0; i < 62; i++ )); do BP_CI[${BP_CHARSET:i:1}]=$i; done
}

_bp_crc_init() {
  (( ${#BP_CRCT[@]} )) && return 0
  local n c k
  for (( n = 0; n < 256; n++ )); do
    c=$n
    for (( k = 0; k < 8; k++ )); do
      if (( c & 1 )); then c=$(( 0xEDB88320 ^ (c >> 1) )); else c=$(( c >> 1 )); fi
    done
    BP_CRCT[n]=$c
  done
}

_bp_crc32() {  # <bytes...> -> CRC-32/IEEE (same as Go crc32.ChecksumIEEE)
  _bp_crc_init
  local c=0xFFFFFFFF b
  for b in "$@"; do c=$(( BP_CRCT[(c ^ b) & 255] ^ (c >> 8) )); done
  printf '%s' $(( c ^ 0xFFFFFFFF ))
}

# convert a big number between bases. In: BPC_IN (most significant first).
# Out: BPC_OUT (most significant first, no leading zeros; "0" -> (0)).
_bp_conv() {  # <from> <to>
  local from="$1" to="$2" i cur dig rem
  local -a num=("${BPC_IN[@]}") out=() q
  while (( ${#num[@]} )); do
    q=(); rem=0
    for i in "${num[@]}"; do
      cur=$(( rem * from + i )); dig=$(( cur / to )); rem=$(( cur % to ))
      if (( ${#q[@]} || dig )); then q+=("$dig"); fi
    done
    out=("$rem" "${out[@]}")
    num=("${q[@]}")
  done
  (( ${#out[@]} )) || out=(0)
  BPC_OUT=("${out[@]}")
}

_bp_b62_width() {  # <len> -> bytes that hold any len-digit base-62 number
  local L="$1"
  (( L > 0 )) || { printf '0'; return; }
  if [[ -z "${BP_B62W[$L]:-}" ]]; then
    local i; BPC_IN=(); for (( i = 0; i < L; i++ )); do BPC_IN+=(61); done
    _bp_conv 62 256; BP_B62W[$L]=${#BPC_OUT[@]}
  fi
  printf '%s' "${BP_B62W[$L]}"
}

# packBase62: s (token alphabet) as a big-endian number in width bytes -> BPK
_bp_b62_pack() {  # <s>
  _bp_ci_init
  local s="$1" L=${#1} i w
  BPC_IN=(); for (( i = 0; i < L; i++ )); do BPC_IN+=("${BP_CI[${s:i:1}]}"); done
  _bp_conv 62 256
  w="$(_bp_b62_width "$L")"
  BPK=()
  for (( i = ${#BPC_OUT[@]}; i < w; i++ )); do BPK+=(0); done
  BPK+=("${BPC_OUT[@]}")
}

_bp_b62_unpack() {  # <len> <bytes...> -> prints the string (rc 1 = not one we wrote)
  _bp_ci_init
  local L="$1" i s=''; shift
  BPC_IN=("$@"); _bp_conv 256 62
  if (( ${#BPC_OUT[@]} > L )); then
    [[ "${BPC_OUT[*]}" == 0 ]] || return 1
  fi
  for (( i = ${#BPC_OUT[@]}; i < L; i++ )); do s+=a; done
  for i in "${BPC_OUT[@]}"; do s+="${BP_CHARSET:i:1}"; done
  (( ${#s} == L )) || s="${s: -L}"
  printf '%s' "$s"
}

_bp_put_uvarint() {  # <n >= 0>
  local n="$1"
  while (( n >= 128 )); do BPB+=($(( (n & 127) | 128 ))); n=$(( n >> 7 )); done
  BPB+=("$n")
}
_bp_put_varint() {  # <n> (Go binary.AppendVarint, zigzag)
  local n="$1" ux
  ux=$(( n << 1 )); (( n < 0 )) && ux=$(( ~ux ))
  _bp_put_uvarint "$ux"
}

_bp_str_bytes() {  # <s> -> BPS (UTF-8 bytes)
  BPS=()
  [[ -z "$1" ]] && return 0
  read -ra BPS <<<"$(printf '%s' "$1" | od -An -tu1 -v | tr -s ' \n' '  ')"
}

_bp_is_ipv4_canon() {
  local re='^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$'
  [[ "$1" =~ $re ]] || return 1
  (( BASH_REMATCH[1] <= 255 && BASH_REMATCH[2] <= 255 && BASH_REMATCH[3] <= 255 && BASH_REMATCH[4] <= 255 ))
}

# appendShareString: word -> IPv4 -> number -> base-62 -> raw
_bp_put_str() {  # <s>
  local s="$1" i w
  for i in "${!BP_WORDS[@]}"; do [[ "${BP_WORDS[$i]}" == "$s" ]] && { BPB+=(1 "$i"); return; }; done
  if _bp_is_ipv4_canon "$s"; then
    local IFS=.; local -a o=($s); BPB+=(2 "${o[@]}"); return
  fi
  if [[ "$s" =~ ^(0|[1-9][0-9]{0,9})$ ]] && (( s <= 4294967295 )); then
    BPB+=(3); _bp_put_uvarint "$s"; return
  fi
  if [[ "$s" =~ ^[a-zA-Z0-9]+$ ]] && (( ${#s} <= 255 )); then
    w="$(_bp_b62_width "${#s}")"
    if (( w + 2 < ${#s} + 1 )); then
      _bp_b62_pack "$s"; BPB+=(4 "${#s}" "${BPK[@]}"); return
    fi
  fi
  _bp_str_bytes "$s"
  BPB+=(0); _bp_put_uvarint "${#BPS[@]}"; BPB+=("${BPS[@]}")
}

_bp_default_name() {  # from BL (defaultShareName)
  local p="${BL[p]:-}" k="${BL[k]:-}" f="${BL[f]:-}"
  [[ -z "$p" ]] && return 0
  case "$k/${f,,}" in
    reverse/iran)   printf 'server-%s' "$p" ;;
    reverse/*)      printf 'client-%s' "$p" ;;
    direct/iran)    printf 'l3-iran-%s' "$p" ;;
    direct/*)       printf 'l3-kharej-%s' "$p" ;;
  esac
}

_bp_bytes_b64url() {  # <bytes...>
  local b x f=''
  for b in "$@"; do printf -v x '\\x%02x' "$b"; f+="$x"; done
  printf '%b' "$f" | base64 -w0 | tr '+/' '-_' | tr -d '='
}

# encodeShareLinkV2 from BL. Lists (hs ft) are newline separated; bools 1/true.
_bp_link_encode() {
  BPB=()
  local id tag v def kind it sum
  for (( id = 0; id < BP_FIELDS_V185; id++ )); do
    tag="${BP_FIELDS[$id]}"; v="${BL[$tag]-}"
    if [[ "$tag" == n ]]; then
      def="$(_bp_default_name)"
      [[ "$v" == "$def" ]] && continue
      [[ -z "$v" ]] && { BPB+=("$id" 0 0); continue; }
    fi
    kind="$(_bp_kind "$tag")"
    case "$kind" in
      s) [[ -z "$v" ]] && continue; BPB+=("$id"); _bp_put_str "$v" ;;
      i) [[ -z "$v" || "$v" == 0 ]] && continue; BPB+=("$id"); _bp_put_varint "$v" ;;
      u) [[ -z "$v" || "$v" == 0 ]] && continue; BPB+=("$id"); _bp_put_uvarint "$v" ;;
      b) [[ "$v" == 1 || "$v" == true ]] || continue; BPB+=("$id") ;;
      p) [[ -z "$v" ]] && continue; BPB+=("$id"); if [[ "$v" == 1 || "$v" == true ]]; then BPB+=(1); else BPB+=(0); fi ;;
      l) [[ -z "$v" ]] && continue
         local -a items=(); mapfile -t items <<<"$v"
         BPB+=("$id"); _bp_put_uvarint "${#items[@]}"
         for it in "${items[@]}"; do _bp_put_str "$it"; done ;;
    esac
  done
  sum="$(_bp_crc32 "${BPB[@]}")"
  BPB+=($(( (sum >> 16) & 255 )) $(( (sum >> 8) & 255 )) $(( sum & 255 )))
  printf 'backpack://2.%s' "$(_bp_bytes_b64url "${BPB[@]}")"
}

_bp_b64url_bytes() {  # <payload> -> decimal bytes on one line (empty on error)
  local s="$1"
  [[ "$s" =~ ^[A-Za-z0-9_-]*$ ]] || return 1
  s="${s//-/+}"; s="${s//_//}"
  while (( ${#s} % 4 )); do s+='='; done
  printf '%s' "$s" | base64 -d 2>/dev/null | od -An -tu1 -v | tr -s ' \n' '  '
}

# the readers below walk BPD from BPI
_bp_get_uvarint() {
  local n=0 shift_=0 b
  while :; do
    (( BPI < ${#BPD[@]} )) || return 1
    b=${BPD[BPI]}; BPI=$(( BPI + 1 ))
    n=$(( n | ((b & 127) << shift_) ))
    (( b < 128 )) && break
    shift_=$(( shift_ + 7 )); (( shift_ > 63 )) && return 1
  done
  BPV=$n
}
_bp_get_varint() {
  _bp_get_uvarint || return 1
  local ux=$BPV
  BPV=$(( ux >> 1 )); (( ux & 1 )) && BPV=$(( ~BPV ))
  return 0
}
_bp_get_str() {  # -> BPV
  (( BPI < ${#BPD[@]} )) || return 1
  local mode=${BPD[BPI]} n i x f=''
  BPI=$(( BPI + 1 ))
  case "$mode" in
    1) (( BPI < ${#BPD[@]} )) || return 1
       n=${BPD[BPI]}; BPI=$(( BPI + 1 ))
       (( n < ${#BP_WORDS[@]} )) || { BL_ERR="this setup link was made by a newer version — update this server"; return 1; }
       BPV="${BP_WORDS[$n]}" ;;
    2) (( BPI + 4 <= ${#BPD[@]} )) || return 1
       BPV="${BPD[BPI]}.${BPD[BPI+1]}.${BPD[BPI+2]}.${BPD[BPI+3]}"; BPI=$(( BPI + 4 )) ;;
    3) _bp_get_uvarint || return 1 ;;
    4) (( BPI < ${#BPD[@]} )) || return 1
       n=${BPD[BPI]}; BPI=$(( BPI + 1 ))
       local w; w="$(_bp_b62_width "$n")"
       (( BPI + w <= ${#BPD[@]} )) || return 1
       BPV="$(_bp_b62_unpack "$n" "${BPD[@]:BPI:w}")" || return 1
       BPI=$(( BPI + w )) ;;
    0) _bp_get_uvarint || return 1
       n=$BPV
       (( BPI + n <= ${#BPD[@]} )) || return 1
       for (( i = 0; i < n; i++ )); do printf -v x '\\x%02x' "${BPD[BPI+i]}"; f+="$x"; done
       printf -v BPV '%b' "$f"; BPI=$(( BPI + n )) ;;
    *) return 1 ;;
  esac
  return 0
}

_bp_decode_v2() {  # <payload> -> BL
  local -a raw=(); read -ra raw <<<"$(_bp_b64url_bytes "$1")"
  local dmg="the setup link is damaged — copy it again, all of it"
  (( ${#raw[@]} >= 4 )) || { BL_ERR="$dmg"; return 1; }
  local nb=$(( ${#raw[@]} - 3 )) sum
  BPD=("${raw[@]:0:nb}")
  sum="$(_bp_crc32 "${BPD[@]}")"
  if (( raw[nb] != ((sum >> 16) & 255) || raw[nb+1] != ((sum >> 8) & 255) || raw[nb+2] != (sum & 255) )); then
    BL_ERR="the setup link is incomplete or damaged — copy the whole of it again"; return 1
  fi
  BPI=0
  local id tag kind cnt j items named=0
  while (( BPI < ${#BPD[@]} )); do
    id=${BPD[BPI]}; BPI=$(( BPI + 1 ))
    (( id < ${#BP_FIELDS[@]} )) || { BL_ERR="this setup link was made by a newer version — update this server"; return 1; }
    tag="${BP_FIELDS[$id]}"; kind="$(_bp_kind "$tag")"
    case "$kind" in
      s) _bp_get_str || { BL_ERR="${BL_ERR:-$dmg}"; return 1; }; BL[$tag]="$BPV"; [[ "$tag" == n ]] && named=1 ;;
      i) _bp_get_varint || { BL_ERR="$dmg"; return 1; }; BL[$tag]="$BPV" ;;
      u) _bp_get_uvarint || { BL_ERR="$dmg"; return 1; }; BL[$tag]="$BPV" ;;
      b) BL[$tag]=1 ;;
      p) (( BPI < ${#BPD[@]} )) || { BL_ERR="$dmg"; return 1; }
         BL[$tag]=$([[ ${BPD[BPI]} == 1 ]] && echo true || echo false); BPI=$(( BPI + 1 )) ;;
      l) _bp_get_uvarint || { BL_ERR="$dmg"; return 1; }
         cnt=$BPV; (( cnt <= 64 )) || { BL_ERR="$dmg"; return 1; }
         items=''
         for (( j = 0; j < cnt; j++ )); do
           _bp_get_str || { BL_ERR="${BL_ERR:-$dmg}"; return 1; }
           items+="${items:+$'\n'}$BPV"
         done
         BL[$tag]="$items" ;;
    esac
  done
  (( named )) || BL[n]="$(_bp_default_name)"
  return 0
}

# format 1 (older builds): gzipped JSON
_bp_decode_v1() {  # <payload>
  local s="$1" json k v
  s="${s//-/+}"; s="${s//_//}"; while (( ${#s} % 4 )); do s+='='; done
  json="$(printf '%s' "$s" | base64 -d 2>/dev/null | gzip -dc 2>/dev/null | head -c 65536)"
  [[ "$json" == \{* ]] || { BL_ERR="the setup link is damaged — copy it again, all of it"; return 1; }
  json="${json//\\u003c/<}"; json="${json//\\u003e/>}"; json="${json//\\u0026/&}"
  for k in k f n t tr e sni p h pr po li pi sp su sd ss ed; do
    v="$(printf '%s' "$json" | sed -n "s/.*[{,]\"$k\":\"\([^\"]*\)\".*/\1/p")"
    [[ -n "$v" ]] && BL[$k]="$v"
  done
  for k in m mt fd fp pa gk lm mv rh rm fw; do
    v="$(printf '%s' "$json" | sed -n "s/.*[{,]\"$k\":\(-\{0,1\}[0-9][0-9]*\).*/\1/p")"
    [[ -n "$v" ]] && BL[$k]="$v"
  done
  for k in u sl si sa; do
    printf '%s' "$json" | grep -q "[{,]\"$k\":true" && BL[$k]=1
  done
  for k in hs ft; do
    v="$(printf '%s' "$json" | sed -n "s/.*[{,]\"$k\":\[\([^]]*\)\].*/\1/p")"
    [[ -n "$v" ]] && BL[$k]="$(printf '%s' "$v" | tr ',' '\n' | sed 's/^"//; s/"$//')"
  done
  return 0
}

# _bp_link_decode <text> : 0 = valid reverse/direct setup link (BL filled), 1 = BL_ERR
_bp_link_decode() {
  local s body ver payload
  BL=(); BL_ERR=''
  s="$(_bp_find_link "$1")"
  [[ -z "$s" ]] && { BL_ERR="paste the setup link from the other server"; return 1; }
  if [[ "$s" != backpack://* ]]; then
    BL_ERR="that does not look like a Backpack setup link — it should begin with backpack://"; return 1
  fi
  body="${s#backpack://}"
  [[ "$body" == *.* ]] || { BL_ERR="the setup link is incomplete — copy the whole of it, including the end"; return 1; }
  ver="${body%%.*}"; payload="${body#*.}"
  case "$ver" in
    2) _bp_decode_v2 "$payload" || return 1 ;;
    1) _bp_decode_v1 "$payload" || return 1 ;;
    *) BL_ERR="this setup link is version $ver and this server understands versions 1 and 2 — update the older of the two machines"; return 1 ;;
  esac
  if [[ -z "${BL[t]:-}" || -z "${BL[tr]:-}" ]]; then
    BL_ERR="the setup link is missing the token or the transport — it was not made by this version"; return 1
  fi
  [[ "${BL[k]:-}" == reverse || "${BL[k]:-}" == direct ]] || { BL_ERR="the setup link does not say what kind of tunnel it is"; return 1; }
  return 0
}

# a link pasted inside a message, in quotes or broken over lines (FindSetupLink)
_bp_find_link() {
  local s; s="$(printf '%s' "$1" | tr -d '\r\n\t ')"
  s="${s#\'}"; s="${s%\'}"; s="${s#\"}"; s="${s%\"}"
  if [[ "$s" == *backpack://* ]]; then
    s="backpack://${s#*backpack://}"
    s="$(printf '%s' "$s" | sed -E 's#^(backpack://[0-9]+\.[A-Za-z0-9_-]*).*#\1#')"
  fi
  printf '%s' "$s"
}

# ============================================================================
# BackPack's TOML (Render layout) - readers
# ============================================================================
_bp_conf() { printf '%s/%s.toml' "$BP_ETC" "$1"; }

_bp_toml_get() {  # <key> <file> [section] -> value (string quotes removed)
  [[ -r "$2" ]] || return 1
  awk -v k="$1" -v want="[${3:-server}]" '
    /^\[/ { sec = $0; next }
    sec == want && $1 == k && $2 == "=" {
      v = $0; sub(/^[^=]*= */, "", v)
      if (v ~ /^"/) { sub(/^"/, "", v); sub(/"[[:space:]]*$/, "", v); gsub(/\\"/, "\"", v); gsub(/\\\\/, "\\", v) }
      print v; found = 1; exit
    }
    END { exit !found }' "$2"
}

_bp_toml_list() {  # <key> <file> [section] -> one item per line
  [[ -r "$2" ]] || return 1
  awk -v k="$1" -v want="[${3:-server}]" '
    /^\[/ && !m { sec = $0; next }
    sec == want && !m && $1 == k && $2 == "=" && $3 == "[" { m = 1; next }
    m && /^\]/ { m = 0; next }
    m { v = $0; sub(/^[[:space:]]*"/, "", v); sub(/",?[[:space:]]*$/, "", v); print v }' "$2"
}

# value or empty, never a failure (missing keys are normal: Render omits zero values)
_bp_tget() { _bp_toml_get "$@" 2>/dev/null || true; }

# shareLinkOf (server branch) + shareLinkWith extras -> BL
_bp_link_fill_from_toml() {  # <file> <name> <host> [hosts, one per line] [restart-h] [restart-m]
  local f="$1" bind tr
  BL=()
  bind="$(_bp_tget bind_addr "$f")"
  [[ -n "$bind" ]] || return 1
  tr="$(_bp_tget transport "$f")"
  BL[k]=reverse; BL[f]=iran; BL[n]="$2"
  BL[t]="$(_bp_tget token "$f")"; BL[tr]="$tr"
  BL[p]="${bind##*:}"
  BL[h]="$(printf '%s' "$3" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  BL[pr]="$(_bp_tget preset "$f")"
  BL[po]="$(_bp_toml_list ports "$f" | awk 'BEGIN{ORS=""} {print (NR>1?", ":"") $0}')"
  if [[ "$(_bp_tget accept_udp "$f")" == true ]]; then BL[u]=1; fi
  BL[m]="$(_bp_tget mss "$f")"
  if [[ "$(_bp_tget simple_auth "$f")" == true ]]; then BL[sa]=1; fi
  BL[mv]="$(_bp_tget mux_version "$f")"
  BL[ft]="$(_bp_toml_list fallback_transports "$f")"
  BL[fw]="$(_bp_tget fallback_dwell "$f")"
  if [[ "$tr" == kcp ]]; then
    BL[fd]="$(_bp_tget kcp_datashards "$f")"
    BL[fp]="$(_bp_tget kcp_parityshards "$f")"
  fi
  BL[hs]="${4:-}"
  if [[ -n "${5:-}" && "${5:-0}" != 0 ]]; then BL[rh]="$5"; BL[rm]="${6:-0}"; fi
  [[ -n "${BL[t]}" ]]
}

# ============================================================================
# BackPack's own commands
# ============================================================================
_bp_name() { printf '%s' "${ST[bp_name]:-${ST[name]}}"; }
_bp_unit_of() { printf 'backpack-%s.service' "$1"; }

_bp_json_str() {  # <s> -> JSON string literal
  local s="$1"
  s="${s//\\/\\\\}"; s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"; s="${s//$'\t'/\\t}"; s="${s//$'\r'/}"
  printf '"%s"' "$s"
}
_bp_json_bool() { [[ "$1" == true || "$1" == yes || "$1" == 1 ]] && printf true || printf false; }

# fine-tune knobs: <json key> <kind b|i|s>
BP_TUNE=(nodelay:b keepAlive:i heartbeat:i logLevel:s logJSON:b channelSize:i mss:i
         muxCon:i muxVersion:i muxFrameSize:i muxRecvBuffer:i muxStreamBuffer:i
         kcpMTU:i kcpInterval:i kcpSndWnd:i kcpRcvWnd:i kcpDataShards:i kcpParityShards:i zeroCopy:b)

# NewTunnel (internal/manage/webapi.go) from ST - only answered tune keys are sent,
# so everything else keeps the preset's value (the panel's own semantics).
_bp_newtunnel_json() {
  local t="${ST[transport]}" j tune='' e k kind v
  j="{\"role\":\"server\",\"transport\":$(_bp_json_str "$t"),\"name\":$(_bp_json_str "$(_bp_name)")"
  j+=",\"tunnelPort\":$(_bp_json_str "${ST[tunnel_port]}"),\"token\":$(_bp_json_str "${ST[token]}")"
  j+=",\"ports\":$(_bp_json_str "$(_bp_ports_list)"),\"preset\":$(_bp_json_str "${ST[preset]:-turbo}")"
  j+=",\"ipv6\":$(_bp_json_bool "${ST[ipv6]:-no}"),\"proxyProtocol\":$(_bp_json_bool "${ST[proxy_protocol]:-no}")"
  # Carry UDP is a main-flow answer, always given (not a preset knob)
  tune="\"acceptUDP\":$(_bp_json_bool "${ST[accept_udp]:-no}")"
  for e in "${BP_TUNE[@]}"; do
    k="${e%%:*}"; kind="${e#*:}"; v="${ST[tune_$k]:-}"
    [[ -z "$v" ]] && continue
    case "$kind" in
      b) tune+=",\"$k\":$(_bp_json_bool "$v")" ;;
      i) tune+=",\"$k\":$v" ;;
      s) tune+=",\"$k\":$(_bp_json_str "$v")" ;;
    esac
  done
  j+=",\"tune\":{$tune}"
  if [[ "$t" == pck ]]; then
    j+=",\"pck\":{\"interface\":$(_bp_json_str "${ST[pck_iface]:-}"),\"gatewayMAC\":$(_bp_json_str "${ST[pck_mac]:-}"),\"flags\":$(_bp_json_str "${ST[pck_flags]:-}")}"
  fi
  if _bp_needs_tls "$t"; then
    j+=",\"conn\":{\"simpleAuth\":$(_bp_json_bool "${ST[simple_auth]:-no}")}"
  fi
  printf '%s}' "$j"
}

# backpack node exec - : one request, one answer (base64 JSON both ways).
# rc 0 = ok (BP_RESP holds the answer JSON), 1 = refused/failed (BP_ERR).
_bp_node() {  # <op> [body-json]
  local req out line
  BP_RESP=''; BP_ERR=''
  if [[ -n "${2:-}" ]]; then req="{\"op\":\"$1\",\"body\":$2}"; else req="{\"op\":\"$1\"}"; fi
  if [[ "${MILI_DRYRUN:-0}" == 1 ]]; then
    printf '%s[dry]%s %s node exec - <<< %s\n' "${C_GRY:-}" "${C_RST:-}" "$BP_BIN" "$req" >&2
    return 0
  fi
  _log_write CMD "$BP_BIN node exec - ($1)" 2>/dev/null || true
  out="$(printf '%s' "$req" | base64 -w0 | "$BP_BIN" node exec - 2>/dev/null)"
  line="$(printf '%s\n' "$out" | awk 'NF { l = $0 } END { print l }')"
  BP_RESP="$(printf '%s' "$line" | base64 -d 2>/dev/null)"
  if [[ "$BP_RESP" == *'"ok":true'* ]]; then return 0; fi
  BP_ERR="$(printf '%s' "$BP_RESP" | sed -n 's/.*"err":"\(\([^"\\]\|\\.\)*\)".*/\1/p' | sed 's/\\"/"/g; s/\\u003c/</g; s/\\u003e/>/g; s/\\u0026/\&/g')"
  [[ -z "$BP_ERR" ]] && BP_ERR="backpack did not answer (is /usr/local/bin/backpack v$BP_VERSION installed?)"
  return 1
}

# binary + BackPack's own by-hand install steps (docs/install.md)
_bp_install() {
  if [[ -x "$BP_BIN" ]] && "$BP_BIN" -v 2>/dev/null | head -n1 | grep -qx "v$BP_VERSION"; then return 0; fi
  cores_ensure backpack || { ui_err "could not install the BackPack core"; return 1; }
  run mkdir -p "$BP_ETC" /root/BackPack/backups || return 1
  run install -m 0755 "$(cores_path backpack)" "$BP_BIN" || { ui_err "could not install $BP_BIN"; return 1; }
  if [[ "${MILI_DRYRUN:-0}" != 1 ]]; then echo /root/BackPack >"$BP_ETC/install_path"; fi
  ui_ok "BackPack v$BP_VERSION installed at $BP_BIN"
}

# ============================================================================
# meta
# ============================================================================
t_backpack_meta() {
  echo "id=backpack"
  echo "title=BackPack  (reverse, 11 transports)"
  echo "tier=free"
  echo "layer=fwd"
  echo "roles=iran foreign"
  echo "primary=iran"
  echo "twoway=no"
  echo "cores=backpack"
  echo "pairing=native"
  echo "handoff_label=Show setup link"
  echo "first_hint=Set up the IRAN server first: it prints a backpack:// setup link you paste on the foreign server."
}

t_backpack_unit() {
  [[ "${ST[name]:-}" == "$1" ]] || st_load "$1" 2>/dev/null
  _bp_unit_of "$(_bp_name)"
}

# a pasted backpack:// link made by an Iran (reverse) server -> the foreign side
t_backpack_accepts_token() {  # <str>
  _bp_link_decode "$1" || return 1
  [[ "${BL[k]}" == reverse && "${BL[f],,}" == iran ]] || return 1
  echo foreign
}

# ============================================================================
# ports list (what goes into BackPack's Forwarded Ports)
# ============================================================================
_bp_ports_list() {
  if [[ "${ST[mode]:-forward}" == socks ]]; then
    printf '127.0.0.1:%s=%s' "${ST[iran_socks]}" "${ST[foreign_socks]}"
  else
    printf '%s' "${ST[fwd]:-}"
  fi
}

_bp_fwd_items() {  # <list> -> one mapping per line
  local it; local -a a=()
  IFS=',' read -ra a <<<"$1"
  for it in "${a[@]}"; do
    it="$(printf '%s' "$it" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    [[ -n "$it" ]] && printf '%s\n' "$it"
  done
  return 0
}

# local half of a mapping -> "<bind> <port-or-range>"
_bp_fwd_local() {
  local l="${1%%=*}"
  if [[ "$l" == \[*\]:* ]]; then printf '%s %s' "${l%]:*}]" "${l##*]:}"
  elif [[ "$l" == *:* ]]; then printf '%s %s' "${l%:*}" "${l##*:}"
  else printf '0.0.0.0 %s' "$l"; fi
}

_bp_fwd_valid() {  # one mapping, docs/port-mappings.md forms (BackPack has the last word)
  local it="$1" l r p a b
  l="${it%%=*}"
  if [[ "$l" == \[*\]:* ]]; then p="${l##*]:}"
  elif [[ "$l" == *:* ]]; then p="${l##*:}"; [[ "${l%:*}" =~ ^[0-9.]+$ ]] || return 1
  else p="$l"; fi
  [[ "$p" =~ ^[0-9]+(-[0-9]+)?$ ]] || return 1
  a="${p%%-*}"; b="${p##*-}"
  (( a >= 1 && a <= 65535 && b >= a && b <= 65535 )) || return 1
  if [[ "$it" == *=* ]]; then
    local rre='^[][A-Za-z0-9.:|-]+$'
    r="${it#*=}"
    [[ -n "$r" && "$r" =~ $rre ]] || return 1
  fi
  return 0
}

# forwardTargets: "exposed -> what the kharej must have listening"
_bp_forward_targets() {  # <list>
  local it ex dest d out
  while read -r it; do
    ex="${it%%=*}"
    if [[ "$it" != *=* ]]; then printf '%s → 127.0.0.1:%s\n' "$ex" "$ex"; continue; fi
    dest="${it#*=}"; out=''
    local IFS='|'
    for d in $dest; do
      [[ -z "$d" ]] && continue
      [[ "$d" == *:* ]] || d="127.0.0.1:$d"
      out+="${out:+|}$d"
    done
    unset IFS
    printf '%s → %s\n' "$ex" "$out"
  done < <(_bp_fwd_items "$1")
}

# the Iran link's ports are mili's SOCKS mapping -> kharej proxy port (else empty)
_bp_link_socks_port() {  # <po>
  local re='^127\.0\.0\.1:[0-9]+=(127\.0\.0\.1:)?([0-9]+)$'
  [[ "$1" =~ $re ]] && printf '%s' "${BASH_REMATCH[2]}"
}

# ============================================================================
# wizard - Iran (BackPack's SetupServer, question for question)
# ============================================================================
t_backpack_wizard() {  # <role> [level]
  if [[ "$1" == iran ]]; then _bp_wizard_iran; else _bp_wizard_foreign; fi
}

_bp_ask_transport() {
  local fam pre_f=0 pre_v=0 cur="${ST[transport]:-tcp}"
  local -a fams=(TCP UDP WebSocket)
  case "$cur" in udp|kcp|quic) pre_f=1 ;; ws|wsmux|wss|wssmux) pre_f=2 ;; esac
  echo; ui_info "Select Transport Family (same on both servers):"
  ui_select "$pre_f" $'TCP\treliable and simple — the safe default' \
                     $'UDP\tlower latency, better on lossy or throttled links' \
                     $'WebSocket\tlooks like normal web traffic — CDN friendly'
  (( SEL >= 1 && SEL <= 3 )) || return 1
  fam="${fams[$((SEL-1))]}"
  local -a vals=()
  echo; ui_info "Select $fam Transport:"
  case "$fam" in
    TCP) vals=(tcp tcpmux stealth pck)
         case "$cur" in tcpmux) pre_v=1 ;; stealth) pre_v=2 ;; pck) pre_v=3 ;; esac
         ui_select "$pre_v" $'TCP\tplain & fast — start here if unsure' \
           $'TCP Mux\tmany streams over few connections — multiplexed' \
           $'TCP + Stealth\tencrypted with no fingerprint — hardest to detect, for heavy filtering' \
           $'TCP + PCK\tbuilds its own TCP packets, below the kernel — Linux, needs root' ;;
    UDP) vals=(udp kcp quic)
         case "$cur" in kcp) pre_v=1 ;; quic) pre_v=2 ;; esac
         ui_select "$pre_v" $'UDP\traw datagrams — for UDP-based services' \
           $'UDP + KCP + FEC\tlow-latency gaming tunnel — reliable UDP, always-on FEC' \
           $'UDP + QUIC\tencrypted TLS 1.3 streams over UDP — great under loss' ;;
    WebSocket) vals=(ws wsmux wss wssmux)
         case "$cur" in wsmux) pre_v=1 ;; wss) pre_v=2 ;; wssmux) pre_v=3 ;; esac
         ui_select "$pre_v" $'WS\tWebSocket — HTTP camouflage, CDN friendly' \
           $'WS Mux\tWebSocket — multiplexed' \
           $'WSS\tTLS WebSocket — Chrome TLS hello, includes ECH' \
           $'WSS Mux\tTLS WebSocket, multiplexed — Chrome TLS hello, includes ECH' ;;
  esac
  (( SEL >= 1 && SEL <= ${#vals[@]} )) || return 1
  ST[transport]="${vals[$((SEL-1))]}"
  if _bp_needs_tls "${ST[transport]}"; then
    ui_note "WSS dials with a Chrome TLS fingerprint whose ClientHello carries the ECH extension;"
    ui_note "where ECH is blocked pick TCP + Stealth or WS instead."
  fi
  return 0
}

_bp_ask_tunnel_port() {
  local v p who own re='^(([0-9.]+)|\[([0-9A-Fa-f:]+)\]):([0-9]+)$'
  while :; do
    v="$(ui_ask 'Tunnel Port (443, or 85.10.11.51:443 to pin one address)' "${ST[tunnel_port]:-$(ports_alloc_public "${ST[name]}")}")"
    v="${v// /}"
    if [[ "$v" =~ ^[0-9]+$ ]]; then p="$v"
    elif [[ "$v" =~ $re ]]; then p="${BASH_REMATCH[4]}"
    else ui_err "a port, or address:port ([v6]:port for IPv6)"; continue; fi
    (( p >= 1 && p <= 65535 )) || { ui_err "port must be 1-65535"; continue; }
    own=0; [[ "${ST[tunnel_port]##*:}" == "$p" ]] && own=1
    if who="$(ports_busy_reason "$p" "${ST[name]}")"; then
      if ! (( own )) || [[ "$who" != backpack* ]]; then ui_err "port $p is in use ($who)"; continue; fi
    fi
    if [[ " ${MILI_RESERVED[*]} " == *" $p "* ]] && ! (( own )); then
      ui_confirm "port $p is normally kept for x-ui / the system. Use it anyway?" n || continue
    fi
    ST[tunnel_port]="$v"; return 0
  done
}

_bp_ask_backups() {
  local raw part out=''
  raw="$(ui_ask 'Backup Addresses For The Kharej (Other IPs Or Domains Of This Server, Comma Separated, Optional, - = clear)' "${ST[backups]:-}")"
  [[ "$raw" == - ]] && raw=''
  local -a a=(); IFS=',' read -ra a <<<"$raw"
  for part in "${a[@]}"; do
    part="${part// /}"; [[ -z "$part" ]] && continue
    if [[ "$part" =~ ^(.+):([0-9]+)$ && "$part" != *::* ]]; then
      (( BASH_REMATCH[2] >= 1 && BASH_REMATCH[2] <= 65535 )) || { ui_warn "Skipped $part: Not An Address With A Port."; continue; }
    elif [[ "$part" == */* ]]; then ui_warn "Skipped $part: Not An IP Or Domain."; continue; fi
    out+="${out:+,}$part"
  done
  ST[backups]="$out"
}

_bp_ports_help() {
  echo; ui_info "Forwarded port forms (Iran listens -> what the kharej forwards to):"
  ui_note "443                       :443 -> the kharej's own 127.0.0.1:443"
  ui_note "443=2096                  a different port at the kharej"
  ui_note "443=10.0.0.5:8443         an explicit host the kharej can reach"
  ui_note "443=10.0.0.1:80|10.0.0.2:80   two backends, balanced"
  ui_note "10000-10009(=20000-20009) a range (offset kept)"
  ui_note "85.11.12.13:443=2053      bind one local address (127.0.0.1:... = this server only)"
}

_bp_fwd_check() {  # <list>
  local it bind lp a b p who n=0 own tp="${ST[tunnel_port]##*:}"
  while read -r it; do
    n=$(( n + 1 ))
    _bp_fwd_valid "$it" || { ui_err "invalid port mapping: $it"; return 1; }
    read -r bind lp <<<"$(_bp_fwd_local "$it")"
    a="${lp%%-*}"; b="${lp##*-}"
    own=0; [[ ",${ST[fwd]:-}," == *",$it,"* ]] && own=1
    for (( p = a; p <= b; p++ )); do
      if ! _bp_is_datagram "${ST[transport]}" && [[ "$p" == "$tp" ]]; then
        ui_err "port $p is the tunnel port — pick other ports"; return 1
      fi
      (( b - a > 200 )) && continue
      if who="$(ports_busy_reason "$p" "${ST[name]}")" && ! { (( own )) && [[ "$who" == backpack* ]]; }; then
        ui_err "already in use on this server: $p ($who)"; return 1
      fi
    done
  done < <(_bp_fwd_items "$1")
  (( n > 0 )) || { ui_err "No valid ports."; return 1; }
  return 0
}

_bp_ask_usage() {
  if [[ "${ST[transport]}" == udp ]]; then
    ST[mode]=forward
    ui_note "the udp transport carries UDP only -> port forward (SOCKS needs a stream transport)."
    return 0
  fi
  local pre=0; [[ "${ST[mode]:-socks}" == forward ]] && pre=1
  echo; ui_info "How will this tunnel be used?"
  ui_pick "$pre" $'SOCKS outbound for 3x-ui\trecommended · x-ui on Iran → SOCKS → BackPack built-in proxy on kharej' \
                 $'Port forward\tBackPack Forwarded Ports · Iran ports → kharej'
  if (( SEL == 2 )); then ST[mode]=forward; else ST[mode]=socks; fi
}

_bp_ask_ports() {
  local p who v
  if [[ "${ST[mode]}" == socks ]]; then
    while :; do
      p="$(ui_ask_port 'SOCKS5 port on THIS server (3x-ui outbound → 127.0.0.1:port)' "${ST[iran_socks]:-$(ports_alloc_socks "${ST[name]}")}")"
      [[ "$p" == "${ST[tunnel_port]##*:}" ]] && { ui_err "must differ from the tunnel port"; continue; }
      if [[ "$p" != "${ST[iran_socks]:-}" ]] && who="$(ports_busy_reason "$p" "${ST[name]}")"; then ui_err "port $p is in use ($who)"; continue; fi
      break
    done
    ST[iran_socks]="$p"
    ui_note "BackPack runs ONE built-in proxy per kharej; keep the same port for every tunnel to it."
    ST[foreign_socks]="$(ui_ask_port 'Built-in proxy (SOCKS5) port on the KHAREJ server' "${ST[foreign_socks]:-10800}")"
    ST[fwd]=''
  else
    _bp_ports_help
    while :; do
      v="$(ui_ask 'Forwarded Ports (e.g. 443, 8080=127.0.0.1:2096)' "${ST[fwd]:-}")"
      v="$(printf '%s' "$v" | sed 's/[[:space:]]*,[[:space:]]*/,/g; s/^[[:space:]]*//; s/[[:space:]]*$//')"
      _bp_fwd_check "$v" && break
    done
    ST[fwd]="$v"
    echo; ui_info "The kharej must have these listening:"
    _bp_forward_targets "$v" | sed 's/^/    /'
  fi
}

_bp_ask_token() {
  local v
  while :; do
    v="$(ui_ask 'Security Token (both ends use the same)' "${ST[token]:-$(sys_rand_token 64)}")"
    v="${v// /}"
    [[ -n "$v" && "$v" =~ ^[A-Za-z0-9._~+/=-]+$ ]] && { ST[token]="$v"; return 0; }
    ui_err "A token is required (letters, digits, ._~+/=-)."
  done
}

_bp_ask_tls() {
  local pre=0
  case "${ST[tls]:-self}" in acme) pre=1 ;; files) pre=2 ;; esac
  echo; ui_info "TLS Certificate:"
  ui_select "$pre" $'Self-Signed\tgenerated now — works anywhere, including on a bare IP' \
                   $'Let'"'"$'s Encrypt\tfree and real — needs a domain pointing at this server' \
                   $'Existing Files\ta certificate and key you already have on disk'
  case "$SEL" in
    1) ST[tls]=self; unset 'ST[acme_domain]' 'ST[acme_email]' 'ST[tls_cert]' 'ST[tls_key]' ;;
    2) local d mine
       [[ "${ST[tunnel_port]##*:}" != 443 ]] && ui_warn "Port 80 Must Be Free And Open For Let's Encrypt."
       while :; do
         d="$(ui_ask "Domain (A Record Pointing Here)" "${ST[acme_domain]:-}")"
         [[ -z "$d" ]] && { ui_err "A domain is required."; continue; }
         sys_is_ip4 "$d" || [[ "$d" == *:* ]] && { ui_err "Let's Encrypt needs a domain, not an IP."; continue; }
         sys_is_host "$d" || { ui_err "not a valid domain"; continue; }
         mine="${ST[host]:-$(sys_public_ip4)}"
         if ! getent ahostsv4 "$d" 2>/dev/null | awk '{print $1}' | grep -qx "$mine"; then
           ui_warn "$d does not point at this server ($mine) yet; issuance would fail until it does."
           ui_confirm "Use It Anyway" n || continue
         fi
         break
       done
       ST[tls]=acme; ST[acme_domain]="$d"
       ST[acme_email]="$(ui_ask 'Email For Expiry Warnings (Optional)' "${ST[acme_email]:-}")"
       unset 'ST[tls_cert]' 'ST[tls_key]' ;;
    3) local c k
       while :; do
         c="$(ui_ask 'Certificate File (fullchain.pem)' "${ST[tls_cert]:-}")"
         k="$(ui_ask 'Key File (privkey.pem)' "${ST[tls_key]:-}")"
         [[ -r "$c" && -r "$k" ]] && break
         ui_err "Invalid certificate: both files must exist and be readable."
       done
       ST[tls]=files; ST[tls_cert]="$c"; ST[tls_key]="$k"; unset 'ST[acme_domain]' 'ST[acme_email]' ;;
    *) return 1 ;;
  esac
}

_bp_yn() { [[ "$1" == yes ]] && echo y || echo n; }

_bp_ask_pck() {
  local pre=0
  case "${ST[pck_flags]:-}" in A) pre=1 ;; PA,A) pre=2 ;; PA,A,PA,PAU) pre=3 ;; esac
  echo; ui_info "TCP Flag Pattern:"
  ui_select "$pre" $'PA\tpush + ack — what bulk data carries; the default' \
                   $'A\tack only — reads as a stream being drained' \
                   $'PA,A\talternates the two, as a real transfer does' \
                   $'PA,A,PA,PAU\tvaried — hardest to match on the flag pattern alone'
  case "$SEL" in 2) ST[pck_flags]=A ;; 3) ST[pck_flags]=PA,A ;; 4) ST[pck_flags]=PA,A,PA,PAU ;; *) ST[pck_flags]='' ;; esac
  if ui_confirm "Override The Automatic Interface / Gateway Detection" "$([[ -n "${ST[pck_iface]:-}${ST[pck_mac]:-}" ]] && echo y || echo n)"; then
    local v
    ui_note "Interfaces: $(ip -o link show 2>/dev/null | awk -F': ' '$2 != "lo" {print $2}' | cut -d@ -f1 | paste -sd' ' -)"
    while :; do
      v="$(ui_ask 'Interface (Blank = Automatic)' "${ST[pck_iface]:-}")"
      [[ -z "$v" ]] || ip link show "$v" >/dev/null 2>&1 || { ui_err "No such interface: $v"; continue; }
      break
    done
    ST[pck_iface]="$v"
    while :; do
      v="$(ui_ask 'Gateway MAC (Blank = Automatic)' "${ST[pck_mac]:-}")"
      [[ -z "$v" || "$v" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]] && break
      ui_err "Not a MAC address (aa:bb:cc:dd:ee:ff)."
    done
    ST[pck_mac]="$v"
  else
    ST[pck_iface]=''; ST[pck_mac]=''
  fi
}

_bp_ask_preset() {
  local t="${ST[transport]}" pre=1
  local -a vals=(balance turbo aggressive)
  local -a rows=($'Balance\tlight on CPU and RAM — best for small or shared VPS'
                 $'Turbo\trecommended — the tuned default for Iran to abroad links'
                 $'Aggressive\tmaximum gaming headroom, noticeably more CPU — for strong servers')
  if [[ "$t" == kcp ]]; then
    vals+=(throughput); rows+=($'Throughput\tmaximum bandwidth for udp+kcp+fec — trades steady ping for speed')
  fi
  local i; for i in "${!vals[@]}"; do [[ "${vals[$i]}" == "${ST[preset]:-turbo}" ]] && pre=$i; done
  echo; ui_info "How Should The Tunnel Be Tuned? (same on both servers)"
  ui_select "$pre" "${rows[@]}"
  (( SEL >= 1 && SEL <= ${#vals[@]} )) || return 1
  ST[preset]="${vals[$((SEL-1))]}"
}

# one fine-tune answer: blank = keep the preset's value
_bp_tune_ask() {  # <key> <kind> <prompt>
  local k="$1" kind="$2" v
  while :; do
    v="$(ui_ask "$3 (Enter = preset)" "${ST[tune_$k]:-}")"
    v="${v// /}"
    [[ -z "$v" ]] && { unset "ST[tune_$k]"; return 0; }
    case "$kind" in
      b) case "${v,,}" in y|yes|true|1) v=true ;; n|no|false|0) v=false ;; *) ui_err "y or n"; continue ;; esac ;;
      i) [[ "$v" =~ ^[0-9]+$ ]] || { ui_err "a whole number"; continue; } ;;
      s) [[ "$v" =~ ^(info|debug|warn|error)$ ]] || { ui_err "info, debug, warn or error"; continue; } ;;
    esac
    ST[tune_$k]="$v"; return 0
  done
}

_bp_ask_finetune() {
  local t="${ST[transport]}" has=0 e
  for e in "${BP_TUNE[@]}"; do [[ -n "${ST[tune_${e%%:*}]:-}" ]] && has=1; done
  if ! ui_confirm "Fine-Tune The Advanced Settings" "$([[ $has == 1 ]] && echo y || echo n)"; then
    for e in "${BP_TUNE[@]}"; do unset "ST[tune_${e%%:*}]"; done
    return 0
  fi
  ui_note "Any answer moves the tunnel off its preset (shown as Custom), as in BackPack."
  _bp_tune_ask nodelay b "TCP_NODELAY (Lower Latency) y/n"
  _bp_tune_ask keepAlive i "Keepalive Period (Seconds)"
  _bp_tune_ask heartbeat i "Heartbeat Interval (Seconds, 0 = Off)"
  _bp_tune_ask logLevel s "Log Level (info/debug/warn/error)"
  _bp_tune_ask logJSON b "Write Logs As JSON (For Log Collectors) y/n"
  _bp_tune_ask channelSize i "Channel Size"
  _bp_is_datagram "$t" || _bp_tune_ask mss i "TCP MSS Clamp (Bytes, 0 = Automatic; Both Ends The Same)"
  if _bp_is_mux "$t"; then
    _bp_tune_ask muxCon i "Mux Connections"
    _bp_tune_ask muxVersion i "Mux Version (1 Or 2)"
    _bp_tune_ask muxFrameSize i "Mux Frame Size"
    _bp_tune_ask muxRecvBuffer i "Mux Receive Buffer"
    _bp_tune_ask muxStreamBuffer i "Mux Stream Buffer"
  fi
  if _bp_is_kcp "$t"; then
    _bp_tune_ask kcpMTU i "KCP MTU (Bytes, Below The Path MTU)"
    _bp_tune_ask kcpInterval i "KCP Interval (ms)"
    _bp_tune_ask kcpSndWnd i "KCP Send Window (Packets)"
    _bp_tune_ask kcpRcvWnd i "KCP Receive Window (Packets)"
    _bp_tune_ask kcpDataShards i "FEC Data Shards (0 = Off)"
    _bp_tune_ask kcpParityShards i "FEC Parity Shards"
  fi
  [[ "$t" == tcp ]] && _bp_tune_ask zeroCopy b "Zero-Copy Forwarding (Experimental) y/n"
  # knobs of other transports do not carry over
  _bp_is_datagram "$t" && unset 'ST[tune_mss]'
  _bp_is_mux "$t" || unset 'ST[tune_muxCon]' 'ST[tune_muxVersion]' 'ST[tune_muxFrameSize]' 'ST[tune_muxRecvBuffer]' 'ST[tune_muxStreamBuffer]'
  _bp_is_kcp "$t" || unset 'ST[tune_kcpMTU]' 'ST[tune_kcpInterval]' 'ST[tune_kcpSndWnd]' 'ST[tune_kcpRcvWnd]' 'ST[tune_kcpDataShards]' 'ST[tune_kcpParityShards]'
  [[ "$t" == tcp ]] || unset 'ST[tune_zeroCopy]'
  return 0
}

_bp_wizard_iran() {
  # Select Transport Family / Transport
  _bp_ask_transport || return 1
  local t="${ST[transport]}" d
  # Iran IP Or Domain (What Kharej Dials)
  d="${ST[host]:-$(sys_public_ip4)}"; [[ "$d" == unknown ]] && d=''
  ST[host]="$(ui_ask 'Iran IP Or Domain (What Kharej Dials)' "$d")"
  ST[host]="${ST[host]// /}"; ST[host]="${ST[host]#[}"; ST[host]="${ST[host]%]}"
  # Tunnel Port
  _bp_ask_tunnel_port
  # Listen On IPv6 As Well (bare port only)
  if [[ "${ST[tunnel_port]}" =~ ^[0-9]+$ ]]; then
    ui_confirm "Listen On IPv6 As Well" "$(_bp_yn "${ST[ipv6]:-no}")" && ST[ipv6]=yes || ST[ipv6]=no
  else
    ST[ipv6]=no
    [[ -z "${ST[host]}" ]] && ST[host]="${ST[tunnel_port]%:*}"
  fi
  # Backup Addresses For The Kharej
  _bp_ask_backups
  [[ -z "${ST[host]}" ]] && ui_warn "No Address — The Kharej Will Be Asked For It."
  # Forwarded Ports (mili: SOCKS outbound or BackPack's own list)
  _bp_ask_usage
  _bp_ask_ports
  # Tunnel Name = the mili tunnel name
  ui_note "Tunnel Name: ${ST[name]}  (service backpack-${ST[name]}, $BP_ETC/${ST[name]}.toml)"
  # Security Token (generated here)
  _bp_ask_token
  # Carry UDP As Well As TCP On Those Ports
  if [[ "$t" != udp ]]; then
    ui_confirm "Carry UDP As Well As TCP On Those Ports" "$(_bp_yn "${ST[accept_udp]:-no}")" && ST[accept_udp]=yes || ST[accept_udp]=no
  else
    ST[accept_udp]=no
  fi
  # the transport's own questions
  if _bp_needs_tls "$t"; then
    _bp_ask_tls || return 1
    ui_confirm "Simple Token Auth (Only Behind A TLS-Terminating Proxy)" "$(_bp_yn "${ST[simple_auth]:-no}")" && ST[simple_auth]=yes || ST[simple_auth]=no
  else
    unset 'ST[tls]' 'ST[acme_domain]' 'ST[acme_email]' 'ST[tls_cert]' 'ST[tls_key]'; ST[simple_auth]=no
  fi
  if [[ "$t" == pck ]]; then _bp_ask_pck; else ST[pck_flags]=''; ST[pck_iface]=''; ST[pck_mac]=''; fi
  if _bp_proxy_proto_ok "$t" && [[ "${ST[mode]}" != socks ]]; then
    ui_confirm "Send Real Client IP (PROXY Protocol — The Service Must Accept It)" "$(_bp_yn "${ST[proxy_protocol]:-no}")" && ST[proxy_protocol]=yes || ST[proxy_protocol]=no
  else
    ST[proxy_protocol]=no
  fi
  # How Should The Tunnel Be Tuned? + Fine-Tune
  _bp_ask_preset || return 1
  _bp_ask_finetune
  # Restart This Tunnel On Both Servers Every N Hours (0 = Off)
  local h
  h="$(ui_ask_int 'Restart This Tunnel On Both Servers Every N Hours (0 = Off)' "${ST[restart_h]:-0}" 0 8760)"
  h="$(_bp_effective_hours "$h")"
  if (( h > 0 )); then
    [[ "$h" != "${ST[restart_h]:-0}" || -z "${ST[restart_m]:-}" ]] && ST[restart_m]=$(( RANDOM % 60 ))
    ST[restart_h]="$h"
  else
    ST[restart_h]=0; unset 'ST[restart_m]'
  fi
  return 0
}

# ============================================================================
# wizard - Foreign (kharej): BackPack's "Setup Link" path
# ============================================================================
_bp_wizard_foreign() {
  local link="${MILI_PREFILL_TOKEN:-}"
  MILI_PREFILL_TOKEN=''
  if [[ -z "$link" && -n "${ST[link]:-}" ]]; then
    ui_confirm "Keep the current setup link?" y && link="${ST[link]}"
  fi
  while :; do
    if [[ -z "$link" ]]; then
      ui_info "Paste the backpack:// setup link the IRAN server printed."
      link="$(ui_ask 'Setup Link' '')"
      [[ -z "$link" ]] && return 1
    fi
    if ! _bp_link_decode "$link"; then ui_err "$BL_ERR"; link=''; continue; fi
    if [[ "${BL[k]}" != reverse || "${BL[f],,}" != iran ]]; then
      ui_err "This link is for the $([[ "${BL[f],,}" == iran ]] && echo kharej || echo iran) side of a ${BL[k]} tunnel, not for the kharej side of a reverse one."
      link=''; continue
    fi
    break
  done
  ST[link]="$(_bp_find_link "$link")"
  ST[transport]="${BL[tr]}"; ST[tunnel_port]="${BL[p]}"; ST[iran_ip]="${BL[h]:-}"
  ST[preset]="${BL[pr]:-}"
  if [[ -z "${ST[iran_ip]}" ]]; then
    local h
    while :; do
      h="$(ui_ask 'Iran IP Or Domain' "${ST[host_override]:-}")"; h="${h#[}"; h="${h%]}"
      [[ -n "$h" ]] && break
      ui_err "An address is required."
    done
    ST[host_override]="$h"; ST[iran_ip]="$h"
  else
    unset 'ST[host_override]'
  fi
  ui_ok "Reverse $(_bp_transport_label "${BL[tr]}") · dials ${ST[iran_ip]}:${BL[p]} · tuning $(_bp_preset_label "${BL[pr]:-}")"
  _bp_needs_tls "${BL[tr]}" && ui_note "WSS sends a Chrome TLS hello with the ECH extension (blocked where ECH is filtered)."
  local sp; sp="$(_bp_link_socks_port "${BL[po]:-}")"
  if [[ -n "$sp" ]]; then
    ST[mode]=socks; ST[foreign_socks]="$sp"
    ui_ok "Usage: SOCKS outbound — BackPack's built-in SOCKS5 proxy on 127.0.0.1:$sp here"
  else
    ST[mode]=forward; unset 'ST[foreign_socks]'
    if [[ -n "${BL[po]:-}" ]]; then
      ui_info "Port forward — this server must have listening:"
      _bp_forward_targets "${BL[po]}" | sed 's/^/    /'
    fi
  fi
  return 0
}

t_backpack_summary() {
  local t="${ST[transport]}"
  if [[ "${ST[role]}" == iran ]]; then
    ui_kv "Role" "Iran · server (listens)"
    ui_kv "Transport" "Reverse $(_bp_transport_label "$t")"
    ui_kv "Listens On" "${ST[tunnel_port]}$([[ "${ST[ipv6]:-}" == yes ]] && echo ' (IPv4 + IPv6)')"
    [[ -n "${ST[host]:-}" ]] && ui_kv "Kharej Dials" "${ST[host]}:${ST[tunnel_port]##*:}"
    [[ -n "${ST[backups]:-}" ]] && ui_kv "Backup Addresses" "${ST[backups]}"
    if [[ "${ST[mode]}" == socks ]]; then
      ui_kv "Usage" "SOCKS · 3x-ui → 127.0.0.1:${ST[iran_socks]} → kharej proxy :${ST[foreign_socks]}"
    else
      ui_kv "Forwarded Ports" "${ST[fwd]}$([[ "${ST[accept_udp]}" == yes ]] && echo '  (TCP + UDP)')"
    fi
    if _bp_needs_tls "$t"; then
      case "${ST[tls]:-self}" in
        acme)  ui_kv "TLS" "Let's Encrypt for ${ST[acme_domain]}" ;;
        files) ui_kv "TLS" "${ST[tls_cert]}" ;;
        *)     ui_kv "TLS" "Self-Signed" ;;
      esac
      [[ "${ST[simple_auth]}" == yes ]] && ui_kv "Simple Auth" "on"
    fi
    [[ -n "${ST[pck_flags]:-}" ]] && ui_kv "Flag Pattern" "${ST[pck_flags]}"
    [[ "${ST[proxy_protocol]:-}" == yes ]] && ui_kv "Real Client IP" "PROXY protocol on"
    local custom=0 e; for e in "${BP_TUNE[@]}"; do [[ -n "${ST[tune_${e%%:*}]:-}" ]] && custom=1; done
    ui_kv "Tuning" "$(_bp_preset_label "${ST[preset]}")$( (( custom )) && echo ' + fine-tuned (Custom)')"
    ui_kv "Restart" "$(_bp_schedule_label "${ST[restart_h]:-0}" "${ST[restart_m]:-0}")"
    ui_kv "Config File" "$(_bp_conf "${ST[name]}")"
    ui_note "BackPack applies its own kernel tuning on create (/etc/sysctl.d/zz-backpack.conf)."
  else
    ui_kv "Role" "Kharej · client (dials Iran)"
    ui_kv "Transport" "Reverse $(_bp_transport_label "$t")"
    ui_kv "Dials" "${ST[iran_ip]}:${ST[tunnel_port]}"
    if [[ "${ST[mode]}" == socks ]]; then ui_kv "Usage" "SOCKS · built-in proxy 127.0.0.1:${ST[foreign_socks]}"
    else ui_kv "Usage" "port forward"; fi
    ui_kv "Builds with" "backpack link apply --name ${ST[name]} '<link>'"
  fi
  return 0
}

# ============================================================================
# scheduled restart (core/restartschedule.go, byte-identical units)
# ============================================================================
_bp_effective_hours() {
  local h="$1"
  if (( h <= 0 )); then echo 0; elif (( h <= 24 )); then echo "$h"; else echo $(( (h / 24) * 24 )); fi
}
_bp_restart_calendar() {  # <hours> <minute>
  local h="$1" m; printf -v m '%02d' "$2"
  if (( h < 24 )); then printf '*-*-* 00/%d:%s:00 UTC' "$h" "$m"
  elif (( h == 24 )); then printf '*-*-* 00:%s:00 UTC' "$m"
  else printf '*-*-01/%d 00:%s:00 UTC' $(( h / 24 )) "$m"; fi
}
_bp_schedule_label() {
  local m; printf -v m '%02d' "${2:-0}"
  if (( ${1:-0} <= 0 )); then echo off; else echo "every $1 hours, at :$m UTC, on both servers"; fi
}
_bp_restart_units() {  # <name> <hours> <minute> -> "service-text" NUL "timer-text"
  local n="$1" h="$2" m=$(( (($3 % 60) + 60) % 60 ))
  printf '[Unit]\nDescription=Scheduled restart of Backpack tunnel %s\n\n[Service]\nType=oneshot\nExecStart=/bin/systemctl try-restart %s\n' "$n" "$(_bp_unit_of "$n")"
  printf '\0'
  printf '[Unit]\nDescription=Restart Backpack tunnel %s every %d hours (UTC, both servers at once)\n\n[Timer]\nOnCalendar=%s\nAccuracySec=1s\n\n[Install]\nWantedBy=timers.target\n' "$n" "$h" "$(_bp_restart_calendar "$h" "$m")"
}
_bp_schedule_apply() {  # <name> <hours> <minute>
  local n="$1" h svc tmr text
  h="$(_bp_effective_hours "${2:-0}")"
  svc="$BP_UNITDIR/backpack-restart-$n.service"; tmr="$BP_UNITDIR/backpack-restart-$n.timer"
  if (( h <= 0 )); then
    [[ -f "$tmr" ]] || return 0
    run systemctl disable --now "backpack-restart-$n.timer" >/dev/null 2>&1 || true
    run rm -f "$tmr" "$svc"; run systemctl daemon-reload
    return 0
  fi
  if [[ "${MILI_DRYRUN:-0}" == 1 ]]; then ui_info "[dry] would write $svc and $tmr ($(_bp_restart_calendar "$h" "${3:-0}"))"; return 0; fi
  text="$(_bp_restart_units "$n" "$h" "${3:-0}" | tr '\0' '\036')"
  printf '%s\n' "${text%%$'\036'*}" >"$svc"
  printf '%s\n' "${text#*$'\036'}" >"$tmr"
  chmod 644 "$svc" "$tmr" 2>/dev/null || true
  run systemctl daemon-reload
  run systemctl enable --now "backpack-restart-$n.timer" >/dev/null 2>&1 || ui_warn "Scheduled Restart Not Set (systemctl enable failed)."
}

# ============================================================================
# certificate: Let's Encrypt / Existing Files, laid out as BackPack's Render writes them
# ============================================================================
_bp_tls_rewrite() {  # <in-file>  (stdout = new file)
  awk -v mode="${ST[tls]:-self}" -v crt="${ST[tls_cert]:-}" -v key="${ST[tls_key]:-}" \
      -v dom="${ST[acme_domain]:-}" -v mail="${ST[acme_email]:-}" '
    /^\[/ { sec = $0 }
    sec == "[server]" && ($1 == "acme_domain" || $1 == "acme_email") && $2 == "=" { next }
    sec == "[server]" && $1 == "tls_cert" && $2 == "=" && mode == "files" { printf "tls_cert = \"%s\"\n", crt; next }
    sec == "[server]" && $1 == "tls_key" && $2 == "=" {
      if (mode == "files") printf "tls_key = \"%s\"\n", key; else print
      if (mode == "acme" && dom != "") {
        printf "acme_domain = \"%s\"\n", dom
        if (mail != "") printf "acme_email = \"%s\"\n", mail
      }
      next
    }
    { print }' "$1"
}

_bp_tls_apply() {  # <name>
  local f; f="$(_bp_conf "$1")"
  _bp_needs_tls "${ST[transport]}" || return 0
  [[ "${ST[tls]:-self}" == self ]] && return 0
  if [[ "${MILI_DRYRUN:-0}" == 1 ]]; then ui_info "[dry] would set the ${ST[tls]} certificate in $f"; return 0; fi
  local tmp; tmp="$(mktemp "$BP_ETC/.$1.XXXXXX")" || return 1
  _bp_tls_rewrite "$f" >"$tmp" && chmod 600 "$tmp" && mv -f "$tmp" "$f" || { rm -f "$tmp"; return 1; }
  run systemctl restart "$(_bp_unit_of "$1")"
}

# ============================================================================
# firewall / port registry
# ============================================================================
_bp_fwd_protos() {
  if [[ "${ST[transport]}" == udp ]]; then echo udp
  elif [[ "${ST[accept_udp]:-no}" == yes ]]; then echo "tcp udp"
  else echo tcp; fi
}

t_backpack_fw_apply() {  # <name>
  st_load "$1"; local name="$1" it bind lp pr tp tpr
  [[ "${ST[role]}" == iran ]] || return 0
  tp="${ST[tunnel_port]##*:}"; tpr="$(_bp_port_proto "${ST[transport]}")"
  fw_allow "$name" "$tpr" "$tp"; fw_ufw_mirror "$name" "$tpr" "$tp"
  [[ "${ST[mode]}" == forward ]] || return 0
  while read -r it; do
    read -r bind lp <<<"$(_bp_fwd_local "$it")"
    [[ "$bind" == 127.* ]] && continue
    for pr in $(_bp_fwd_protos); do
      fw_allow "$name" "$pr" "$lp"; fw_ufw_mirror "$name" "$pr" "${lp//-/:}"
    done
  done < <(_bp_fwd_items "${ST[fwd]:-}")
  return 0
}

_bp_claim() {  # <name>
  local name="$1" it bind lp a b p pr tpr
  ports_release "$name"
  if [[ "${ST[role]}" == iran ]]; then
    tpr="$(_bp_port_proto "${ST[transport]}")"
    ports_claim "$name" "$tpr" "${ST[tunnel_port]##*:}" 0.0.0.0
    if [[ "${ST[mode]}" == socks ]]; then
      ports_claim "$name" tcp "${ST[iran_socks]}" 127.0.0.1
    else
      pr=tcp; [[ "$(_bp_fwd_protos)" == "tcp udp" ]] && pr=both; [[ "${ST[transport]}" == udp ]] && pr=udp
      while read -r it; do
        read -r bind lp <<<"$(_bp_fwd_local "$it")"
        a="${lp%%-*}"; b="${lp##*-}"
        if (( b - a > 100 )); then ui_warn "range $lp: not registered port-by-port (too wide)"; continue; fi
        for (( p = a; p <= b; p++ )); do ports_claim "$name" "$pr" "$p" "$bind"; done
      done < <(_bp_fwd_items "${ST[fwd]:-}")
    fi
  elif [[ "${ST[mode]}" == socks ]]; then
    ports_claim "$name" tcp "${ST[foreign_socks]}" 127.0.0.1
  fi
  return 0
}

t_backpack_ports() {
  st_load "$1"
  if [[ "${ST[role]}" == iran ]]; then
    echo "$(_bp_port_proto "${ST[transport]}"):${ST[tunnel_port]##*:}:0.0.0.0"
    [[ "${ST[mode]}" == socks ]] && echo "tcp:${ST[iran_socks]}:127.0.0.1"
  else
    [[ "${ST[mode]}" == socks ]] && echo "tcp:${ST[foreign_socks]}:127.0.0.1"
  fi
  return 0
}

# ============================================================================
# provision (create / Edit)
# ============================================================================
t_backpack_provision() {  # <name>
  st_load "$1"
  require_root
  _bp_install || return 1
  if [[ "${ST[role]}" == iran ]]; then _bp_provision_iran "$1"; else _bp_provision_foreign "$1"; fi
}

_bp_provision_iran() {
  local name="$1" json f
  ST[bp_name]="$name"
  st_save
  json="$(_bp_newtunnel_json)"
  ui_info "BackPack: creating '$name' (Reverse $(_bp_transport_label "${ST[transport]}") on ${ST[tunnel_port]})"
  if ! _bp_node apply "{\"kind\":\"reverse\",\"tunnel\":$json}"; then
    ui_err "BackPack refused it: $BP_ERR"
    return 1
  fi
  _bp_tls_apply "$name" || ui_warn "could not set the ${ST[tls]} certificate — BackPack keeps the self-signed one."
  _bp_schedule_apply "$name" "${ST[restart_h]:-0}" "${ST[restart_m]:-0}"
  [[ "${ST[restart_h]:-0}" != 0 ]] && ui_info "Scheduled Restart: $(_bp_schedule_label "${ST[restart_h]}" "${ST[restart_m]}")."

  fw_remove "$name"; t_backpack_fw_apply "$name"
  st_load "$name"
  _bp_claim "$name"
  ports_sync_reserved

  if [[ "${MILI_DRYRUN:-0}" == 1 ]]; then ui_note "dry-run: link and checks skipped"; return 0; fi
  f="$(_bp_conf "$name")"
  if _bp_link_fill_from_toml "$f" "$name" "${ST[host]:-}" "$(printf '%s' "${ST[backups]:-}" | tr ',' '\n')" "${ST[restart_h]:-0}" "${ST[restart_m]:-0}"; then
    ST[link]="$(_bp_link_encode)"
  else
    ui_warn "could not read $f to build the setup link"; ST[link]=''
  fi
  st_save
  _bp_verify_iran "$name"
}

_bp_listening() {  # <port> <tcp|udp>
  if [[ "$2" == udp ]]; then ss -Hlnu 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$1\$"
  else ss -Hltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$1\$"; fi
}

_bp_verify_iran() {
  local name="$1" u i tp pr
  u="$(_bp_unit_of "$name")"; tp="${ST[tunnel_port]##*:}"; pr="$(_bp_port_proto "${ST[transport]}")"
  for (( i = 0; i < 8; i++ )); do svc_active "$u" && break; sleep 1; done
  if ! svc_active "$u"; then
    ui_err "$u is not running — see: journalctl -u $u -n 30"; journalctl -u "$u" -n 12 --no-pager 2>/dev/null; return 1
  fi
  if [[ "${ST[transport]}" != pck ]]; then
    for (( i = 0; i < 8; i++ )); do _bp_listening "$tp" "$pr" && break; sleep 1; done
    if _bp_listening "$tp" "$pr"; then ui_ok "listening on $pr ${ST[tunnel_port]} (Reverse $(_bp_transport_label "${ST[transport]}"))"
    else ui_err "running but not listening on $pr :$tp"; journalctl -u "$u" -n 12 --no-pager 2>/dev/null; return 1; fi
  else
    ui_ok "running (TCP + PCK builds its own packets on :$tp)"
  fi
  ui_note "the forwarded ports come up once the kharej connects."
  return 0
}

_bp_proxy_ensure() {  # <port>  BackPack's built-in proxy (one per server)
  local want="$1" st port type running
  st="$("$BP_BIN" proxy status --json 2>/dev/null)"
  running="$(printf '%s' "$st" | grep -o '"running": *true')"
  port="$(printf '%s' "$st" | sed -n 's/.*"port": *\([0-9]*\).*/\1/p')"
  type="$(printf '%s' "$st" | sed -n 's/.*"type": *"\([a-z0-9]*\)".*/\1/p')"
  if [[ -n "$running" && "$port" == "$want" && "$type" == socks5 ]]; then
    ui_ok "BackPack built-in SOCKS5 already on 127.0.0.1:$want"; return 0
  fi
  if [[ -n "$running" ]]; then
    ui_err "BackPack's built-in proxy already runs $type on 127.0.0.1:$port (one per server)."
    ui_note "Set the Iran side's kharej proxy port to $port (Edit there), then paste its new link here."
    return 1
  fi
  ui_info "running: backpack proxy enable socks5 $want"
  run "$BP_BIN" proxy enable socks5 "$want" 2>&1 | sed 's/^/    /'
  (( PIPESTATUS[0] == 0 )) || { ui_err "could not enable the built-in proxy"; return 1; }
  ST[proxy_by_mili]=yes
}

_bp_provision_foreign() {
  local name="$1" out rc made
  [[ -n "${ST[link]:-}" ]] || { ui_err "no setup link"; return 1; }
  ST[bp_name]="${ST[bp_name]:-$name}"
  st_save
  local -a a=(link apply --name "$(_bp_name)")
  [[ -n "${ST[host_override]:-}" ]] && a+=(--host "${ST[host_override]}")
  a+=("${ST[link]}")
  ui_info "running: backpack link apply --name $(_bp_name)$([[ -n "${ST[host_override]:-}" ]] && echo " --host ${ST[host_override]}") '<link>'"
  out="$(run "$BP_BIN" "${a[@]}" 2>&1)"; rc=$?
  printf '%s\n' "$out" | sed -E $'s/\x1b\\[[0-9;]*m//g' | sed 's/^/  /'
  made="$(printf '%s' "$out" | sed -n 's/.*Tunnel "\([A-Za-z0-9._-]*\)".*/\1/p' | head -n1)"
  [[ -n "$made" ]] && ST[bp_name]="$made"
  case "$rc" in
    0) ;;
    4) [[ -f "$(_bp_conf "$(_bp_name)")" ]] || { ui_err "BackPack did not create the tunnel."; st_save; return 1; }
       ui_warn "not connected yet — it keeps trying. Check the Iran tunnel port is open and both run v$BP_VERSION." ;;
    *) ui_err "backpack link apply failed (exit $rc)"; st_save; return 1 ;;
  esac
  if [[ "${ST[mode]}" == socks ]]; then _bp_proxy_ensure "${ST[foreign_socks]}" || { st_save; return 1; }; fi
  _bp_claim "$name"
  ports_sync_reserved
  st_save
  return 0
}

# ============================================================================
# lifecycle
# ============================================================================
t_backpack_up() {  # <name>
  st_load "$1"; local name="$1" u
  require_root
  [[ -f "$(_bp_conf "$(_bp_name)")" ]] || { ui_err "BackPack config $(_bp_conf "$(_bp_name)") is missing — use Edit to set it up again."; return 1; }
  u="$(_bp_unit_of "$(_bp_name)")"
  run systemctl enable --now "$u" >/dev/null 2>&1 || true
  t_backpack_fw_apply "$name"
  _bp_claim "$name"
  if [[ "${ST[role]}" == foreign && "${ST[mode]}" == socks ]]; then
    run systemctl enable --now backpack-proxy.service >/dev/null 2>&1 || true
  fi
  [[ "${MILI_DRYRUN:-0}" == 1 ]] && return 0
  local i; for (( i = 0; i < 8; i++ )); do svc_active "$u" && return 0; sleep 1; done
  svc_active "$u"
}

t_backpack_down() {  # <name>
  st_load "$1"
  run systemctl stop "$(_bp_unit_of "$(_bp_name)")" >/dev/null 2>&1 || true
  run systemctl disable "$(_bp_unit_of "$(_bp_name)")" >/dev/null 2>&1 || true
  fw_remove "$1"
  return 0
}

t_backpack_restart() {  # <name>
  st_load "$1"
  run systemctl restart "$(_bp_unit_of "$(_bp_name)")"
}

# other mili BackPack kharej tunnels that use the built-in SOCKS proxy
_bp_other_socks() {  # <exclude-name>
  local f n
  for f in "$MILI_TUNDIR"/*.conf; do
    [[ -f "$f" ]] || continue
    n="${f##*/}"; n="${n%.conf}"; [[ "$n" == "$1" ]] && continue
    grep -qx 'type=backpack' "$f" && grep -qx 'role=foreign' "$f" && grep -qx 'mode=socks' "$f" && printf '%s\n' "$n"
  done
}

# Delete: BackPack's own delete (service, unit, restart timer, config, metrics, quota, meta)
t_backpack_remove() {  # <name>
  st_load "$1"; local name="$1"
  if [[ -x "$BP_BIN" ]]; then
    _bp_node delete "{\"name\":$(_bp_json_str "$(_bp_name)")}" || ui_warn "BackPack: $BP_ERR"
  fi
  if [[ "${ST[role]}" == foreign && "${ST[mode]}" == socks && "${ST[proxy_by_mili]:-}" == yes ]] && [[ -z "$(_bp_other_socks "$name")" ]]; then
    run "$BP_BIN" proxy disable >/dev/null 2>&1 || true
  fi
  fw_remove "$name"
  ports_release "$name"
  ports_sync_reserved
  return 0
}

# cheap (menu): the service runs
t_backpack_health() {
  st_load "$1"
  svc_active "$(_bp_unit_of "$(_bp_name)")"
}
# deeper (watchdog): Iran = running + listening (waits for the kharej without restarts);
# kharej = BackPack's own verdict on its control channel
t_backpack_probe() {
  st_load "$1"
  svc_active "$(_bp_unit_of "$(_bp_name)")" || return 1
  if [[ "${ST[role]}" == iran ]]; then
    [[ "${ST[transport]}" == pck ]] && return 0
    _bp_listening "${ST[tunnel_port]##*:}" "$(_bp_port_proto "${ST[transport]}")"
  else
    "$BP_BIN" tunnel status "$(_bp_name)" >/dev/null 2>&1
  fi
}

_bp_status_lines() {
  [[ -x "$BP_BIN" ]] || return 0
  "$BP_BIN" tunnel status "$(_bp_name)" 2>/dev/null | sed -E $'s/\x1b\\[[0-9;]*m//g' | grep -vE '^(name|role|transport|address) ' | sed 's/^/    /'
}

t_backpack_info() {
  st_load "$1"
  local t="${ST[transport]}"
  ui_kv "transport" "Reverse $(_bp_transport_label "$t") · $(_bp_preset_label "${ST[preset]:-}")"
  _bp_needs_tls "$t" && ui_kv "ECH" "on · WSS sends a Chrome TLS hello with ECH"
  if [[ "${ST[role]}" == iran ]]; then
    ui_kv "role" "Iran · server, listens ${ST[tunnel_port]}"
    ui_kv "service" "$(_bp_unit_of "$(_bp_name)") · $(_bp_conf "$(_bp_name)")"
    _bp_status_lines
    if [[ "${ST[mode]}" == socks ]]; then echo; xui_outbound_box "127.0.0.1" "${ST[iran_socks]}" "" ""
    else ui_kv "ports" "${ST[fwd]}"; fi
  else
    ui_kv "role" "Kharej · client → ${ST[iran_ip]}:${ST[tunnel_port]}"
    ui_kv "service" "$(_bp_unit_of "$(_bp_name)")"
    _bp_status_lines
    [[ "${ST[mode]}" == socks ]] && ui_kv "exit SOCKS5" "BackPack built-in proxy 127.0.0.1:${ST[foreign_socks]}"
  fi
  return 0
}

t_backpack_xui() {
  st_load "$1"
  if [[ "${ST[mode]}" == socks && "${ST[role]}" == iran ]]; then
    xui_help_socks "$1" "127.0.0.1" "${ST[iran_socks]}" "" ""
  elif [[ "${ST[mode]}" == socks ]]; then
    ui_warn "the 3x-ui SOCKS outbound is on the IRAN server: Manage → its BackPack tunnel → 3x-ui JSON helper."
  else
    ui_head "Use '$1' with 3x-ui (port forward)"; ui_note "Iran ports → kharej: ${ST[fwd]:-see the Iran side}"
  fi
}

t_backpack_test() {
  st_load "$1"
  local u; u="$(_bp_unit_of "$(_bp_name)")"
  if svc_active "$u"; then ui_ok "$u active"; else ui_err "$u not active"; return 1; fi
  if [[ -x "$BP_BIN" ]]; then
    "$BP_BIN" tunnel status "$(_bp_name)" 2>&1 | sed -E $'s/\x1b\\[[0-9;]*m//g' | sed 's/^/    /'
    if (( PIPESTATUS[0] == 0 )); then ui_ok "BackPack: online"; else ui_warn "BackPack: not online yet"; fi
  fi
  if [[ "${ST[role]}" == iran && "${ST[mode]}" == socks ]]; then doctor_socks 127.0.0.1 "${ST[iran_socks]}" "" "" || true; fi
  if [[ "${ST[role]}" == foreign && "${ST[mode]}" == socks ]]; then
    "$BP_BIN" proxy status 2>/dev/null | sed 's/^/    /'
  fi
  return 0
}

# what to carry to the kharej: BackPack's own setup link
t_backpack_handoff() {  # <name>
  st_load "$1"
  if [[ "${ST[role]}" == iran ]]; then
    if [[ -z "${ST[link]:-}" && -f "$(_bp_conf "$(_bp_name)")" ]]; then
      _bp_link_fill_from_toml "$(_bp_conf "$(_bp_name)")" "$(_bp_name)" "${ST[host]:-}" \
        "$(printf '%s' "${ST[backups]:-}" | tr ',' '\n')" "${ST[restart_h]:-0}" "${ST[restart_m]:-0}" && ST[link]="$(_bp_link_encode)"
    fi
    [[ -n "${ST[link]:-}" ]] || { ui_err "no setup link yet — the Iran setup did not finish (Edit to retry)."; return 1; }
    pair_present "${ST[link]}" "BackPack setup link — tunnel '$1'"
    ui_kv "carries" "Reverse $(_bp_transport_label "${ST[transport]}") · ${ST[host]:-?}:${ST[tunnel_port]##*:} · $(_bp_preset_label "${ST[preset]:-}")"
    echo; ui_info "Next, on the KHAREJ (foreign) server:"
    ui_note "mili → New tunnel → BackPack → Foreign → paste this link (or Import pairing code)."
    ui_note "plain BackPack works too:  sudo backpack link apply '<link>'"
    ui_note "kharej without anything:   bash <(curl -fsSL https://raw.githubusercontent.com/AminMGMT/BackPack/main/install.sh) link apply '<link>'"
    ui_note "Both servers must run the same BackPack (mili installs v$BP_VERSION)."
    ui_note "If this server's provider has a firewall panel, allow $(_bp_port_proto "${ST[transport]}" | tr a-z A-Z) ${ST[tunnel_port]##*:}."
    if [[ "${ST[mode]}" == socks ]]; then echo; xui_outbound_box "127.0.0.1" "${ST[iran_socks]}" "" ""; fi
  else
    ui_head "BackPack '$1' — kharej side"
    if t_backpack_probe "$1"; then ui_ok "connected to Iran ${ST[iran_ip]}:${ST[tunnel_port]}"
    else ui_warn "not connected to Iran yet (BackPack keeps trying)"; fi
    [[ "${ST[mode]}" == socks ]] && ui_note "The 3x-ui SOCKS outbound lives on the IRAN server: Manage → its BackPack tunnel → 3x-ui JSON helper."
  fi
  return 0
}
