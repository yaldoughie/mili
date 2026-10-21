# shellcheck shell=bash
# mili :: ui.sh - colors, banner, boxes, menus, prompts, spinner, badges
# Pure functions. No top-level side effects except ui_init() when called.

# ---- color capability detection ------------------------------------------
# Sets MILI_COLORMODE = truecolor | 256 | 16 | none and defines palette vars.
ui_init() {
  local force="${MILI_COLOR:-auto}"   # auto|always|never
  MILI_COLORMODE=none
  if [[ "$force" == never || -n "${NO_COLOR:-}" ]]; then
    MILI_COLORMODE=none
  elif [[ "$force" == always ]]; then
    MILI_COLORMODE=truecolor
  elif [[ -t 1 ]]; then
    case "${COLORTERM:-}" in
      truecolor|24bit) MILI_COLORMODE=truecolor ;;
      *)
        local n; n=$(tput colors 2>/dev/null || echo 0)
        if   (( n >= 256 )); then MILI_COLORMODE=256
        elif (( n >= 8   )); then MILI_COLORMODE=16
        else MILI_COLORMODE=none; fi ;;
    esac
  fi

  if [[ "$MILI_COLORMODE" == none ]]; then
    C_RST=''; C_B=''; C_DIM=''; C_IT=''; C_UL=''
    C_RED=''; C_GRN=''; C_YEL=''; C_BLU=''; C_MAG=''; C_CYN=''; C_WHT=''; C_GRY=''
    C_ORA=''; C_PNK=''; C_TEAL=''; C_LIME=''
    return 0
  fi

  C_RST=$'\e[0m'; C_B=$'\e[1m'; C_DIM=$'\e[2m'; C_IT=$'\e[3m'; C_UL=$'\e[4m'
  if [[ "$MILI_COLORMODE" == truecolor ]]; then
    C_RED=$'\e[38;2;255;85;85m';   C_GRN=$'\e[38;2;80;220;130m'
    C_YEL=$'\e[38;2;245;205;80m';  C_BLU=$'\e[38;2;90;160;255m'
    C_MAG=$'\e[38;2;200;120;255m'; C_CYN=$'\e[38;2;90;220;230m'
    C_WHT=$'\e[38;2;240;240;245m'; C_GRY=$'\e[38;2;150;155;165m'
    C_ORA=$'\e[38;2;255;160;70m';  C_PNK=$'\e[38;2;255;120;180m'
    C_TEAL=$'\e[38;2;60;200;190m'; C_LIME=$'\e[38;2;170;230;90m'
  elif [[ "$MILI_COLORMODE" == 256 ]]; then
    C_RED=$'\e[38;5;203m'; C_GRN=$'\e[38;5;114m'; C_YEL=$'\e[38;5;221m'
    C_BLU=$'\e[38;5;75m';  C_MAG=$'\e[38;5;177m'; C_CYN=$'\e[38;5;80m'
    C_WHT=$'\e[38;5;255m'; C_GRY=$'\e[38;5;245m'; C_ORA=$'\e[38;5;215m'
    C_PNK=$'\e[38;5;211m'; C_TEAL=$'\e[38;5;43m'; C_LIME=$'\e[38;5;149m'
  else
    C_RED=$'\e[31m'; C_GRN=$'\e[32m'; C_YEL=$'\e[33m'; C_BLU=$'\e[34m'
    C_MAG=$'\e[35m'; C_CYN=$'\e[36m'; C_WHT=$'\e[37m'; C_GRY=$'\e[90m'
    C_ORA=$'\e[33m'; C_PNK=$'\e[35m'; C_TEAL=$'\e[36m'; C_LIME=$'\e[32m'
  fi
}

# visible width of a string (strip ANSI)
ui_width() { local s="$1"; s=$(printf '%s' "$s" | sed -E $'s/\x1b\\[[0-9;]*m//g'); printf '%s' "${#s}"; }

# truecolor gradient banner for the word MILI
ui_banner() {
  local sub="${1:-}"
  if [[ "$MILI_COLORMODE" == none ]]; then
    printf '%s\n' "=== M I L I ==="
    [[ -n "$sub" ]] && printf '%s\n' "$sub"
    return
  fi
  local -a rows
  rows=(
    'MM    MM  II  LL      II'
    'MMM  MMM  II  LL      II'
    'MM MM MM  II  LL      II'
    'MM    MM  II  LL      II'
    'MM    MM  II  LLLLLL  II'
  )
  local row out ch n i r g b
  for row in "${rows[@]}"; do
    out=''; n=${#row}
    for (( i=0; i<n; i++ )); do
      ch="${row:i:1}"
      if [[ "$ch" == ' ' ]]; then out+=' '; continue; fi
      if [[ "$MILI_COLORMODE" == truecolor ]]; then
        r=$(( 130 + i*110/(n>1?n-1:1) ))
        g=$(( 90  + i*50 /(n>1?n-1:1) ))
        b=$(( 235 - i*70 /(n>1?n-1:1) ))
        out+=$'\e[1;38;2;'"$r;$g;$b"'m'"$ch"
      else
        out+="$C_B$C_MAG$ch"
      fi
    done
    printf '  %s%s\n' "$out" "$C_RST"
  done
  [[ -n "$sub" ]] && printf '  %s%s%s\n' "$C_GRY" "$sub" "$C_RST"
}

# horizontal rule
ui_hr() { local w="${1:-64}" ch="${2:--}" out='' i; for ((i=0;i<w;i++)); do out+="$ch"; done; printf '%s%s%s\n' "$C_GRY" "$out" "$C_RST"; }

# section header
ui_head() { printf '\n%s[ %s ]%s\n' "$C_B$C_CYN" "$1" "$C_RST"; ui_hr 64; }

# status glyphs
ui_ok()   { printf '%s[OK]%s %s\n'   "$C_GRN" "$C_RST" "$*"; }
ui_warn() { printf '%s[!]%s %s\n'    "$C_YEL" "$C_RST" "$*"; }
ui_err()  { printf '%s[x]%s %s\n'    "$C_RED" "$C_RST" "$*"; }
ui_info() { printf '%s[*]%s %s\n'    "$C_BLU" "$C_RST" "$*"; }
ui_note() { printf '%s    %s%s\n'    "$C_GRY" "$*" "$C_RST"; }

# colored badge:  ui_badge <text> <color>
ui_badge() { local t="$1" c="${2:-$C_BLU}"; printf '%s %s %s' "$c$C_B" "$t" "$C_RST"; }

# key/value line
ui_kv() { printf '  %s%-18s%s %s\n' "$C_GRY" "$1" "$C_RST" "$2"; }

# numbered menu item:  ui_item <num> <label> [hint] [star]
ui_item() {
  local n="$1" label="$2" hint="${3:-}" star="${4:-}"
  local s=''; [[ -n "$star" ]] && s="$C_YEL*$C_RST "
  if [[ -n "$hint" ]]; then
    printf '   %s%2s%s) %s%s%-26s%s %s%s%s\n' "$C_B$C_CYN" "$n" "$C_RST" "$s" "$C_WHT" "$label" "$C_RST" "$C_GRY" "$hint" "$C_RST"
  else
    printf '   %s%2s%s) %s%s%s\n' "$C_B$C_CYN" "$n" "$C_RST" "$s$C_WHT" "$label" "$C_RST"
  fi
}

# ============================================================================
# arrow-key selector (live pointer, up/down + Enter). Returns 1-based index in
# global SEL (0 = cancelled). Items may embed a hint as "label\thint".
# Falls back to a numbered prompt when stdin/stdout is not a TTY or NO_COLOR.
# ============================================================================
declare -ga UISEL_ITEMS=()
UISEL_SEL=0

_ui_sel_row() {  # <index>
  local i="$1" raw="${UISEL_ITEMS[$1]}" label hint
  label="${raw%%$'\t'*}"; hint=''
  [[ "$raw" == *$'\t'* ]] && hint="${raw#*$'\t'}"
  if (( i == UISEL_SEL )); then
    printf '\e[2K   %s%s %s%-30s%s%s%s%s\n' \
      "$C_B$C_CYN" "▶" "$C_B$C_WHT" "$label" "$C_RST" \
      "${hint:+  $C_CYN}" "$hint" "$C_RST"
  else
    printf '\e[2K     %s%-30s%s%s%s%s\n' \
      "$C_WHT" "$label" "$C_RST" "${hint:+  $C_GRY}" "$hint" "$C_RST"
  fi
}

_ui_sel_render() { local i; for i in "${!UISEL_ITEMS[@]}"; do _ui_sel_row "$i"; done; }

# ui_select <preselect-index> <item> [item...]   -> sets SEL (1-based; 0=cancel)
ui_select() {
  local pre="${1:-0}"; shift
  UISEL_ITEMS=("$@"); UISEL_SEL="$pre"
  local n=${#UISEL_ITEMS[@]} key esc
  (( n == 0 )) && { SEL=0; return; }
  (( UISEL_SEL < 0 || UISEL_SEL >= n )) && UISEL_SEL=0

  # fallback: no TTY / no color -> numbered prompt
  if [[ ! -t 0 || ! -t 1 || "$MILI_COLORMODE" == none ]]; then
    local i; for i in "${!UISEL_ITEMS[@]}"; do
      printf '   %s%2d%s) %s\n' "$C_B$C_CYN" $((i+1)) "$C_RST" "${UISEL_ITEMS[$i]%%$'\t'*}"
    done
    local pick; read -r -p "$(printf '%s>%s ' "$C_CYN" "$C_RST")" pick || true
    [[ "$pick" =~ ^[0-9]+$ ]] && SEL="$pick" || SEL=0
    return
  fi

  tput civis 2>/dev/null || true
  _ui_sel_render
  while :; do
    IFS= read -rsn1 key 2>/dev/null || { SEL=0; break; }
    case "$key" in
      $'\x1b') read -rsn2 -t 0.05 esc 2>/dev/null
               case "$esc" in
                 '[A'|'OA') (( UISEL_SEL = (UISEL_SEL - 1 + n) % n )) ;;
                 '[B'|'OB') (( UISEL_SEL = (UISEL_SEL + 1) % n )) ;;
                 '') SEL=0; break ;;   # bare ESC = cancel
               esac ;;
      ''|$'\n'|$'\r') SEL=$(( UISEL_SEL + 1 )); break ;;
      k|K) (( UISEL_SEL = (UISEL_SEL - 1 + n) % n )) ;;
      j|J) (( UISEL_SEL = (UISEL_SEL + 1) % n )) ;;
      q|Q) SEL=0; break ;;
      [1-9]) (( key >= 1 && key <= n )) && UISEL_SEL=$(( key - 1 )) ;;
    esac
    printf '\e[%dA' "$n"   # move back to top of list
    _ui_sel_render
  done
  tput cnorm 2>/dev/null || true
}

# ---- prompts ---------------------------------------------------------------
# ask <prompt> <default> -> echoes answer
ui_ask() {
  local p="$1" def="${2:-}" ans
  if [[ -n "$def" ]]; then
    read -r -p "$(printf '%s? %s%s %s[%s]%s: ' "$C_CYN" "$C_RST" "$p" "$C_GRY" "$def" "$C_RST")" ans || true
    printf '%s' "${ans:-$def}"
  else
    read -r -p "$(printf '%s? %s%s: ' "$C_CYN" "$C_RST" "$p")" ans || true
    printf '%s' "$ans"
  fi
}

# ask_secret <prompt> -> echoes answer (no echo while typing)
ui_ask_secret() {
  local p="$1" ans
  read -r -s -p "$(printf '%s? %s%s: ' "$C_CYN" "$C_RST" "$p")" ans || true
  printf '\n' >&2
  printf '%s' "$ans"
}

# confirm <prompt> [default y|n] -> returns 0 for yes
ui_confirm() {
  local p="$1" def="${2:-n}" ans hint='[y/N]'
  [[ "$def" == y ]] && hint='[Y/n]'
  read -r -p "$(printf '%s? %s%s %s%s%s ' "$C_YEL" "$C_RST" "$p" "$C_GRY" "$hint" "$C_RST")" ans || true
  ans="${ans:-$def}"
  [[ "$ans" =~ ^[Yy]$ ]]
}

# pause until Enter
ui_pause() { read -r -p "$(printf '%s    press Enter to continue%s' "$C_GRY" "$C_RST")" _ || true; }

# spinner around a background pid:  ui_spin <pid> <msg>
ui_spin() {
  local pid="$1" msg="${2:-working}" frames='|/-\' i=0 rc
  if [[ "$MILI_COLORMODE" == none || ! -t 1 ]]; then
    wait "$pid" 2>/dev/null; return $?
  fi
  tput civis 2>/dev/null || true
  while kill -0 "$pid" 2>/dev/null; do
    printf '\r%s%s%s %s ' "$C_CYN" "${frames:i++%${#frames}:1}" "$C_RST" "$msg"
    sleep 0.1
  done
  wait "$pid" 2>/dev/null; rc=$?
  tput cnorm 2>/dev/null || true
  printf '\r\033[K'
  return $rc
}

ui_clear() { [[ -t 1 && "$MILI_COLORMODE" != none ]] && printf '\033[2J\033[H' || true; }
