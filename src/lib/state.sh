# shellcheck shell=bash
# mili :: state.sh - tunnel registry CRUD + type dispatcher
#
# Each tunnel is a flat key=value file: /etc/mili/tunnels/<name>.conf
# Values written with printf %q (safe to re-source). Loaded into assoc array ST.

MILI_ETC="${MILI_ETC:-/etc/mili}"
MILI_TUNDIR="${MILI_TUNDIR:-$MILI_ETC/tunnels}"
MILI_CONF="${MILI_CONF:-$MILI_ETC/mili.conf}"

declare -gA ST   # current loaded tunnel record

st_dir_init() {
  # mili's own dirs; creating them is benign and must succeed even in dry-run
  mkdir -p "$MILI_ETC" "$MILI_TUNDIR" "$MILI_ETC/engines" "$MILI_ETC/pki" "$MILI_ETC/backups" 2>/dev/null || true
  chmod 700 "$MILI_ETC" "$MILI_TUNDIR" "$MILI_ETC/pki" 2>/dev/null || true
}

# valid tunnel name: lowercase alnum, 1..10 chars (keeps iface names within IFNAMSIZ)
st_valid_name() { [[ "$1" =~ ^[a-z0-9]{1,10}$ ]]; }

st_exists() { [[ -f "$MILI_TUNDIR/$1.conf" ]]; }

# list all tunnel names
st_list() {
  [[ -d "$MILI_TUNDIR" ]] || return 0
  local f
  for f in "$MILI_TUNDIR"/*.conf; do
    [[ -e "$f" ]] || continue
    basename "$f" .conf
  done
}

st_count() { st_list | grep -c . ; }

# load <name> into ST assoc array
st_load() {
  local name="$1" f="$MILI_TUNDIR/$1.conf"
  [[ -f "$f" ]] || return 1
  ST=()
  local k v line
  while IFS= read -r line; do
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]] || continue
    k="${BASH_REMATCH[1]}"; v="${BASH_REMATCH[2]}"
    # strip one layer of surrounding single quotes from printf %q output
    eval "v=$v" 2>/dev/null || v="${BASH_REMATCH[2]}"
    ST["$k"]="$v"
  done <"$f"
  ST[name]="$name"
  return 0
}

# save current ST array to disk (atomic)
st_save() {
  local name="${ST[name]:?st_save needs ST[name]}" f tmp
  st_valid_name "$name" || die "invalid tunnel name '$name'"
  st_dir_init
  f="$MILI_TUNDIR/$name.conf"
  tmp="$(mktemp "$MILI_TUNDIR/.$name.XXXXXX")" || die "mktemp failed"
  {
    printf '# mili tunnel record: %s\n' "$name"
    printf '# saved %s\n' "$(date -Iseconds 2>/dev/null || date)"
    local k
    for k in $(printf '%s\n' "${!ST[@]}" | sort); do
      printf '%s=%q\n' "$k" "${ST[$k]}"
    done
  } >"$tmp"
  run chmod 600 "$tmp" 2>/dev/null || true
  if [[ "${MILI_DRYRUN:-0}" == 1 ]]; then
    ui_info "[dry] would write $f"; cat "$tmp"; rm -f "$tmp"
  else
    mv -f "$tmp" "$f"
  fi
}

# get a field with default:  st_get <key> [default]
st_get() { local k="$1" d="${2:-}"; printf '%s' "${ST[$k]:-$d}"; }
st_set() { ST["$1"]="$2"; }

st_delete_file() {
  local name="$1"
  [[ -f "$MILI_TUNDIR/$name.conf" ]] && run rm -f "$MILI_TUNDIR/$name.conf"
}

# ---- type dispatcher -------------------------------------------------------
# All tunnel modules expose functions named t_<type>_<op>.
# t_has <type> <op> -> true if function defined.
t_has() { declare -F "t_$1_$2" >/dev/null 2>&1; }

# t_call <type> <op> [args...] ; fails loudly if missing
t_call() {
  local type="$1" op="$2"; shift 2
  if t_has "$type" "$op"; then
    "t_${type}_${op}" "$@"
  else
    die "tunnel type '$type' has no operation '$op'"
  fi
}

# registered tunnel types (populated by modules via t_register)
declare -ga MILI_TYPES=()
# t_register <type> ; modules call this at load
t_register() { MILI_TYPES+=("$1"); }

# resolve meta field:  t_meta_field <type> <field>
# modules' t_<type>_meta prints "key=value" lines.
t_meta_field() {
  local type="$1" field="$2"
  t_has "$type" meta || return 1
  "t_${type}_meta" | awk -F= -v k="$field" '$1==k{sub(/^[^=]*=/,""); print; exit}'
}
