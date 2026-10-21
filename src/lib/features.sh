# shellcheck shell=bash
# mili :: features.sh - feature registry with free/premium tiers + license stub.
# v1: everything free. Flipping a feature to premium = one line in a module.

MILI_LICENSE="${MILI_LICENSE:-$MILI_ETC/license}"
declare -gA FEAT_TIER=()   # id -> free|premium

feature() { FEAT_TIER["$1"]="${2:-free}"; }   # register

# is the premium license valid? (stub -> always false until real impl)
license_valid() {
  [[ -r "$MILI_LICENSE" ]] || return 1
  # future: verify signature / expiry. For now any non-empty file != valid.
  return 1
}

mili_edition() { license_valid && echo "Premium" || echo "Free"; }

mili_edition_badge() {
  if license_valid; then
    ui_badge "PREMIUM" "$C_YEL"
  else
    ui_badge "FREE" "$C_TEAL"
  fi
}

# feature_gate <id> : 0 if allowed, else prints notice and returns 1
feature_gate() {
  local id="$1" tier="${FEAT_TIER[$1]:-free}"
  [[ "$tier" == free ]] && return 0
  license_valid && return 0
  ui_warn "'$id' is a Premium feature - coming soon."
  return 1
}

feature_is_premium() { [[ "${FEAT_TIER[$1]:-free}" == premium ]]; }
