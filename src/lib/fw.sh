# shellcheck shell=bash
# mili :: fw.sh - own iptables/ip6tables chains. NEVER flush, NEVER change policy.
# All rules tagged with -m comment --comment "mili:<name>" for clean removal.
# Guarantee = jump to MILI-IN inserted at top of INPUT. ufw/firewalld mirrored.

FW_TAGPFX="mili"

_ipt()  { run iptables  "$@"; }
_ipt6() { run ip6tables "$@"; }
# quiet check variants (status matters, output not)
_iptq()  { iptables  "$@" >/dev/null 2>&1; }
_ipt6q() { ip6tables "$@" >/dev/null 2>&1; }

# create our chains if absent and hook them (idempotent)
fw_init() {
  sys_has iptables || sys_apt_ensure iptables
  local t chain
  # filter
  for chain in MILI-IN; do
    _iptq -t filter -nL "$chain" || _ipt -t filter -N "$chain"
    _ipt6q -t filter -nL "$chain" || _ipt6 -t filter -N "$chain"
  done
  # nat
  for chain in MILI-PRE MILI-POST; do
    _iptq -t nat -nL "$chain" || _ipt -t nat -N "$chain"
    _ipt6q -t nat -nL "$chain" || _ipt6 -t nat -N "$chain"
  done
  # mangle (MSS clamp + paqet out), raw (paqet notrack)
  for chain in MILI-MSS MILI-OUT; do
    _iptq -t mangle -nL "$chain" || _ipt -t mangle -N "$chain"
    _ipt6q -t mangle -nL "$chain" || _ipt6 -t mangle -N "$chain"
  done
  _iptq -t raw -nL MILI-RAW || _ipt -t raw -N MILI-RAW
  _ipt6q -t raw -nL MILI-RAW || _ipt6 -t raw -N MILI-RAW
  fw_rehook
}

# ensure jump rules reference our chains (re-inserted if missing)
fw_rehook() {
  # filter INPUT -> MILI-IN at position 1
  _iptq  -t filter -C INPUT -j MILI-IN || _ipt  -t filter -I INPUT 1 -j MILI-IN
  _ipt6q -t filter -C INPUT -j MILI-IN || _ipt6 -t filter -I INPUT 1 -j MILI-IN
  # nat PREROUTING/POSTROUTING
  _iptq  -t nat -C PREROUTING  -j MILI-PRE  || _ipt  -t nat -I PREROUTING 1 -j MILI-PRE
  _ipt6q -t nat -C PREROUTING  -j MILI-PRE  || _ipt6 -t nat -I PREROUTING 1 -j MILI-PRE
  _iptq  -t nat -C POSTROUTING -j MILI-POST || _ipt  -t nat -I POSTROUTING 1 -j MILI-POST
  _ipt6q -t nat -C POSTROUTING -j MILI-POST || _ipt6 -t nat -I POSTROUTING 1 -j MILI-POST
  # mangle FORWARD -> MSS clamp
  _iptq  -t mangle -C FORWARD -j MILI-MSS || _ipt  -t mangle -I FORWARD 1 -j MILI-MSS
  _ipt6q -t mangle -C FORWARD -j MILI-MSS || _ipt6 -t mangle -I FORWARD 1 -j MILI-MSS
  # raw PREROUTING -> MILI-RAW  (paqet NOTRACK)
  _iptq  -t raw -C PREROUTING -j MILI-RAW || _ipt  -t raw -I PREROUTING 1 -j MILI-RAW
  # mangle OUTPUT -> MILI-OUT (paqet RST drop)
  _iptq  -t mangle -C OUTPUT -j MILI-OUT || _ipt -t mangle -I OUTPUT 1 -j MILI-OUT
}

# add a filter ACCEPT:  fw_allow <name> <proto> <port|range> [src]
fw_allow() {
  local name="$1" proto="$2" port="$3" src="${4:-}" tag="$FW_TAGPFX:$1"
  local -a a=(-t filter -A MILI-IN -p "$proto")
  [[ -n "$src" && "$src" != any ]] && a+=(-s "$src")
  [[ -n "$port" && "$port" != - ]] && a+=(--dport "$port")
  a+=(-m comment --comment "$tag" -j ACCEPT)
  _iptq -t filter -C MILI-IN -p "$proto" ${src:+-s "$src"} ${port:+--dport "$port"} -m comment --comment "$tag" -j ACCEPT \
    || _ipt "${a[@]}"
}

# allow GRE (proto 47) / FOU udp from a specific peer
fw_allow_proto() {  # <name> <protonum> <src>
  local name="$1" protonum="$2" src="$3" tag="$FW_TAGPFX:$1"
  _iptq -t filter -C MILI-IN -p "$protonum" -s "$src" -m comment --comment "$tag" -j ACCEPT \
    || _ipt -t filter -A MILI-IN -p "$protonum" -s "$src" -m comment --comment "$tag" -j ACCEPT
}

# DNAT a local public port to a remote target:  fw_dnat <name> <proto> <lport> <dst-ip> <dport>
fw_dnat() {
  local name="$1" proto="$2" lport="$3" dip="$4" dport="$5" tag="$FW_TAGPFX:$1"
  _iptq -t nat -C MILI-PRE -p "$proto" --dport "$lport" -m comment --comment "$tag" -j DNAT --to-destination "$dip:$dport" \
    || _ipt -t nat -A MILI-PRE -p "$proto" --dport "$lport" -m comment --comment "$tag" -j DNAT --to-destination "$dip:$dport"
  _iptq -t nat -C MILI-POST -p "$proto" -d "$dip" --dport "$dport" -m comment --comment "$tag" -j MASQUERADE \
    || _ipt -t nat -A MILI-POST -p "$proto" -d "$dip" --dport "$dport" -m comment --comment "$tag" -j MASQUERADE
}

# MASQUERADE an inner subnet out the default iface (L3 exit, foreign side)
fw_masq() {  # <name> <cidr>
  local name="$1" cidr="$2" tag="$FW_TAGPFX:$1"
  _iptq -t nat -C MILI-POST -s "$cidr" -m comment --comment "$tag" -j MASQUERADE \
    || _ipt -t nat -A MILI-POST -s "$cidr" -m comment --comment "$tag" -j MASQUERADE
}

# MSS clamp on a tunnel iface
fw_mss() {  # <name> <iface> [mss|pmtu]
  local name="$1" ifc="$2" mss="${3:-pmtu}" tag="$FW_TAGPFX:$1"
  local setspec=(--clamp-mss-to-pmtu)
  [[ "$mss" != pmtu ]] && setspec=(--set-mss "$mss")
  _iptq -t mangle -C MILI-MSS -o "$ifc" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS "${setspec[@]}" \
    || _ipt -t mangle -A MILI-MSS -o "$ifc" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS "${setspec[@]}"
}

# loopback guard for a SOCKS port an engine binds on 0.0.0.0 but should be local
fw_loopback_guard() {  # <name> <proto> <port>
  local name="$1" proto="$2" port="$3" tag="$FW_TAGPFX:$1"
  _iptq -t filter -C MILI-IN -p "$proto" --dport "$port" ! -i lo -m comment --comment "$tag" -j DROP \
    || _ipt -t filter -A MILI-IN -p "$proto" --dport "$port" ! -i lo -m comment --comment "$tag" -j DROP
}

# paqet: NOTRACK a raw-socket port so conntrack doesn't interfere
fw_raw_notrack() {  # <name> <proto> <port>
  local name="$1" proto="$2" port="$3" tag="$FW_TAGPFX:$1"
  _iptq -t raw -C MILI-RAW -p "$proto" --dport "$port" -m comment --comment "$tag" -j NOTRACK \
    || _ipt -t raw -A MILI-RAW -p "$proto" --dport "$port" -m comment --comment "$tag" -j NOTRACK
  _iptq -t raw -C MILI-RAW -p "$proto" --sport "$port" -m comment --comment "$tag" -j NOTRACK \
    || _ipt -t raw -A MILI-RAW -p "$proto" --sport "$port" -m comment --comment "$tag" -j NOTRACK
}

# paqet: drop kernel-generated RST for a tcp port (userspace owns the flow)
fw_drop_rst() {  # <name> <port>
  local name="$1" port="$2" tag="$FW_TAGPFX:$1"
  _iptq -t mangle -C MILI-OUT -p tcp --sport "$port" --tcp-flags RST RST -m comment --comment "$tag" -j DROP \
    || _ipt -t mangle -A MILI-OUT -p tcp --sport "$port" --tcp-flags RST RST -m comment --comment "$tag" -j DROP
}

# delete every rule tagged mili:<name> across all our chains (v4+v6)
fw_remove() {
  local name="$1" tag="$FW_TAGPFX:$1" table chain line
  for table in filter nat mangle raw; do
    for chain in MILI-IN MILI-PRE MILI-POST MILI-MSS MILI-OUT MILI-RAW; do
      _iptq -t "$table" -nL "$chain" || continue
      # repeatedly delete matching rules by spec
      while iptables -t "$table" -S "$chain" 2>/dev/null | grep -q "comment \"$tag\""; do
        line=$(iptables -t "$table" -S "$chain" 2>/dev/null | grep -m1 "comment \"$tag\"" | sed 's/^-A /-D /')
        # shellcheck disable=SC2086
        _ipt -t "$table" $line || break
      done
      while ip6tables -t "$table" -S "$chain" 2>/dev/null | grep -q "comment \"$tag\""; do
        line=$(ip6tables -t "$table" -S "$chain" 2>/dev/null | grep -m1 "comment \"$tag\"" | sed 's/^-A /-D /')
        # shellcheck disable=SC2086
        _ipt6 -t "$table" $line || break
      done
    done
  done
  fw_ufw_remove "$name"
}

# wipe all mili chains entirely (uninstall)
fw_teardown() {
  local table chain
  # unhook jumps first
  _iptq  -t filter -D INPUT -j MILI-IN; _ipt6q -t filter -D INPUT -j MILI-IN
  _iptq  -t nat -D PREROUTING -j MILI-PRE; _ipt6q -t nat -D PREROUTING -j MILI-PRE
  _iptq  -t nat -D POSTROUTING -j MILI-POST; _ipt6q -t nat -D POSTROUTING -j MILI-POST
  _iptq  -t mangle -D FORWARD -j MILI-MSS; _ipt6q -t mangle -D FORWARD -j MILI-MSS
  _iptq  -t raw -D PREROUTING -j MILI-RAW
  _iptq  -t mangle -D OUTPUT -j MILI-OUT
  for table in filter nat mangle raw; do
    for chain in MILI-IN MILI-PRE MILI-POST MILI-MSS MILI-OUT MILI-RAW; do
      _iptq  -t "$table" -F "$chain"; _iptq  -t "$table" -X "$chain"
      _ipt6q -t "$table" -F "$chain"; _ipt6q -t "$table" -X "$chain"
    done
  done
}

# ---- ufw / firewalld mirror (so later "enable ufw" doesn't kill tunnels) ---
fw_ufw_mirror() {  # <name> <proto> <port> [src]
  sys_has ufw || return 0
  local name="$1" proto="$2" port="$3" src="${4:-}"
  local cmt="mili:$name"
  if [[ -n "$src" && "$src" != any ]]; then
    run ufw allow from "$src" to any port "$port" proto "$proto" comment "$cmt" >/dev/null 2>&1 || true
  else
    run ufw allow "$port/$proto" comment "$cmt" >/dev/null 2>&1 || true
  fi
}
fw_ufw_allow_gre() {  # <name> <peer>
  sys_has ufw || return 0
  run ufw allow proto gre from "$2" comment "mili:$1" >/dev/null 2>&1 || true
}
fw_ufw_remove() {  # <name> : best-effort remove ufw rules we added
  sys_has ufw || return 0
  local name="$1" num
  # delete by matching comment, highest rule number first
  while read -r num; do
    [[ -n "$num" ]] && run bash -c "yes | ufw delete $num" >/dev/null 2>&1 || true
  done < <(ufw status numbered 2>/dev/null | grep "mili:$name" | grep -oE '^\[[ ]*[0-9]+\]' | grep -oE '[0-9]+' | sort -rn)
}
