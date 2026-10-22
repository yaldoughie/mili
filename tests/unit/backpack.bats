#!/usr/bin/env bats
# mili :: BackPack (AminMGMT/BackPack v1.8.5) native flow.
# fixtures/backpack/*.toml and vectors.txt were produced by BackPack v1.8.5's own
# Go code (TunnelSpec.Render + shareLinkWith + a gzip-JSON format-1 link), so
# these tests prove mili's bash link codec is byte-identical to BackPack.

load helper

setup() {
  mili_load
  FX="$BATS_TEST_DIRNAME/fixtures/backpack"
}

iran_st() {
  ST=(); ST[name]=bp1; ST[type]=backpack; ST[role]=iran
  ST[transport]=tcp; ST[tunnel_port]=443; ST[token]=TOKtok123; ST[preset]=turbo
  ST[mode]=socks; ST[iran_socks]=10801; ST[foreign_socks]=10800; ST[accept_udp]=no
}

@test "backpack is a native-pairing tunnel, Iran first" {
  [ "$(t_meta_field backpack pairing)" = native ]
  [ "$(t_meta_field backpack primary)" = iran ]
}

# ---- setup link codec --------------------------------------------------------
@test "setup link from BackPack's TOML is byte-identical to BackPack (all vectors)" {
  local name host hosts rh rm link got n=0
  while IFS='|' read -r name host hosts rh rm link; do
    [[ "$name" == FORMAT1 ]] && continue
    _bp_link_fill_from_toml "$FX/backpack-$name.toml" "$name" "$host" "$(tr ',' '\n' <<<"$hosts")" "$rh" "$rm"
    got="$(_bp_link_encode)"
    [ "$got" = "$link" ] || { echo "vector $name: got $got"; return 1; }
    n=$((n + 1))
  done <"$FX/vectors.txt"
  [ "$n" -eq 6 ]
}

@test "link decode reads every field BackPack wrote" {
  local link
  link="$(awk -F'|' '$1=="wss1"{print $6}' "$FX/vectors.txt")"
  _bp_link_decode "$link"
  [ "${BL[k]}" = reverse ]; [ "${BL[f]}" = iran ]; [ "${BL[n]}" = wss1 ]
  [ "${BL[tr]}" = wss ]; [ "${BL[p]}" = 8443 ]; [ "${BL[h]}" = ir.example.com ]
  [ "${BL[pr]}" = balance ]; [ "${BL[po]}" = "443, 8443=127.0.0.1:2096" ]
  [ "${BL[u]}" = 1 ]; [ "${BL[sa]}" = 1 ]
  [ "${BL[hs]}" = $'5.6.7.8\ncdn.example.com:8443' ]
  [ "${BL[rh]}" = 6 ]; [ "${BL[rm]}" = 7 ]
  [ "${BL[t]}" = Ab3dEfGh1jKlMn0pQrStUvWxYz9876543210abcdefghijklmnopqrstuvwxyzAB ]
}

@test "default name is left out and put back (server-<port>), base-62 names round-trip" {
  local link
  link="$(awk -F'|' '$1=="server-3000"{print $6}' "$FX/vectors.txt")"
  _bp_link_decode "$link"
  [ "${BL[n]}" = server-3000 ]; [ "${BL[m]}" = 1300 ]; [ "${BL[mv]}" = 2 ]
  link="$(awk -F'|' '$1=="kcp1234567"{print $6}' "$FX/vectors.txt")"
  _bp_link_decode "$link"
  [ "${BL[n]}" = kcp1234567 ]; [ "${BL[t]}" = shortTOKEN ]; [ "${BL[fd]}" = 10 ]; [ "${BL[fp]}" = 1 ]
}

@test "format-1 links (older BackPack) still decode" {
  local link
  link="$(awk -F'|' '$1=="FORMAT1"{print $2}' "$FX/vectors.txt")"
  _bp_link_decode "$link"
  [ "${BL[n]}" = old1 ]; [ "${BL[tr]}" = ws ]; [ "${BL[p]}" = 8080 ]
  [ "${BL[po]}" = "127.0.0.1:10802=10800" ]; [ "${BL[hs]}" = 5.5.5.5 ]
}

@test "damaged / foreign strings are refused with BackPack's wording" {
  local link
  link="$(awk -F'|' '$1=="bp1"{print $6}' "$FX/vectors.txt")"
  refute _bp_link_decode "${link%?}"
  [[ "$BL_ERR" == *"damaged"* || "$BL_ERR" == *"incomplete"* ]]
  refute _bp_link_decode "vless://abc"
  [[ "$BL_ERR" == *"begin with backpack://"* ]]
  refute _bp_link_decode "backpack://9.AAAA"
  [[ "$BL_ERR" == *"version 9"* ]]
}

@test "a link pasted inside text, quoted or wrapped is still found" {
  local link
  link="$(awk -F'|' '$1=="bp1"{print $6}' "$FX/vectors.txt")"
  _bp_link_decode "here: '${link:0:30}
${link:30}' thanks"
  [ "${BL[n]}" = bp1 ]
}

@test "base-62 packing: widths and round trip" {
  [ "$(_bp_b62_width 1)" = 1 ]
  [ "$(_bp_b62_width 64)" = 48 ]
  _bp_b62_pack zz9; [ "$(_bp_b62_unpack 3 "${BPK[@]}")" = zz9 ]
  _bp_b62_pack aaaa; [ "$(_bp_b62_unpack 4 "${BPK[@]}")" = aaaa ]
}

@test "crc32 matches IEEE (gzip trailer)" {
  [ "$(_bp_crc32 49 50 51 52 53 54 55 56 57)" = 3421780262 ]   # "123456789" -> 0xCBF43926
}

@test "a pasted Iran link routes to the foreign side; other text does not" {
  local link
  link="$(awk -F'|' '$1=="bp1"{print $6}' "$FX/vectors.txt")"
  run t_backpack_accepts_token "$link"
  [ "$output" = foreign ]
  run t_backpack_accepts_token 'mili1:abc'
  [ "$status" -ne 0 ]
}

# ---- NewTunnel (BackPack's panel form) ---------------------------------------
@test "NewTunnel JSON: SOCKS mapping is loopback-only, only answered tune keys" {
  iran_st
  run _bp_newtunnel_json
  [ "$output" = '{"role":"server","transport":"tcp","name":"bp1","tunnelPort":"443","token":"TOKtok123","ports":"127.0.0.1:10801=10800","preset":"turbo","ipv6":false,"proxyProtocol":false,"tune":{"acceptUDP":false}}' ]
}

@test "NewTunnel JSON: forward list, fine-tune answers, pck flags, simpleAuth only on wss" {
  iran_st; ST[mode]=forward; ST[fwd]='443,8443=127.0.0.1:2096'; ST[transport]=pck; ST[pck_flags]=PA,A
  ST[tune_heartbeat]=0; ST[tune_logLevel]=debug; ST[simple_auth]=yes
  run _bp_newtunnel_json
  [[ "$output" == *'"ports":"443,8443=127.0.0.1:2096"'* ]]
  [[ "$output" == *'"tune":{"acceptUDP":false,"heartbeat":0,"logLevel":"debug"}'* ]]
  [[ "$output" == *'"pck":{"interface":"","gatewayMAC":"","flags":"PA,A"}'* ]]
  [[ "$output" != *simpleAuth* ]]
  ST[transport]=wssmux
  run _bp_newtunnel_json
  [[ "$output" == *'"conn":{"simpleAuth":true}'* ]]
  [[ "$output" != *'"pck"'* ]]
}

# ---- kharej side ---------------------------------------------------------------
@test "kharej usage from the link: SOCKS mapping -> proxy port, else forward" {
  [ "$(_bp_link_socks_port '127.0.0.1:10801=10800')" = 10800 ]
  [ "$(_bp_link_socks_port '127.0.0.1:10801=127.0.0.1:1080')" = 1080 ]
  [ -z "$(_bp_link_socks_port '443, 8443=127.0.0.1:2096')" ]
  [ -z "$(_bp_link_socks_port '0.0.0.0:10801=10800')" ]
}

@test "forward targets spelled out as BackPack does" {
  run _bp_forward_targets '443,8443=2096,9000=10.0.0.1:80|10.0.0.2:80'
  [ "${lines[0]}" = "443 → 127.0.0.1:443" ]
  [ "${lines[1]}" = "8443 → 127.0.0.1:2096" ]
  [ "${lines[2]}" = "9000 → 10.0.0.1:80|10.0.0.2:80" ]
}

@test "port mapping forms (docs/port-mappings.md)" {
  local ok
  for ok in 443 443=2096 443=127.0.0.1:2096 '443=10.0.0.1:80|10.0.0.2:80' 10000-10009 \
            10000-10009=20000-20009 127.0.0.1:443=2096 85.11.12.13:10000-10009 '[2a01:4f8::1]:443=127.0.0.1:2053'; do
    _bp_fwd_valid "$ok" || { echo "rejected $ok"; return 1; }
  done
  refute _bp_fwd_valid 0
  refute _bp_fwd_valid 70000
  refute _bp_fwd_valid 500-400
  refute _bp_fwd_valid 'abc'
  [ "$(_bp_fwd_local '85.11.12.13:443=2053')" = "85.11.12.13 443" ]
  [ "$(_bp_fwd_local '[2a01::1]:443=1')" = "[2a01::1] 443" ]
  [ "$(_bp_fwd_local '10000-10009')" = "0.0.0.0 10000-10009" ]
}

# ---- certificate + schedule, as BackPack's Render / SetScheduledRestart write them --
@test "Let's Encrypt lines go right after tls_key, as Render places them" {
  ST=([tls]=acme [acme_domain]=ir.example.com [acme_email]=a@b.c)
  run _bp_tls_rewrite "$FX/backpack-wss1.toml"
  [ "$status" -eq 0 ]
  printf '%s\n' "$output" | grep -A2 '^tls_key' | tr '\n' '|' | grep -qx 'tls_key = "/etc/backpack/certs/wss1.key"|acme_domain = "ir.example.com"|acme_email = "a@b.c"|'
  ST=([tls]=files [tls_cert]=/root/c.pem [tls_key]=/root/k.pem)
  run _bp_tls_rewrite "$FX/backpack-wss1.toml"
  [[ "$output" == *'tls_cert = "/root/c.pem"'* && "$output" == *'tls_key = "/root/k.pem"'* ]]
  [[ "$output" != *acme_domain* ]]
}

@test "restart schedule units match BackPack's (UTC calendar, effective hours)" {
  [ "$(_bp_restart_calendar 6 7)" = '*-*-* 00/6:07:00 UTC' ]
  [ "$(_bp_restart_calendar 24 0)" = '*-*-* 00:00:00 UTC' ]
  [ "$(_bp_restart_calendar 48 5)" = '*-*-01/2 00:05:00 UTC' ]
  [ "$(_bp_effective_hours 30)" = 24 ]
  [ "$(_bp_effective_hours 50)" = 48 ]
  local out; out="$(_bp_restart_units t1 6 7 | tr '\0' '#')"
  [[ "$out" == *"ExecStart=/bin/systemctl try-restart backpack-t1.service"*"#[Unit]"*"Description=Restart Backpack tunnel t1 every 6 hours (UTC, both servers at once)"*"OnCalendar=*-*-* 00/6:07:00 UTC"* ]]
}

@test "TOML readers (BackPack Render layout)" {
  [ "$(_bp_toml_get bind_addr "$FX/backpack-wss1.toml")" = "[::]:8443" ]
  [ "$(_bp_toml_get accept_udp "$FX/backpack-wss1.toml")" = true ]
  run _bp_toml_list ports "$FX/backpack-wss1.toml"
  [ "${lines[0]}" = 443 ]; [ "${lines[1]}" = "8443=127.0.0.1:2096" ]
  refute _bp_toml_get preset_missing "$FX/backpack-wss1.toml"
}

# ---- reserved ports: one kernel list shared with BackPack --------------------------
@test "reserved ports: mili's and BackPack's lists are merged and collapsed" {
  [ "$(sysctl_ports_union '443,10801,2083' '2084-2086,443,7000')" = "443,2083-2086,7000,10801" ]
  [ "$(sysctl_ports_union '' '')" = "" ]
  local f="$BATS_TEST_TMPDIR/zz-backpack.conf"
  printf '# Managed by backpack\nnet.core.somaxconn = 4096\nnet.ipv4.ip_local_reserved_ports = 443,5353,10000-10009\n' >"$f"
  BP_SYSCTL_FILE="$f"
  [ "$(sysctl_backpack_reserved)" = "443,5353,10000-10009" ]
}
