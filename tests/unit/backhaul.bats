#!/usr/bin/env bats
# mili :: Backhaul native flow (Musixal installer layout, open-source core v0.7.2)

load helper

setup() { mili_load; }

iran_st() {
  ST=(); ST[name]=bh1; ST[type]=backhaul; ST[role]=iran
  ST[tunnel_port]=3080; ST[transport]=tcp; ST[token]=TOKabc
  ST[accept_udp]=false; ST[channel_size]=2048; ST[nodelay]=true; ST[heartbeat]=40
  ST[mux_con]=8; ST[mux_version]=2; ST[sniffer]=false; ST[web_port]=0; ST[proxy_protocol]=false
  ST[mode]=socks; ST[iran_socks]=10810; ST[foreign_socks]=10880
}

@test "backhaul is a native-pairing tunnel, Iran listens first" {
  [ "$(t_meta_field backhaul pairing)" = native ]
  [ "$(t_meta_field backhaul primary)" = iran ]
}

@test "Iran TOML: Musixal layout, skip_optz, loopback SOCKS mapping" {
  iran_st
  run _bh_toml bh1
  [ "$status" -eq 0 ]
  local want
  want="# mili Backhaul server (Iran) - tunnel bh1
[server]
bind_addr = \":3080\"
transport = \"tcp\"
accept_udp = false
token = \"TOKabc\"
keepalive_period = 75
nodelay = true
channel_size = 2048
heartbeat = 40
mux_con = 8
mux_version = 2
mux_framesize = 32768
mux_recievebuffer = 4194304
mux_streambuffer = 2000000
sniffer = false
web_port = 0
sniffer_log = \"$MILI_LOGDIR/backhaul-bh1.json\"
log_level = \"info\"
proxy_protocol = false
skip_optz = true

ports = [
    \"127.0.0.1:10810=10880\",
]"
  [ "$output" = "$want" ]
}

@test "Foreign TOML: dials Iran, IPv6 bracketed, edge only for websocket" {
  ST=(); ST[name]=bh2; ST[role]=foreign; ST[iran_ip]=2001:db8::1; ST[tunnel_port]=3080
  ST[transport]=tcp; ST[token]=T; ST[edge_ip]=188.114.96.0; ST[mux_version]=2
  run _bh_toml bh2
  [[ "$output" == *'remote_addr = "[2001:db8::1]:3080"'* ]]
  [[ "$output" != *edge_ip* ]]
  [[ "$output" == *'connection_pool = 8'* ]]
  [[ "$output" == *'retry_interval = 3'* ]]
  [[ "$output" == *'skip_optz = true'* ]]
  ST[transport]=wsmux
  run _bh_toml bh2
  [[ "$output" == *'edge_ip = "188.114.96.0"'* ]]
}

@test "udp transport forces nodelay=false; old state keeps the core's mux_version 1" {
  iran_st; ST[transport]=udp; ST[nodelay]=true; ST[mode]=forward; ST[fwd]=5353
  unset 'ST[mux_version]'
  run _bh_toml bh1
  [[ "$output" == *'nodelay = false'* ]]
  [[ "$output" == *'mux_version = 1'* ]]
  [[ "$output" == *'    "5353",'* ]]
}

@test "wss/wssmux get tls_cert/tls_key (self-signed path when no real cert)" {
  iran_st; ST[transport]=wssmux; ST[domain]=''
  run _bh_toml bh1
  [[ "$output" == *"tls_cert = \"$MILI_ETC/pki/bh1/cert.pem\""* ]]
  [[ "$output" == *"tls_key = \"$MILI_ETC/pki/bh1/key.pem\""* ]]
  ST[transport]=tcpmux
  run _bh_toml bh1
  [[ "$output" != *tls_cert* ]]
}

@test "ports list: every form the v0.7.2 core accepts, nothing else" {
  local ok bad
  for ok in 443 443-600 4000=5000 443-600=5201 443=1.1.1.1:5201 443-600=1.1.1.1:5201 \
            127.0.0.2:443=5201 127.0.0.2:443=1.1.1.1:5201 8080=example.com:80; do
    _bh_fwd_valid "$ok" || { echo "rejected $ok"; return 1; }
  done
  for bad in '' x 443-600:5201 600-443 70000 443=x=1 '443= 5' 1.2.3.4=5; do
    if _bh_fwd_valid "$bad"; then echo "accepted $bad"; return 1; fi
  done
}

@test "ports list: local side + forward block" {
  [ "$(_bh_fwd_local 443-600=5201)" = "0.0.0.0 443-600" ]
  [ "$(_bh_fwd_local 127.0.0.2:443=1.1.1.1:5201)" = "127.0.0.2 443" ]
  iran_st; ST[mode]=forward; ST[fwd]="443-445, 8443=2083"
  run _bh_ports_block
  [ "${lines[0]}" = '    "443-445",' ]
  [ "${lines[1]}" = '    "8443=2083",' ]
}

@test "foreign SOCKS default is derived from the tunnel port (same on both servers)" {
  [ "$(_bh_socks_default 20000)" = 10800 ]
  [ "$(_bh_socks_default 3080)" = 10880 ]
  [ "$(_bh_socks_default 23456)" = 10856 ]
}

@test "token must be a plain TOML string" {
  _bh_valid_token abcDEF123-_.
  refute _bh_valid_token 'has space'
  refute _bh_valid_token 'q"uote'
  refute _bh_valid_token 'back\slash'
  refute _bh_valid_token ''
}
