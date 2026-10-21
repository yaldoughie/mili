#!/usr/bin/env bats
# mili :: paqet native flow (ChownYourLife deploy-tunnel layout, paqet's real YAML keys)

load helper

setup() { mili_load; }

pq_st() {  # <role>
  ST=(); ST[name]=pq1; ST[type]=paqet; ST[role]=$1
  ST[iface]=eth0; ST[local_ip]=10.0.0.5; ST[router_mac]=aa:bb:cc:dd:ee:01
  ST[listen_port]=9999; ST[secret]=KEY123; ST[conn]=3; ST[kcp]=fast; ST[mtu]=1350; ST[kcp_preset]=normal
}

@test "paqet is a native-pairing tunnel, foreign listens first" {
  [ "$(t_meta_field paqet pairing)" = native ]
  [ "$(t_meta_field paqet primary)" = foreign ]
}

@test "KCP values = the deploy script's set_kcp_defaults / apply_kcp_preset" {
  [ "$(_pq_kcp_values normal server)"    = "1 10 2 1 2048 2048 4194304 2097152" ]
  [ "$(_pq_kcp_values normal client)"    = "1 10 2 1 1024 1024 4194304 2097152" ]
  [ "$(_pq_kcp_values gaming server)"    = "1 10 2 1 1024 1024 2097152 1048576" ]
  [ "$(_pq_kcp_values gaming client)"    = "1 10 2 1 512 512 2097152 1048576" ]
  [ "$(_pq_kcp_values streaming server)" = "1 10 2 1 4096 4096 8388608 4194304" ]
  [ "$(_pq_kcp_values streaming client)" = "1 10 2 1 2048 2048 8388608 4194304" ]
}

@test "server YAML: listen + ipv4 port match, 8MB pcap, paqet's real key names" {
  pq_st foreign
  run _pq_yaml pq1
  [[ "$output" == *'role: "server"'* ]]
  [[ "$output" == *$'listen:\n  addr: ":9999"'* ]]
  [[ "$output" == *'addr: "10.0.0.5:9999"'* ]]
  [[ "$output" == *'router_mac: "aa:bb:cc:dd:ee:01"'* ]]
  [[ "$output" == *'sockbuf: 8388608'* ]]
  [[ "$output" == *'nocongestion: 1'* ]]
  [[ "$output" != *' nc: '* ]]
  [[ "$output" == *'rcvwnd: 2048'* ]]
  [[ "$output" == *'key: "KEY123"'* ]]
  [[ "$output" == *'block: "aes"'* ]]
  [[ "$output" != *'socks5:'* ]]
  [[ "$output" != *$'\nserver:'* ]]
}

@test "client YAML (SOCKS): random local port, server addr, loopback SOCKS5 without auth" {
  pq_st iran; ST[foreign_ip]=203.0.113.10; ST[proxy]=socks; ST[socks_port]=10877
  run _pq_yaml pq1
  [[ "$output" == *'role: "client"'* ]]
  [[ "$output" == *'addr: "10.0.0.5:0"'* ]]
  [[ "$output" == *$'server:\n  addr: "203.0.113.10:9999"'* ]]
  [[ "$output" == *'listen: "127.0.0.1:10877"'* ]]
  [[ "$output" == *'username: ""'* ]]
  [[ "$output" == *'sockbuf: 4194304'* ]]
  [[ "$output" == *'rcvwnd: 1024'* ]]
  [[ "$output" != *$'\nlisten:'* ]]
}

@test "client YAML (forward): targets are on the foreign server, like the script" {
  pq_st iran; ST[foreign_ip]=203.0.113.10; ST[proxy]=forward; ST[fwd]="8443=443,2083=2083"
  run _pq_yaml pq1
  [[ "$output" == *$'  - listen: ":8443"\n    target: "203.0.113.10:443"\n    protocol: "tcp"'* ]]
  [[ "$output" == *$'  - listen: ":2083"\n    target: "203.0.113.10:2083"'* ]]
  [[ "$output" != *'socks5:'* ]]
}

@test "manual mode writes the preset's KCP values" {
  pq_st iran; ST[foreign_ip]=203.0.113.10; ST[proxy]=socks; ST[socks_port]=10877
  ST[kcp]=manual; ST[kcp_preset]=gaming
  run _pq_yaml pq1
  [[ "$output" == *'mode: "manual"'* ]]
  [[ "$output" == *'rcvwnd: 512'* ]]
  [[ "$output" == *'smuxbuf: 2097152'* ]]
}

@test "TCP flags and MAC validation" {
  [ "$(_pq_flags PA)" = '["PA"]' ]
  [ "$(_pq_flags PA,S)" = '["PA", "S"]' ]
  _pq_valid_mac aa:bb:cc:dd:ee:ff
  refute _pq_valid_mac aa:bb:cc:dd:ee
  refute _pq_valid_mac '<incomplete>'
}

@test "paqet download URL matches the real release asset names" {
  MILI_ARCH=amd64; [ "$(cores_url paqet)" = "https://github.com/hanselime/paqet/releases/download/v1.0.0-alpha.21/paqet-linux-amd64-v1.0.0-alpha.21.tar.gz" ]
  MILI_ARCH=arm64; [[ "$(cores_url paqet)" == */paqet-linux-arm64-v1.0.0-alpha.21.tar.gz ]]
  MILI_ARCH=armv7; [[ "$(cores_url paqet)" == */paqet-linux-arm32-v1.0.0-alpha.21.tar.gz ]]
}
