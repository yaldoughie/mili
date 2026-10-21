#!/usr/bin/env bats
# mili :: pairing + ports unit tests. Run:  bats tests/unit/
# Loads the bundled dist/mili.sh (built by ./build.sh) with `version` so the
# CLI returns immediately, then exercises pure functions.

setup() {
  export MILI_ETC="$BATS_TEST_TMPDIR/etc"
  export MILI_LOGDIR="$BATS_TEST_TMPDIR/log"
  export MILI_COLOR=never MILI_PUBIP4=1.1.1.1
  mkdir -p "$MILI_ETC" "$MILI_LOGDIR"
  set -- version
  # shellcheck disable=SC1090
  source "$BATS_TEST_DIRNAME/../../dist/mili.sh" >/dev/null 2>&1
}

@test "b64url roundtrip survives + / =" {
  run bash -c 'e=$(printf "a+b/c=d" | _b64url_enc); _b64url_dec "$e"'
  [ "$output" = "a+b/c=d" ]
}

@test "pairing plain encode/decode roundtrips fields" {
  local p; p=$'type=gre\nname=t1\nrole=foreign\nkey=42'
  local code; code=$(printf '%s' "$p" | pair_encode "")
  run pair_field "$(pair_decode "$code" "")" name
  [ "$output" = "t1" ]
}

@test "pairing encrypted needs the right passphrase" {
  local p=$'type=gre\nname=t1\nkey=42'
  local code; code=$(printf '%s' "$p" | pair_encode "secret")
  run pair_decode "$code" "secret"
  [ "$status" -eq 0 ]
  run pair_decode "$code" "wrong"
  [ -z "$output" ]
}

@test "GRE pair_export swaps role and IPs for the peer" {
  declare -gA ST
  ST=([name]=g1 [type]=gre [role]=iran [variant]=fou [mode]=socks [inner_n]=3 \
      [key]=7 [mtu]=1400 [ttl]=255 [fou_port]=20010 [my_ip]=1.1.1.1 [peer_ip]=2.2.2.2 \
      [inner_local]=10.77.3.1 [inner_peer]=10.77.3.2 [socks_port]=10810 [socks_user]=mili [socks_pass]=pw)
  st_save
  local exp; exp=$(t_gre_pair_export g1)
  [ "$(pair_field "$exp" role)" = foreign ]
  [ "$(pair_field "$exp" my_ip)" = 2.2.2.2 ]
  [ "$(pair_field "$exp" peer_ip)" = 1.1.1.1 ]
}

@test "ports allocator skips a claimed port" {
  ports_db_init
  ports_claim demo tcp 20000 0.0.0.0
  run ports_in_use 20000 ""
  [ "$status" -eq 0 ]
  run ports_in_use 20000 demo   # excluded for its own tunnel
  [ "$status" -ne 0 ]
}

@test "valid tunnel names" {
  run st_valid_name abc123
  [ "$status" -eq 0 ]
  run st_valid_name "toolongname11"
  [ "$status" -ne 0 ]
  run st_valid_name "Bad-Name"
  [ "$status" -ne 0 ]
}
