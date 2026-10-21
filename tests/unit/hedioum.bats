#!/usr/bin/env bats
# mili :: hedioum native-pairing helpers. Run:  bats tests/unit/
# Expected values were produced by hedioum v0.11.0's own Go code
# (internal/pairing + internal/persona + config.MarshalIndent), so these tests
# prove mili's bash port is byte-identical to hedioum.

load helper

setup() {
  mili_load
  FX="$BATS_TEST_DIRNAME/fixtures"
}

# Go: pairing.Encode(Token{95.179.148.154, aabb.., cpanel, vpn.example.com, {ssh:2200 tls:443 cpanel:2083 mysql:3306}})
TOK1=eyJ2IjoyLCJpcCI6Ijk1LjE3OS4xNDguMTU0IiwiYXV0aCI6ImFhYmJjY2RkZWVmZjAwMTEyMjMzNDQ1NTY2Nzc4ODk5IiwicGVyc29uYSI6ImNwYW5lbCIsInNuaSI6InZwbi5leGFtcGxlLmNvbSIsImVwcyI6eyJjcGFuZWwiOjIwODMsIm15c3FsIjozMzA2LCJzc2giOjIyMDAsInRscyI6NDQzfX0
# Go: no persona/sni (omitempty)
TOK2=eyJ2IjoyLCJpcCI6IjEuMi4zLjQiLCJhdXRoIjoiMDE4OWU3NzJiZmU2M2Q4MTVmMDI2YjhmNzZkMjkyZWEiLCJlcHMiOnsic3NoIjoyMiwidGxzIjo0NDN9fQ
# Go: token for fixtures/hedioum-foreign.json with exit IP 9.9.9.9
TOKF=eyJ2IjoyLCJpcCI6IjkuOS45LjkiLCJhdXRoIjoiYWFiYmNjZGRlZWZmMDAxMTIyMzM0NDU1NjY3Nzg4OTkiLCJwZXJzb25hIjoiY3BhbmVsIiwic25pIjoidnBuLmV4YW1wbGUuY29tIiwiZXBzIjp7ImNwYW5lbCI6MjA4MywiZG9ja2VyIjo1MDAwLCJpbWFwcyI6OTkzLCJteXNxbCI6MzMwNiwic210cCI6NTg3LCJzbXRwcyI6NDY1LCJzc2giOjIyLCJ0bHMiOjQ0Mywid2VibWFpbCI6MjA5Niwid2htIjoyMDg3fX0

# ---- token encode / decode --------------------------------------------------
@test "token encode is byte-identical to hedioum (Go)" {
  run _hed_token_encode 95.179.148.154 aabbccddeeff00112233445566778899 cpanel vpn.example.com 'ssh:2200 tls:443 cpanel:2083 mysql:3306'
  [ "$output" = "$TOK1" ]
}

@test "token encode omits empty persona/sni like Go omitempty" {
  run _hed_token_encode 1.2.3.4 0189e772bfe63d815f026b8f76d292ea '' '' 'tls:443 ssh:22'
  [ "$output" = "$TOK2" ]
}

@test "token decode extracts every field" {
  _hed_token_decode "$TOK1"
  [ "$HT_IP" = 95.179.148.154 ]
  [ "$HT_AUTH" = aabbccddeeff00112233445566778899 ]
  [ "$HT_PERSONA" = cpanel ]
  [ "$HT_SNI" = vpn.example.com ]
  [ "$HT_EPS" = "cpanel:2083 mysql:3306 ssh:2200 tls:443" ]
}

@test "token decode tolerates surrounding whitespace/newlines" {
  _hed_token_decode "  $TOK2
"
  [ "$HT_IP" = 1.2.3.4 ]
}

@test "legacy 32-hex auth key is recognized (rc 2)" {
  run _hed_token_decode 0189e772bfe63d815f026b8f76d292ea
  [ "$status" -eq 2 ]
}

@test "garbage and the old mis-captured substring are rejected" {
  run _hed_token_decode '!!!not-a-token!!!'
  [ "$status" -eq 1 ]
  run _hed_token_decode '--target-ip/--persona/--mimics:'
  [ "$status" -eq 1 ]
}

@test "token validation mirrors hedioum's errors" {
  local bad
  bad=$(printf '%s' '{"v":2,"ip":"1.2.3.4","auth":"short","eps":{"tls":443}}' | _b64url_enc)
  _hed_token_decode "$bad" || true; [ "$HT_ERR" = "pairing token has an invalid auth key" ]
  bad=$(printf '%s' '{"v":2,"ip":"","auth":"aabbccddeeff00112233445566778899","eps":{"tls":443}}' | _b64url_enc)
  _hed_token_decode "$bad" || true; [ "$HT_ERR" = "pairing token has no exit IP" ]
  bad=$(printf '%s' '{"v":2,"ip":"1.2.3.4","auth":"aabbccddeeff00112233445566778899","eps":{}}' | _b64url_enc)
  _hed_token_decode "$bad" || true; [ "$HT_ERR" = "pairing token has no endpoints" ]
  bad=$(printf '%s' '{"v":2,"ip":"1.2.3.4","auth":"aabbccddeeff00112233445566778899","eps":{"tls":0}}' | _b64url_enc)
  _hed_token_decode "$bad" || true; [[ "$HT_ERR" == *'invalid port 0'* ]]
  bad=$(printf '%s' '{"v":3,"ip":"1.2.3.4","auth":"aabbccddeeff00112233445566778899","eps":{"tls":443}}' | _b64url_enc)
  _hed_token_decode "$bad" || true; [[ "$HT_ERR" == *'version 3'* ]]
}

@test "hedioum's own printed token is picked out of noisy setup output" {
  local log="$BATS_TEST_TMPDIR/setup.log"
  {
    echo "[✓] Foreign config written (mimics: ssh,tls)."
    echo "Paste THIS pairing token into the hub — it already carries the exit IP, every"
    echo "port, and the persona, so the hub needs no --target-ip/--persona/--mimics:"
    echo "$TOK1"
    echo "(Raw auth key, for advanced/legacy setups only: aabbccddeeff00112233445566778899)"
  } >"$log"
  run _hed_token_from_output "$log" aabbccddeeff00112233445566778899
  [ "$status" -eq 0 ]
  [ "$output" = "$TOK1" ]
  run _hed_token_from_output "$log" 00000000000000000000000000000000
  [ "$status" -eq 1 ]
}

# ---- persona (port of internal/persona) -------------------------------------
@test "auto persona matches hedioum for several seeds" {
  [ "$(_hed_persona_auto aabbccddeeff00112233445566778899)" = cpanel ]
  [ "$(_hed_persona_auto 0189e772bfe63d815f026b8f76d292ea)" = directadmin ]
  [ "$(_hed_persona_auto 00000000000000000000000000000000)" = directadmin ]
  [ "$(_hed_persona_auto ffffffffffffffffffffffffffffffff)" = devops ]
  [ "$(_hed_persona_auto 1234567890abcdef1234567890abcdef)" = cpanel ]
}

@test "persona resolve matches hedioum's seeded mimic sets" {
  [ "$(_hed_persona_resolve cpanel aabbccddeeff00112233445566778899)" = "ssh,tls,cpanel,whm,webmail,smtp,mysql,smtps,docker,imaps" ]
  [ "$(_hed_persona_resolve directadmin 0189e772bfe63d815f026b8f76d292ea)" = "ssh,tls,directadmin,postgres,https-alt,smtps,grafana,docker,imap,mysql" ]
  [ "$(_hed_persona_resolve devops ffffffffffffffffffffffffffffffff)" = "ssh,tls,https-alt,docker,grafana,prometheus,smtps,imap,imaps,mysql" ]
  [ "$(_hed_persona_resolve cpanel 1234567890abcdef1234567890abcdef)" = "ssh,tls,cpanel,whm,webmail,docker,https-alt,postgres,smtps,smtp" ]
  run _hed_persona_resolve nope aabbccddeeff00112233445566778899
  [ "$status" -ne 0 ]
}

@test "custom mimic lists: all / dedupe / unknown" {
  run _hed_expand_mimics all
  [ "$output" = "ssh,tls,https-alt,smtp,imap,smtps,imaps,directadmin,docker,grafana,prometheus,cpanel,whm,webmail,postgres,mysql" ]
  run _hed_expand_mimics 'ssh, tls,ssh'
  [ "$output" = "ssh,tls" ]
  run _hed_expand_mimics 'ssh,bogus'
  [ "$status" -eq 1 ]
  [[ "$output" == 'unknown mimic "bogus"'* ]]
}

@test "mimic -> default port / setup-foreign flag / state key" {
  [ "$(_hed_mimic_default_port tls)" = 443 ]
  [ "$(_hed_mimic_default_port https-alt)" = 8443 ]
  [ "$(_hed_mimic_port_flag ssh)" = --listen-port ]
  [ "$(_hed_mimic_port_flag https-alt)" = --https-alt-port ]
  [ "$(_hed_port_key https-alt)" = port_https_alt ]
}

# ---- hedioum.json readers (fixtures = real MarshalIndent output) ------------
@test "foreign config: role, scalars, mimics, sni" {
  local f="$FX/hedioum-foreign.json"
  [ "$(_hed_cfg_role "$f")" = foreign ]
  [ "$(_hed_cfg_get auth_token "$f")" = aabbccddeeff00112233445566778899 ]
  [ "$(_hed_cfg_get http_decoy_port "$f")" = -1 ]
  [ "$(_hed_cfg_sni "$f")" = vpn.example.com ]
  run _hed_cfg_mimics "$f"
  [ "${lines[0]}" = "ssh 22" ]
  [ "${lines[1]}" = "tls 443" ]
  [ "${#lines[@]}" -eq 10 ]
}

@test "token built from the foreign config equals hedioum's" {
  run _hed_token_build 9.9.9.9 "$FX/hedioum-foreign.json"
  [ "$output" = "$TOKF" ]
}

@test "iran hub config: nodes listed, no token built" {
  local f="$FX/hedioum-iran.json"
  [ "$(_hed_cfg_role "$f")" = iran ]
  [ "$(_hed_cfg_node_count "$f")" -eq 2 ]
  _hed_cfg_has_node DE-01 "$f"
  ! _hed_cfg_has_node hed "$f"
  run _hed_token_build 9.9.9.9 "$f"
  [ "$status" -ne 0 ]
}

@test "a pasted hedioum token routes to the iran side; other text does not" {
  run t_hedioum_accepts_token "$TOK1"
  [ "$output" = iran ]
  run t_hedioum_accepts_token 0189e772bfe63d815f026b8f76d292ea
  [ "$output" = iran ]
  run t_hedioum_accepts_token 'mili1:abc'
  [ "$status" -ne 0 ]
}

@test "hedioum is a native-pairing tunnel" {
  [ "$(t_meta_field hedioum pairing)" = native ]
}
