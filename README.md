# mili

**Unified anti-DPI tunnel manager for Iran ⇄ Foreign servers.** One script, one
menu, many tunnels side by side — zero port conflicts, and fully friendly with
the 3x-ui (MHSanaei) panel whether mili is installed before or after it.

![ci](https://github.com/yaldoughie/mili/actions/workflows/ci.yml/badge.svg)
![platform](https://img.shields.io/badge/Ubuntu-22.04%20%7C%2024.04-E95420?logo=ubuntu&logoColor=white)
![platform](https://img.shields.io/badge/Debian-11%20%7C%2012-A81D33?logo=debian&logoColor=white)
![license](https://img.shields.io/badge/license-MIT-blue)

## Install in one line

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/yaldoughie/mili/main/install.sh)
```

Then open the menu any time with:

```bash
mili
```

That is the whole flow: the one-liner installs the `mili` command system-wide;
every time after, just type `mili`. Run the **same command on both** the Iran
and foreign servers — the wizard asks each one its role and hands you a pairing
code to paste on the other side.

> Status: **v0.1 (pass 1)** — framework + priority tunnels **GRE, GRE+FRP, FRP,
> Backhaul, paqet, Hedioum**. Extras (rathole, WireGuard/AmneziaWG, Hysteria2,
> TUIC v5, gost v3) land in pass 2 as drop-in modules.

---

## Why mili

- **Same script on both sides.** Iran and foreign servers run the identical
  `mili`; the wizard asks each server its role and generates a **pairing code**
  you paste on the other side. No SSH credentials ever leave a machine.
- **SOCKS-first.** Every tunnel can expose a SOCKS5 endpoint you drop straight
  into an x-ui **outbound** (copy-ready JSON + numbered steps). Port-forward and
  full L3 exit modes are available too.
- **No port conflicts, ever.** A single port authority checks live sockets,
  mili's own registry, **x-ui inbounds/panel ports**, sshd and a reserved list
  (22, 53, 80 for ACME, 443, 2053, 2096, …) before claiming anything, and
  reserves its ports from the kernel ephemeral range.
- **x-ui is never touched.** mili only *reads* x-ui state. It never writes the
  x-ui DB/API, never flushes iptables, never edits `/etc/sysctl.conf`, never
  uses port 80, and never installs `iptables-persistent`.
- **Premium-ready.** A feature registry tags every action free/premium; v1 is
  all-free, flipping one to premium later is a one-line change.

---

## Requirements & compatibility

- **Ubuntu 22.04 and 24.04** (primary targets, CI-tested) and 20.04; Debian
  11/12. amd64 / arm64 / armv7.
- Run as **root** (`sudo -i` first, or prefix with `sudo`).
- On Ubuntu 24.04 the default `iptables-nft` backend is used transparently — no
  extra setup. mili never installs `iptables-persistent`.

### Update / uninstall

```bash
mili update       # or re-run the install one-liner
mili uninstall    # removes every mili trace; 3x-ui is left untouched
```

Offline / air-gapped: copy `dist/mili.sh` to `/usr/local/bin/mili`, `chmod +x`,
run `mili`. Core binaries move with `mili cores bundle` /
`Cores → Import offline bundle`, or pull peer-to-peer.

---

## Tunnels (pass 1)

| Tunnel | Transport | Server listens | Best for |
|---|---|---|---|
| **GRE** | kernel GRE / GRE-in-UDP (FOU) / ip6gre | symmetric | lowest overhead L3; FOU evades proto-47 blocks |
| **GRE+FRP** | FRP *inside* a private GRE | Iran (inner IP) | stealth: only GRE/FOU is visible, no public FRP port |
| **FRP** | fatedier/frp reverse | Iran (public) | simple reverse tunnel over the open net |
| **Backhaul** | tcp/mux/ws/wss/udp (own values) | Iran | high-throughput muxed reverse tunnel |
| **paqet** | raw pcap packets + KCP (own values) | Foreign | aggressive anti-DPI, TCP-flag cycling |
| **Hedioum** | mimic pool SOCKS (native token) | Foreign egress | persona/mimic traffic shaping |

All tunnels coexist. Any tunnel may layer over another's inner IP (that is how
GRE+FRP works, and e.g. Backhaul-over-GRE). Hedioum and paqet don't layer (they
need a real NIC / fixed ports).

### Usage modes (chosen per tunnel in the wizard)

1. **SOCKS outbound** *(recommended)* — Iran exposes a SOCKS5 endpoint
   (`127.0.0.1:<port>` or a tunnel inner IP). Add it to x-ui as an outbound.
2. **Port forward** — Iran public ports/ranges forward to a foreign target
   (e.g. a foreign x-ui inbound) with optional `local=remote` remapping.
3. **L3 exit** (GRE / later WG) — foreign MASQUERADEs an inner subnet; Iran
   policy-routes selected traffic out through it.

---

## Using a tunnel with 3x-ui

Open **Manage tunnels → <name> → 3x-ui JSON helper**. mili prints a copy-ready
outbound and routing rule, plus your detected inbound tags:

```json
{
  "tag": "mili-mytunnel",
  "protocol": "socks",
  "settings": { "servers": [ { "address": "127.0.0.1", "port": 10810,
    "users": [ { "user": "mili", "pass": "…" } ] } ] }
}
```

Panel → **Xray Configs → Outbounds → +  → JSON** (paste), then add a routing
rule steering your inbound tag(s) to `mili-mytunnel` **before** the
`geoip:private → blocked` rule → Save → Restart Xray. The tunnel's **Test**
action runs `curl --socks5-hostname …` and shows the exit IP.

---

## Menu

Full-screen, **arrow-key driven** (↑/↓ to move the pointer, **Enter** to select,
**q** to go back/quit — digit keys jump too). The header is instant: tunnel
counts come from stored state and the public IP is fetched once and cached.

```
★ New tunnel           Network optimizer
  Import pairing code   Diagnostics (doctor)
  Manage tunnels        Backup & restore
  3x-ui helper          Settings
  Ports & conflicts     Edition / License
  Cores (binaries)      Update · Uninstall · Exit
```

**Pairing model.** Each tunnel is set up the way its own core's installer does
it — same questions, same order, every one with an Enter default. Set up the
side that **listens** first; it shows exactly what to use on the other server.

- **Backhaul** (Musixal installer flow) → *New tunnel → Backhaul → Iran*
  (tunnel port, transport, token, … then SOCKS or port-forward). Iran shows four
  values — **Iran IP, tunnel port, transport, token** (+ the SOCKS port) — type
  them on Foreign: *New tunnel → Backhaul → Foreign*. SOCKS mode needs no
  password: both ends of the SOCKS hop are loopback-only.
- **paqet** (paqet-tunnel deploy-script flow, paqet's own YAML) → *New tunnel →
  paqet → Foreign* (port, connections, KCP mode, MTU; key generated, network
  auto-detected). Foreign shows **IP, port, key** → type them on Iran: *New
  tunnel → paqet → Iran* → SOCKS5 for 3x-ui (or port forwarding). mili then
  checks the exit IP through the tunnel.
- **FRP** → set up on **Iran** (it listens) → one mili code → paste on Foreign.
- **Hedioum** uses **its own pairing token**, not a mili code. mili asks the
  same questions as hedioum's own wizard (Enter accepts every default):
  **Foreign** → *New tunnel → Hedioum → Foreign* → mili runs
  `hedioum-tunnel setup-foreign` and shows hedioum's token (+ QR).
  **Iran** → *New tunnel → Hedioum → Iran* (or just paste the token into
  *Import pairing code*) → mili runs `hedioum-tunnel add-node` with the tunnel
  name as the node alias. Several foreign servers can share one Iran hub, and a
  token from a plain hedioum install works too. Start/Stop/Delete on Iran only
  touch that node; Delete on Foreign restores OpenSSH to its original port if
  hedioum moved it.
- **GRE / GRE+FRP** need *both* public IPs, so they use a two-step handshake:
  set up on **Iran** → code → paste on **Foreign** → Foreign prints a **reply
  code** → paste that back on Iran (*Import pairing code*). Link comes up. Still
  zero manual IP entry — each side auto-detects its own address.

### ECH (Encrypted Client Hello)

Some networks now drop TLS ClientHellos that carry the ECH extension, which
shows up as **TLS handshake timeouts**. mili itself never turns ECH on. Which
tunnels send it:

| Tunnel | Iran → foreign TLS | ECH extension |
|---|---|---|
| Hedioum: every mimic **except `ssh`** (tls, https-alt, cpanel, whm, webmail, directadmin, docker, grafana, prometheus, smtps, imaps, smtp, imap, postgres, mysql) | uTLS Chrome ClientHello, built into the hedioum binary | **yes** (GREASE ECH, no hedioum flag to turn it off) |
| Hedioum `ssh` mimic | no TLS | no |
| Backhaul wss / wssmux | Go standard `crypto/tls` | no |
| FRP / GRE+FRP with TLS | Go standard `crypto/tls` | no |
| Backhaul tcp/tcpmux/ws/udp, paqet, GRE | no TLS | no |

**ECH-free mode (Hedioum, Iran side):** the Iran wizard asks *All mimics* or
*ECH-free*. ECH-free dials only the foreign's SSH mimic (no TLS, no ECH),
using hedioum's own `add-node --target-ip … --mimics ssh --ssh-port …`.
To switch an existing node: *Manage → node → Edit* and pick *ECH-free* (pick
*All mimics* to go back; the foreign server is unchanged either way). This only
works when the foreign's persona includes the SSH mimic, which every built-in
persona does. *Test* prints a hint when TLS mimics fail in the handshake while
SSH still works.

CLI mirror:

```
mili status | up <n> | down <n> | restart <n> | logs <n>
mili import <code> | export <n> | ports | doctor
mili cores install <core> | cores bundle | update | uninstall | version
```

---

## Safety guarantees (x-ui coexistence)

- Reads `/etc/x-ui/x-ui.db` (sqlite, read-only) and `x-ui setting -show` only.
- Own iptables chains (`MILI-IN`, `MILI-PRE/POST`, `MILI-MSS`, `MILI-RAW`,
  `MILI-OUT`), every rule tagged `mili:<name>`; `mili uninstall` removes them all.
- sysctl only under `/etc/sysctl.d/90-mili*.conf` (x-ui's `99-bbr` still wins);
  qdisc only ever `fq`.
- ufw/firewalld allows are mirrored so enabling ufw later won't cut tunnels.
- A boot-time `mili-fw.service` rebuilds chains; a 60s watchdog restarts failed
  tunnels (via `systemctl restart`, never `pkill`) and re-audits ports.

---

## Build from source

```bash
./build.sh            # -> dist/mili.sh (bash -n + shellcheck + sha256)
```

Source layout: `src/lib/*.sh` (framework) + `src/tunnels/*.sh` (one module per
tunnel) + `src/main.sh` (menu/CLI). `build.sh` concatenates them into the single
`dist/mili.sh`. Every system-changing command goes through a `run` wrapper, so
`MILI_DRYRUN=1` previews actions without executing them.

---

## Roadmap

- **pass 2 tunnels:** rathole, WireGuard/AmneziaWG, Hysteria2, TUIC v5, gost v3.
- cores peer serve/pull polish, failover paths, richer diagnostics.
- premium tier (reserved features + licensing) — hooks already in place.
