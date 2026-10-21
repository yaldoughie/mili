# mili — 2-VPS end-to-end checklist

Two servers: **iran** (Ubuntu 24.04) and **foreign** (Debian 12). Run the whole
list twice: (A) install mili first then 3x-ui, (B) 3x-ui first then mili.

## Setup
- [ ] `install.sh` on both; `mili version` matches.
- [ ] `mili doctor` on both: GRE + FOU modules load, deps present.

## Per priority tunnel (gre, grefrp, frp, backhaul, paqet, hedioum)
- [ ] Create on foreign/iran as its wizard asks; copy the pairing code to the
      other side (`mili import <code>`).
- [ ] `mili status` shows it **up** on both sides.
- [ ] SOCKS mode: on iran `curl --socks5-hostname 127.0.0.1:<port> https://api.ipify.org`
      returns the **foreign** public IP.
- [ ] Forward mode: a listener on foreign is reachable via the iran public port.
- [ ] 3x-ui helper prints valid outbound JSON; paste into x-ui, route an inbound,
      restart Xray, confirm egress IP = foreign.

## Hedioum (native token flow)
- [ ] Foreign: New tunnel → Hedioum → Foreign, Enter through every question.
      `setup-foreign` exits 0; every mimic port shows "listening"; OpenSSH on
      :2022 and still reachable via :22 (mimic forwards to it).
- [ ] The token mili shows == the token hedioum printed in
      `/var/log/mili/hedioum-<name>.setup.log`.
- [ ] Foreign with x-ui/xray on 443: wizard flags `tls 443 busy (xray)` and
      offers a free port; the token carries that port.
- [ ] Iran: paste the raw token into *Import pairing code* → routes to the Iran
      wizard; `add-node` exits 0; probe shows ✓ per endpoint;
      `curl --socks5-hostname 127.0.0.1:<port> https://api.ipify.org` = foreign IP.
- [ ] Second foreign → second Iran tunnel on the same hub: both nodes in
      `/etc/hedioum/hedioum.json`, both SOCKS ports work.
- [ ] Stop one Iran tunnel → the other keeps working; watchdog doesn't revive it.
- [ ] Foreign Restart while connected through :22 → session drops, service back
      within ~10s, token unchanged.
- [ ] Delete Foreign (SSH was moved) → sshd back on :22, hedioum stopped,
      config backed up under `/etc/mili/backups/`.
- [ ] Adopt: plain `hedioum-tunnel setup-foreign` first, then mili → New →
      Hedioum → Foreign → "Use existing setup" → same token, no restart.

## Backhaul (native values, Musixal installer flow)
- [ ] Iran: New tunnel → Backhaul → Iran, Enter through every question
      (SOCKS mode). Summary + "type these on the FOREIGN server" box shows Iran
      IP, tunnel port, transport, token, SOCKS port.
- [ ] Foreign: New tunnel → Backhaul → Foreign, type those 4 values, Enter the
      rest → "connected to Iran" + "exit SOCKS5 ready".
- [ ] Iran: `curl --socks5-hostname 127.0.0.1:<port> https://api.ipify.org`
      = foreign IP; manage screen shows "foreign: connected".
- [ ] Wrong token on Foreign → stays "not connected"; Iran log says
      `invalid security token`.
- [ ] Forward mode: ports `443-445,8443=2083` → iptables shows `443:445`;
      a foreign service is reachable via Iran :8443.
- [ ] wssmux: self-signed cert created under `/etc/mili/pki/<name>/`.

## paqet (native values, paqet-tunnel deploy-script flow)
- [ ] `mili cores install paqet` downloads `paqet-linux-<arch>-v<ver>.tar.gz`.
- [ ] Foreign: New tunnel → paqet → Foreign, Enter through → `/etc/mili/engines/paqet/<name>.yaml`;
      `iptables -t raw -S MILI-RAW` shows dport+sport NOTRACK;
      `iptables -t raw -S OUTPUT | grep MILI-RAW` present; RST drop in MILI-OUT.
- [ ] Iran: New tunnel → paqet → Iran, type IP / port / key → "config OK ·
      test packet sent", "SOCKS5 ready", "exit IP <foreign>".
- [ ] Wrong key → "no traffic through the tunnel yet" warning, service stays up.
- [ ] Stop the foreign paqet → Iran watchdog probe fails → unit restarted after
      3 checks (see `/var/log/mili/watchdog.log`).

## Coexistence
- [ ] All six tunnels **up simultaneously**; `mili ports` reports no conflict.
- [ ] x-ui panel reachable, inbounds работают, ACME renew on port 80 still works.
- [ ] x-ui menu *23 enable ufw* → tunnels survive (ufw mirrors present).
- [ ] x-ui menu *26 BBR* → no sysctl fight (`sysctl net.ipv4.tcp_congestion_control`).
- [ ] Add an x-ui inbound on a mili port → watchdog + menu header flag the clash.
- [ ] `reboot` → every tunnel + firewall chain comes back (mili-fw + units).

## Teardown
- [ ] `mili uninstall` (everything) → zero leftovers:
  - [ ] `iptables-save | grep -i mili` → empty
  - [ ] `systemctl list-units 'mili*'` → none
  - [ ] `ls /etc/sysctl.d | grep mili` → none
  - [ ] `/etc/mili`, `/opt/mili`, `/usr/local/bin/mili` gone
- [ ] x-ui still fully functional (never touched).
