# Security Policy

## Reporting

Report vulnerabilities privately via GitHub **Security → Advisories → New draft advisory**, or email the maintainer. Do not open public issues for exploitable VPN / Tor / DNS leaks.

## Scope

- Unintended traffic outside Tor while Connected (clearnet / cellular / CGNAT)
- Kill-switch bypass in Blocking state
- DNS bypass of DNSCrypt / TunDnsMux path
- Credential or keystore exposure in CI or repo

**Not in scope as “leaks” (product features):** firewall **Via LAN** (RFC1918 on a bound Wi‑Fi/Ethernet `Network` only) and **Via OVPN** (encapsulated over Tor). Mis-routing those planes (e.g. LAN over cellular, OVPN to RFC1918) *is* in scope.

## CVE tracking

Known public CVEs mapped to pins and mitigations: [docs/CVE_INVENTORY.md](docs/CVE_INVENTORY.md).

## OpenVPN over Tor

Optional feature. When enabled, OnionVPN may load a GPL OpenVPN binary (`libovpnexec.so`).
Redistribution of that binary is subject to the OpenVPN / ics-openvpn GPL licence.
Device DNS remains DNSCrypt-over-Tor even for firewall “Via OVPN” flows.

## CI signing

Release keystores are provided only via GitHub Actions secrets (`RELEASE_KEYSTORE_*`). Never commit `keystore.properties` or `.jks` files.
