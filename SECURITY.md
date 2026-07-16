# Security Policy

## Reporting

Report vulnerabilities privately via GitHub **Security → Advisories → New draft advisory**, or email the maintainer. Do not open public issues for exploitable VPN / Tor / DNS leaks.

## Scope

- Traffic leak outside Tor while Connected
- Kill-switch bypass in Blocking state
- DNS bypass of DNSCrypt / FakeDNS path
- Credential or keystore exposure in CI or repo

## CI signing

Release keystores are provided only via GitHub Actions secrets (`RELEASE_KEYSTORE_*`). Never commit `keystore.properties` or `.jks` files.
