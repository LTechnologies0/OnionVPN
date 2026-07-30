# OnionVPN Anti-Leak Checklist

Evidence-backed atomic controls (≥200). Status Pass only with matching automated test or verified code invariant.
Generated from source enumeration — do not invent IDs without evidence paths.

| ID | Layer | Evidence | Expected | Test | Status |
|----|-------|----------|----------|------|--------|
| AL-001 | torrc | `TorConfigWriter.kt` | torrc contains: DataDirectory $dataDirectory | AntiLeakTorrcTest | Pass |
| AL-002 | torrc | `TorConfigWriter.kt` | torrc contains: ClientOnly 1 | AntiLeakTorrcTest | Pass |
| AL-003 | torrc | `TorConfigWriter.kt` | torrc contains: AvoidDiskWrites 1 | AntiLeakTorrcTest | Pass |
| AL-004 | torrc | `TorConfigWriter.kt` | torrc contains: DormantCanceledByStartup 1 | AntiLeakTorrcTest | Pass |
| AL-005 | torrc | `TorConfigWriter.kt` | torrc contains: DormantClientTimeout 30 minutes | AntiLeakTorrcTest | Pass |
| AL-006 | torrc | `TorConfigWriter.kt` | torrc contains: SafeLogging 1 | AntiLeakTorrcTest | Pass |
| AL-007 | torrc | `TorConfigWriter.kt` | torrc contains: Log notice stderr | AntiLeakTorrcTest | Pass |
| AL-008 | torrc | `TorConfigWriter.kt` | torrc contains: SocksPolicy accept 127.0.0.1 | AntiLeakTorrcTest | Pass |
| AL-009 | torrc | `TorConfigWriter.kt` | torrc contains: SocksPolicy reject * | AntiLeakTorrcTest | Pass |
| AL-010 | torrc | `TorConfigWriter.kt` | torrc contains: AutomapHostsOnResolve 1 | AntiLeakTorrcTest | Pass |
| AL-011 | torrc | `TorConfigWriter.kt` | torrc contains: AutomapHostsSuffixes .onion,.exit | AntiLeakTorrcTest | Pass |
| AL-012 | torrc | `TorConfigWriter.kt` | torrc contains: SafeSocks 0 | AntiLeakTorrcTest | Pass |
| AL-013 | torrc | `TorConfigWriter.kt` | torrc contains: TestSocks 0 | AntiLeakTorrcTest | Pass |
| AL-014 | torrc | `TorConfigWriter.kt` | torrc contains: VirtualAddrNetwork 10.192.0.0/10 | AntiLeakTorrcTest | Pass |
| AL-015 | torrc | `TorConfigWriter.kt` | torrc contains: TransPort 0 | AntiLeakTorrcTest | Pass |
| AL-016 | torrc | `TorConfigWriter.kt` | torrc contains: HTTPTunnelPort 0 | AntiLeakTorrcTest | Pass |
| AL-017 | torrc | `TorConfigWriter.kt` | torrc contains: ControlPort 0 | AntiLeakTorrcTest | Pass |
| AL-018 | torrc | `TorConfigWriter.kt` | torrc contains: CookieAuthentication 1 | AntiLeakTorrcTest | Pass |
| AL-019 | torrc | `TorConfigWriter.kt` | torrc contains: CookieAuthFile ${File(dataDirectory, COOKIE_FILE_NAME).absolutePath} | AntiLeakTorrcTest | Pass |
| AL-020 | torrc | `TorConfigWriter.kt` | torrc contains: ControlSocket ${File(dataDirectory, CONTROL_SOCKET_NAME).absolutePath} | AntiLeakTorrcTest | Pass |
| AL-021 | torrc | `TorConfigWriter.kt` | torrc contains: GeoIPFile ${geoIp.absolutePath} | AntiLeakTorrcTest | Pass |
| AL-022 | torrc | `TorConfigWriter.kt` | torrc contains: GeoIPv6File ${geoIp6.absolutePath} | AntiLeakTorrcTest | Pass |
| AL-023 | torrc | `TorConfigWriter.kt` | torrc contains: ClientRejectInternalAddresses 1 | AntiLeakTorrcTest | Pass |
| AL-024 | torrc | `TorConfigWriter.kt` | torrc contains: AllowNonRFC953Hostnames 0 | AntiLeakTorrcTest | Pass |
| AL-025 | torrc | `TorConfigWriter.kt` | torrc contains: RefuseUnknownExits 1 | AntiLeakTorrcTest | Pass |
| AL-026 | torrc | `TorConfigWriter.kt` | torrc contains: FetchUselessDescriptors 0 | AntiLeakTorrcTest | Pass |
| AL-027 | torrc | `TorConfigWriter.kt` | torrc contains: DownloadExtraInfo 0 | AntiLeakTorrcTest | Pass |
| AL-028 | torrc | `TorConfigWriter.kt` | torrc contains: ClientPreferIPv6ORPort 0 | AntiLeakTorrcTest | Pass |
| AL-029 | torrc | `TorConfigWriter.kt` | torrc contains: HardwareAccel 1 | AntiLeakTorrcTest | Pass |
| AL-030 | torrc | `TorConfigWriter.kt` | torrc contains: VanguardsLiteEnabled 1 | AntiLeakTorrcTest | Pass |
| AL-031 | torrc | `TorConfigWriter.kt` | torrc contains: ConfluxEnabled auto | AntiLeakTorrcTest | Pass |
| AL-032 | torrc | `TorConfigWriter.kt` | torrc contains: UseMicrodescriptors 1 | AntiLeakTorrcTest | Pass |
| AL-033 | torrc | `TorConfigWriter.kt` | torrc contains: UseEntryGuards 1 | AntiLeakTorrcTest | Pass |
| AL-034 | torrc | `TorConfigWriter.kt` | torrc contains: NumEntryGuards 2 | AntiLeakTorrcTest | Pass |
| AL-035 | torrc | `TorConfigWriter.kt` | torrc contains: NumPrimaryGuards 2 | AntiLeakTorrcTest | Pass |
| AL-036 | torrc | `TorConfigWriter.kt` | torrc contains: NumDirectoryGuards 3 | AntiLeakTorrcTest | Pass |
| AL-037 | torrc | `TorConfigWriter.kt` | torrc contains: EnforceDistinctSubnets 1 | AntiLeakTorrcTest | Pass |
| AL-038 | torrc | `TorConfigWriter.kt` | torrc contains: StrictNodes 0 | AntiLeakTorrcTest | Pass |
| AL-039 | torrc | `TorConfigWriter.kt` | torrc contains: MaxClientCircuitsPending 48 | AntiLeakTorrcTest | Pass |
| AL-040 | torrc | `TorConfigWriter.kt` | torrc contains: CircuitBuildTimeout 60 | AntiLeakTorrcTest | Pass |
| AL-041 | torrc | `TorConfigWriter.kt` | torrc contains: LearnCircuitBuildTimeout 1 | AntiLeakTorrcTest | Pass |
| AL-042 | torrc | `TorConfigWriter.kt` | torrc contains: SocksTimeout 120 | AntiLeakTorrcTest | Pass |
| AL-043 | torrc | `TorConfigWriter.kt` | torrc contains: CircuitStreamTimeout 0 | AntiLeakTorrcTest | Pass |
| AL-044 | torrc | `TorConfigWriter.kt` | torrc contains: ConnectionPadding auto | AntiLeakTorrcTest | Pass |
| AL-045 | torrc | `TorConfigWriter.kt` | torrc contains: ReducedConnectionPadding 0 | AntiLeakTorrcTest | Pass |
| AL-046 | torrc | `TorConfigWriter.kt` | torrc contains: CircuitPadding 1 | AntiLeakTorrcTest | Pass |
| AL-047 | torrc | `TorConfigWriter.kt` | torrc contains: ReducedCircuitPadding 0 | AntiLeakTorrcTest | Pass |
| AL-048 | torrc | `TorConfigWriter.kt` | torrc contains: WarnPlaintextPorts 23,109,110,143 | AntiLeakTorrcTest | Pass |
| AL-049 | torrc | `TorConfigWriter.kt` | torrc contains: RejectPlaintextPorts 23,109 | AntiLeakTorrcTest | Pass |
| AL-050 | torrc | `TorConfigWriter.kt` | torrc contains: NewCircuitPeriod ${preferences.torNewCircuitPeriodSec} | AntiLeakTorrcTest | Pass |
| AL-051 | torrc | `TorConfigWriter.kt` | torrc contains: MaxCircuitDirtiness ${preferences.torMaxCircuitDirtinessSec} | AntiLeakTorrcTest | Pass |
| AL-052 | torrc | `TorConfigWriter.kt` | torrc contains: UseBridges 1 | AntiLeakTorrcTest | Pass |
| AL-053 | torrc | `TorConfigWriter.kt` | torrc contains: Bridge $line | AntiLeakTorrcTest | Pass |
| AL-054 | torrc | `TorConfigWriter.kt` | torrc contains: EntryNodes $it | AntiLeakTorrcTest | Pass |
| AL-055 | torrc | `TorConfigWriter.kt` | torrc contains: StrictNodes 1 | AntiLeakTorrcTest | Pass |
| AL-056 | torrc | `TorConfigWriter.kt` | torrc contains: ExitNodes $it | AntiLeakTorrcTest | Pass |
| AL-057 | torrc | `TorConfigWriter.kt` | torrc contains: ExcludeNodes $it | AntiLeakTorrcTest | Pass |
| AL-058 | torrc | `TorConfigWriter.kt` | policy: SOCKSPort.*SESSION_GROUP_APPS.*KeepAliveIsolateSOCKSAuth | AntiLeakTorrcTest | Pass |
| AL-059 | torrc | `TorConfigWriter.kt` | policy: SOCKSPort.*SESSION_GROUP_DNSCRYPT.*KeepAliveIsolateSOCKSAuth | AntiLeakTorrcTest | Pass |
| AL-060 | torrc | `TorConfigWriter.kt` | policy: SOCKSPort.*SESSION_GROUP_PROBE | AntiLeakTorrcTest | Pass |
| AL-061 | torrc | `TorConfigWriter.kt` | policy: DNSPort.*SESSION_GROUP_DNS.*IsolateDestAddr | AntiLeakTorrcTest | Pass |
| AL-062 | torrc | `TorConfigWriter.kt` | policy: IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateSOCKSAuth | AntiLeakTorrcTest | Pass |
| AL-063 | torrc | `TorConfigWriter.kt` | policy: IsolateDestPort | AntiLeakTorrcTest | Pass |
| AL-064 | torrc | `TorConfigWriter.SOCKS_ISOLATION_APPS` | Apps omit IsolateDestPort | TorConfigWriterTest | Pass |
| AL-065 | torrc | `TorConfigWriter.SOCKS_ISOLATION_MAX` | DNSCrypt/probe include IsolateDestPort | TorConfigWriterTest | Pass |
| AL-066 | torrc | `TorConfigWriter HTTPTunnelPort 0` | HTTPTunnelPort disabled | TorConfigWriterTest | Pass |
| AL-067 | torrc | `TorConfigWriter TransPort 0` | TransPort disabled | AntiLeakTorrcTest | Pass |
| AL-068 | dnscrypt | `DnsCryptConfigWriter.kt` | config enforces force_tcp = true | AntiLeakDnsCryptTest | Pass |
| AL-069 | dnscrypt | `DnsCryptConfigWriter.kt` | config enforces ignore_system_dns = true | AntiLeakDnsCryptTest | Pass |
| AL-070 | dnscrypt | `DnsCryptConfigWriter.kt` | config enforces dnscrypt_ephemeral_keys = true | AntiLeakDnsCryptTest | Pass |
| AL-071 | dnscrypt | `DnsCryptConfigWriter.kt` | config enforces tls_disable_session_tickets = true | AntiLeakDnsCryptTest | Pass |
| AL-072 | dnscrypt | `DnsCryptConfigWriter.kt` | config enforces block_ipv6 = true | AntiLeakDnsCryptTest | Pass |
| AL-073 | dnscrypt | `DnsCryptConfigWriter.kt` | config enforces ipv6_servers = false | AntiLeakDnsCryptTest | Pass |
| AL-074 | dnscrypt | `DnsCryptConfigWriter.kt` | config enforces proxy = 'socks5:// | AntiLeakDnsCryptTest | Pass |
| AL-075 | dnscrypt | `DnsCryptConfigWriter.kt` | config enforces bootstrap_resolvers = | AntiLeakDnsCryptTest | Pass |
| AL-076 | dnscrypt | `DnsCryptConfigWriter.kt` | config enforces netprobe_address = | AntiLeakDnsCryptTest | Pass |
| AL-077 | dnscrypt | `DnsCryptConfigWriter.kt` | config enforces listen_addresses = | AntiLeakDnsCryptTest | Pass |
| AL-078 | dnscrypt | `DnsCryptConfigWriter.kt` | config enforces require_dnssec | AntiLeakDnsCryptTest | Pass |
| AL-079 | dnscrypt | `DnsCryptConfigWriter.kt` | config enforces require_nolog | AntiLeakDnsCryptTest | Pass |
| AL-080 | dnscrypt | `DnsCryptConfigWriter.kt` | config enforces require_nofilter | AntiLeakDnsCryptTest | Pass |
| AL-081 | dnscrypt | `DnsCryptConfigWriter.kt` | config enforces cache = true | AntiLeakDnsCryptTest | Pass |
| AL-082 | dnscrypt | `DnsCryptConfigWriter.kt` | config enforces [blocked_names] | AntiLeakDnsCryptTest | Pass |
| AL-083 | dnscrypt | `DnsCryptConfigWriter.kt` | config enforces [sources.'public-resolvers'] | AntiLeakDnsCryptTest | Pass |
| AL-084 | dnscrypt | `DnsCryptConfigWriter.kt` | config enforces minisign_key | AntiLeakDnsCryptTest | Pass |
| AL-085 | dnscrypt | `DnsCryptConfigWriter.kt` | config enforces tls_cipher_suite | AntiLeakDnsCryptTest | Pass |
| AL-086 | dnscrypt | `DnsCryptConfigWriter.kt` | config enforces max_clients = 128 | AntiLeakDnsCryptTest | Pass |
| AL-087 | dnscrypt | `DnsCryptConfigWriter.kt` | config enforces ipv4_servers = true | AntiLeakDnsCryptTest | Pass |
| AL-088 | dnscrypt | `DnsCryptConfigWriter.kt` | config enforces timeout = 15000 | AntiLeakDnsCryptTest | Pass |
| AL-089 | dnscrypt | `DnsCryptConfigWriter.kt` | config enforces keepalive = 30 | AntiLeakDnsCryptTest | Pass |
| AL-090 | dnscrypt | `DnsCryptConfigWriter.kt` | config enforces cert_refresh_delay = 240 | AntiLeakDnsCryptTest | Pass |
| AL-091 | dnscrypt | `DnsCryptConfigWriter.kt` | config enforces cache_neg_max_ttl = 60 | AntiLeakDnsCryptTest | Pass |
| AL-092 | dnscrypt | `DnsCryptConfigWriter.kt` | config enforces SOCKS_DNSCRYPT_USER | AntiLeakDnsCryptTest | Pass |
| AL-093 | dnscrypt-block | `DnsCryptConfigWriter.blockedNamesFileContent` | blocked_names includes dns.google | AntiLeakDnsCryptTest | Pass |
| AL-094 | dnscrypt-block | `DnsCryptConfigWriter.blockedNamesFileContent` | blocked_names includes dns.google.com | AntiLeakDnsCryptTest | Pass |
| AL-095 | dnscrypt-block | `DnsCryptConfigWriter.blockedNamesFileContent` | blocked_names includes dns.cloudflare.com | AntiLeakDnsCryptTest | Pass |
| AL-096 | dnscrypt-block | `DnsCryptConfigWriter.blockedNamesFileContent` | blocked_names includes cloudflare-dns.com | AntiLeakDnsCryptTest | Pass |
| AL-097 | dnscrypt-block | `DnsCryptConfigWriter.blockedNamesFileContent` | blocked_names includes one.one.one.one | AntiLeakDnsCryptTest | Pass |
| AL-098 | dnscrypt-block | `DnsCryptConfigWriter.blockedNamesFileContent` | blocked_names includes mozilla.cloudflare-dns.com | AntiLeakDnsCryptTest | Pass |
| AL-099 | dnscrypt-block | `DnsCryptConfigWriter.blockedNamesFileContent` | blocked_names includes security.cloudflare-dns.com | AntiLeakDnsCryptTest | Pass |
| AL-100 | dnscrypt-block | `DnsCryptConfigWriter.blockedNamesFileContent` | blocked_names includes chrome.cloudflare-dns.com | AntiLeakDnsCryptTest | Pass |
| AL-101 | dnscrypt-block | `DnsCryptConfigWriter.blockedNamesFileContent` | blocked_names includes dns.quad9.net | AntiLeakDnsCryptTest | Pass |
| AL-102 | dnscrypt-block | `DnsCryptConfigWriter.blockedNamesFileContent` | blocked_names includes dns9.quad9.net | AntiLeakDnsCryptTest | Pass |
| AL-103 | dnscrypt-block | `DnsCryptConfigWriter.blockedNamesFileContent` | blocked_names includes dns10.quad9.net | AntiLeakDnsCryptTest | Pass |
| AL-104 | dnscrypt-block | `DnsCryptConfigWriter.blockedNamesFileContent` | blocked_names includes dns11.quad9.net | AntiLeakDnsCryptTest | Pass |
| AL-105 | dnscrypt-block | `DnsCryptConfigWriter.blockedNamesFileContent` | blocked_names includes doh.opendns.com | AntiLeakDnsCryptTest | Pass |
| AL-106 | dnscrypt-block | `DnsCryptConfigWriter.blockedNamesFileContent` | blocked_names includes doh.dns.sb | AntiLeakDnsCryptTest | Pass |
| AL-107 | dnscrypt-block | `DnsCryptConfigWriter.blockedNamesFileContent` | blocked_names includes dns.adguard.com | AntiLeakDnsCryptTest | Pass |
| AL-108 | dnscrypt-block | `DnsCryptConfigWriter.blockedNamesFileContent` | blocked_names includes dns-family.adguard.com | AntiLeakDnsCryptTest | Pass |
| AL-109 | dnscrypt-block | `DnsCryptConfigWriter.blockedNamesFileContent` | blocked_names includes dns.nextdns.io | AntiLeakDnsCryptTest | Pass |
| AL-110 | dnscrypt-block | `DnsCryptConfigWriter.blockedNamesFileContent` | blocked_names includes connectivitycheck.gstatic.com | AntiLeakDnsCryptTest | Pass |
| AL-111 | dnscrypt-block | `DnsCryptConfigWriter.blockedNamesFileContent` | blocked_names includes www.gstatic.com | AntiLeakDnsCryptTest | Pass |
| AL-112 | dnscrypt-block | `DnsCryptConfigWriter.blockedNamesFileContent` | blocked_names includes clients3.google.com | AntiLeakDnsCryptTest | Pass |
| AL-113 | dnscrypt-block | `DnsCryptConfigWriter.blockedNamesFileContent` | blocked_names includes clients1.google.com | AntiLeakDnsCryptTest | Pass |
| AL-114 | dnscrypt-block | `DnsCryptConfigWriter.blockedNamesFileContent` | blocked_names includes captive.apple.com | AntiLeakDnsCryptTest | Pass |
| AL-115 | dnscrypt-block | `DnsCryptConfigWriter.blockedNamesFileContent` | blocked_names includes www.apple.com | AntiLeakDnsCryptTest | Pass |
| AL-116 | dnscrypt-block | `DnsCryptConfigWriter.blockedNamesFileContent` | blocked_names includes www.msftconnecttest.com | AntiLeakDnsCryptTest | Pass |
| AL-117 | dnscrypt-block | `DnsCryptConfigWriter.blockedNamesFileContent` | blocked_names includes msftncsi.com | AntiLeakDnsCryptTest | Pass |
| AL-118 | dnscrypt-block | `DnsCryptConfigWriter.blockedNamesFileContent` | blocked_names includes www.msftncsi.com | AntiLeakDnsCryptTest | Pass |
| AL-119 | dnscrypt-block | `DnsCryptConfigWriter.blockedNamesFileContent` | blocked_names includes detectportal.firefox.com | AntiLeakDnsCryptTest | Pass |
| AL-120 | dnscrypt-block | `DnsCryptConfigWriter.blockedNamesFileContent` | blocked_names includes network-test.debian.org | AntiLeakDnsCryptTest | Pass |
| AL-121 | dnscrypt-block | `DnsCryptConfigWriter.blockedNamesFileContent` | blocked_names includes neverssl.com | AntiLeakDnsCryptTest | Pass |
| AL-122 | dnscrypt-block | `DnsCryptConfigWriter.blockedNamesFileContent` | blocked_names includes connectivitycheck.android.com | AntiLeakDnsCryptTest | Pass |
| AL-123 | dnscrypt-block | `DnsCryptConfigWriter.blockedNamesFileContent` | blocked_names includes android.googleapis.com | AntiLeakDnsCryptTest | Pass |
| AL-124 | dnscrypt-block | `DnsCryptConfigWriter.blockedNamesFileContent` | blocked_names includes play.googleapis.com | AntiLeakDnsCryptTest | Pass |
| AL-125 | vpn-dns-pin | `VpnProfileBuilder.BLOCKED_PUBLIC_DNS` | route pin 8.8.8.8 | AntiLeakVpnProfileTest | Pass |
| AL-126 | vpn-dns-pin | `VpnProfileBuilder.BLOCKED_PUBLIC_DNS` | route pin 8.8.4.4 | AntiLeakVpnProfileTest | Pass |
| AL-127 | vpn-dns-pin | `VpnProfileBuilder.BLOCKED_PUBLIC_DNS` | route pin 2001:4860:4860::8888 | AntiLeakVpnProfileTest | Pass |
| AL-128 | vpn-dns-pin | `VpnProfileBuilder.BLOCKED_PUBLIC_DNS` | route pin 2001:4860:4860::8844 | AntiLeakVpnProfileTest | Pass |
| AL-129 | vpn-dns-pin | `VpnProfileBuilder.BLOCKED_PUBLIC_DNS` | route pin 1.1.1.1 | AntiLeakVpnProfileTest | Pass |
| AL-130 | vpn-dns-pin | `VpnProfileBuilder.BLOCKED_PUBLIC_DNS` | route pin 1.0.0.1 | AntiLeakVpnProfileTest | Pass |
| AL-131 | vpn-dns-pin | `VpnProfileBuilder.BLOCKED_PUBLIC_DNS` | route pin 1.1.1.2 | AntiLeakVpnProfileTest | Pass |
| AL-132 | vpn-dns-pin | `VpnProfileBuilder.BLOCKED_PUBLIC_DNS` | route pin 1.0.0.2 | AntiLeakVpnProfileTest | Pass |
| AL-133 | vpn-dns-pin | `VpnProfileBuilder.BLOCKED_PUBLIC_DNS` | route pin 1.1.1.3 | AntiLeakVpnProfileTest | Pass |
| AL-134 | vpn-dns-pin | `VpnProfileBuilder.BLOCKED_PUBLIC_DNS` | route pin 1.0.0.3 | AntiLeakVpnProfileTest | Pass |
| AL-135 | vpn-dns-pin | `VpnProfileBuilder.BLOCKED_PUBLIC_DNS` | route pin 2606:4700:4700::1111 | AntiLeakVpnProfileTest | Pass |
| AL-136 | vpn-dns-pin | `VpnProfileBuilder.BLOCKED_PUBLIC_DNS` | route pin 2606:4700:4700::1001 | AntiLeakVpnProfileTest | Pass |
| AL-137 | vpn-dns-pin | `VpnProfileBuilder.BLOCKED_PUBLIC_DNS` | route pin 2606:4700:4700::1112 | AntiLeakVpnProfileTest | Pass |
| AL-138 | vpn-dns-pin | `VpnProfileBuilder.BLOCKED_PUBLIC_DNS` | route pin 2606:4700:4700::1002 | AntiLeakVpnProfileTest | Pass |
| AL-139 | vpn-dns-pin | `VpnProfileBuilder.BLOCKED_PUBLIC_DNS` | route pin 9.9.9.9 | AntiLeakVpnProfileTest | Pass |
| AL-140 | vpn-dns-pin | `VpnProfileBuilder.BLOCKED_PUBLIC_DNS` | route pin 149.112.112.112 | AntiLeakVpnProfileTest | Pass |
| AL-141 | vpn-dns-pin | `VpnProfileBuilder.BLOCKED_PUBLIC_DNS` | route pin 9.9.9.10 | AntiLeakVpnProfileTest | Pass |
| AL-142 | vpn-dns-pin | `VpnProfileBuilder.BLOCKED_PUBLIC_DNS` | route pin 149.112.112.10 | AntiLeakVpnProfileTest | Pass |
| AL-143 | vpn-dns-pin | `VpnProfileBuilder.BLOCKED_PUBLIC_DNS` | route pin 2620:fe::fe | AntiLeakVpnProfileTest | Pass |
| AL-144 | vpn-dns-pin | `VpnProfileBuilder.BLOCKED_PUBLIC_DNS` | route pin 2620:fe::9 | AntiLeakVpnProfileTest | Pass |
| AL-145 | vpn-dns-pin | `VpnProfileBuilder.BLOCKED_PUBLIC_DNS` | route pin 94.140.14.14 | AntiLeakVpnProfileTest | Pass |
| AL-146 | vpn-dns-pin | `VpnProfileBuilder.BLOCKED_PUBLIC_DNS` | route pin 94.140.15.15 | AntiLeakVpnProfileTest | Pass |
| AL-147 | vpn-dns-pin | `VpnProfileBuilder.BLOCKED_PUBLIC_DNS` | route pin 94.140.14.15 | AntiLeakVpnProfileTest | Pass |
| AL-148 | vpn-dns-pin | `VpnProfileBuilder.BLOCKED_PUBLIC_DNS` | route pin 94.140.15.16 | AntiLeakVpnProfileTest | Pass |
| AL-149 | vpn-dns-pin | `VpnProfileBuilder.BLOCKED_PUBLIC_DNS` | route pin 208.67.222.222 | AntiLeakVpnProfileTest | Pass |
| AL-150 | vpn-dns-pin | `VpnProfileBuilder.BLOCKED_PUBLIC_DNS` | route pin 208.67.220.220 | AntiLeakVpnProfileTest | Pass |
| AL-151 | vpn-dns-pin | `VpnProfileBuilder.BLOCKED_PUBLIC_DNS` | route pin 185.228.168.9 | AntiLeakVpnProfileTest | Pass |
| AL-152 | vpn-dns-pin | `VpnProfileBuilder.BLOCKED_PUBLIC_DNS` | route pin 185.228.169.9 | AntiLeakVpnProfileTest | Pass |
| AL-153 | vpn-dns-pin | `VpnProfileBuilder.BLOCKED_PUBLIC_DNS` | route pin 8.26.56.26 | AntiLeakVpnProfileTest | Pass |
| AL-154 | vpn-dns-pin | `VpnProfileBuilder.BLOCKED_PUBLIC_DNS` | route pin 8.20.247.20 | AntiLeakVpnProfileTest | Pass |
| AL-155 | vpn-dns-pin | `VpnProfileBuilder.BLOCKED_PUBLIC_DNS` | route pin 4.2.2.1 | AntiLeakVpnProfileTest | Pass |
| AL-156 | vpn-dns-pin | `VpnProfileBuilder.BLOCKED_PUBLIC_DNS` | route pin 4.2.2.2 | AntiLeakVpnProfileTest | Pass |
| AL-157 | vpn-dns-pin | `VpnProfileBuilder.BLOCKED_PUBLIC_DNS` | route pin 194.242.2.2 | AntiLeakVpnProfileTest | Pass |
| AL-158 | vpn-dns-pin | `VpnProfileBuilder.BLOCKED_PUBLIC_DNS` | route pin 194.242.2.3 | AntiLeakVpnProfileTest | Pass |
| AL-159 | vpn-dns-pin | `VpnProfileBuilder.BLOCKED_PUBLIC_DNS` | route pin 45.90.28.0 | AntiLeakVpnProfileTest | Pass |
| AL-160 | vpn-dns-pin | `VpnProfileBuilder.BLOCKED_PUBLIC_DNS` | route pin 45.90.30.0 | AntiLeakVpnProfileTest | Pass |
| AL-161 | vpn-dns-pin | `VpnProfileBuilder.BLOCKED_PUBLIC_DNS` | route pin 76.76.2.0 | AntiLeakVpnProfileTest | Pass |
| AL-162 | vpn-dns-pin | `VpnProfileBuilder.BLOCKED_PUBLIC_DNS` | route pin 76.76.10.0 | AntiLeakVpnProfileTest | Pass |
| AL-163 | vpn-profile | `VpnProfileBuilder` | never allowBypass | AntiLeakVpnProfileTest | Pass |
| AL-164 | vpn-profile | `VpnProfileBuilder` | full tunnel 0.0.0.0/0 | AntiLeakVpnProfileTest | Pass |
| AL-165 | vpn-profile | `VpnProfileBuilder` | full tunnel ::/0 | AntiLeakVpnProfileTest | Pass |
| AL-166 | vpn-profile | `VpnProfileBuilder` | self-exclude package | AntiLeakVpnProfileTest | Pass |
| AL-167 | vpn-profile | `VpnProfileBuilder` | allowFamily AF_INET | AntiLeakVpnProfileTest | Pass |
| AL-168 | vpn-profile | `VpnProfileBuilder` | allowFamily AF_INET6 | AntiLeakVpnProfileTest | Pass |
| AL-169 | vpn-profile | `VpnProfileBuilder` | setBlocking only in Blocking+killSwitch | AntiLeakVpnProfileTest | Pass |
| AL-170 | vpn-profile | `VpnProfileBuilder` | Connected DNS = VPN_DNS_ADDRESS | AntiLeakVpnProfileTest | Pass |
| AL-171 | vpn-profile | `VpnProfileBuilder` | Blocking DNS = FALLBACK_BLOCKING_DNS | AntiLeakVpnProfileTest | Pass |
| AL-172 | udp-blackhole | `LeakPacketFilter.BlackholeReason` | classify/blackhole NotUdp | LeakPacketFilterTest | Pass |
| AL-173 | udp-blackhole | `LeakPacketFilter.BlackholeReason` | classify/blackhole Ipv6 | LeakPacketFilterTest | Pass |
| AL-174 | udp-blackhole | `LeakPacketFilter.BlackholeReason` | classify/blackhole Multicast | LeakPacketFilterTest | Pass |
| AL-175 | udp-blackhole | `LeakPacketFilter.BlackholeReason` | classify/blackhole LinkLocal | LeakPacketFilterTest | Pass |
| AL-176 | udp-blackhole | `LeakPacketFilter.BlackholeReason` | classify/blackhole Icmp | LeakPacketFilterTest | Pass |
| AL-177 | udp-blackhole | `LeakPacketFilter.BlackholeReason` | classify/blackhole QuicHttp3 | LeakPacketFilterTest | Pass |
| AL-178 | udp-blackhole | `LeakPacketFilter.BlackholeReason` | classify/blackhole StunWebrtc | LeakPacketFilterTest | Pass |
| AL-179 | udp-blackhole | `LeakPacketFilter.BlackholeReason` | classify/blackhole MdnsLlmnr | LeakPacketFilterTest | Pass |
| AL-180 | udp-blackhole | `LeakPacketFilter.BlackholeReason` | classify/blackhole Ssdp | LeakPacketFilterTest | Pass |
| AL-181 | udp-blackhole | `LeakPacketFilter.BlackholeReason` | classify/blackhole Ntp | LeakPacketFilterTest | Pass |
| AL-182 | udp-blackhole | `LeakPacketFilter.BlackholeReason` | classify/blackhole Dhcp | LeakPacketFilterTest | Pass |
| AL-183 | udp-blackhole | `LeakPacketFilter.BlackholeReason` | classify/blackhole WireGuard | LeakPacketFilterTest | Pass |
| AL-184 | udp-blackhole | `LeakPacketFilter.BlackholeReason` | classify/blackhole OpenVpn | LeakPacketFilterTest | Pass |
| AL-185 | udp-blackhole | `LeakPacketFilter.BlackholeReason` | classify/blackhole Dtls | LeakPacketFilterTest | Pass |
| AL-186 | udp-blackhole | `LeakPacketFilter.BlackholeReason` | classify/blackhole TcpDns | LeakPacketFilterTest | Pass |
| AL-187 | udp-blackhole | `LeakPacketFilter.BlackholeReason` | classify/blackhole GenericUdp | LeakPacketFilterTest | Pass |
| AL-188 | udp-blackhole | `LeakPacketFilter` | UDP/53 DivertDns not blackhole | LeakPacketFilterTest | Pass |
| AL-189 | udp-blackhole | `LeakPacketFilter` | non-DNS UDP blackhole | LeakPacketFilterTest | Pass |
| AL-190 | udp-blackhole | `LeakPacketFilter` | IPv6 early drop | LeakPacketFilterTest | Pass |
| AL-191 | udp-blackhole | `LeakPacketFilter` | TCP/53 and DoT/853 blackhole | LeakPacketFilterTest | Pass |
| AL-192 | udp-blackhole | `LeakPacketFilter` | isTorrifiableIpv4Tcp only TCP | LeakPacketFilterTest | Pass |
| AL-193 | validation | `core/validation/src/main/java/ltechnologies/onionphone/onionvpn/core/validation/TunnelValidator.kt` | check id vpn.not.established defined | TunnelValidator* | Pass |
| AL-194 | validation | `core/validation/src/main/java/ltechnologies/onionphone/onionvpn/core/validation/TunnelValidator.kt` | check id uid.forwarder.wiring defined | TunnelValidator* | Pass |
| AL-195 | validation | `core/validation/src/main/java/ltechnologies/onionphone/onionvpn/core/validation/TunnelValidator.kt` | check id dnscrypt.tor.wiring.missing defined | TunnelValidator* | Pass |
| AL-196 | validation | `core/validation/src/main/java/ltechnologies/onionphone/onionvpn/core/validation/TunnelValidator.kt` | check id dnscrypt.tor.wiring defined | TunnelValidator* | Pass |
| AL-197 | validation | `core/validation/src/main/java/ltechnologies/onionphone/onionvpn/core/validation/TunnelValidator.kt` | check id dnscrypt.config.missing defined | TunnelValidator* | Pass |
| AL-198 | validation | `core/validation/src/main/java/ltechnologies/onionphone/onionvpn/core/validation/TunnelValidator.kt` | check id tor.config.missing defined | TunnelValidator* | Pass |
| AL-199 | validation | `core/validation/src/main/java/ltechnologies/onionphone/onionvpn/core/validation/TunnelValidator.kt` | check id vpn.blocked.dns.routes defined | TunnelValidator* | Pass |
| AL-200 | validation | `core/validation/src/main/java/ltechnologies/onionphone/onionvpn/core/validation/TunnelValidator.kt` | check id dns.mode.dnscrypt defined | TunnelValidator* | Pass |
| AL-201 | validation | `core/validation/src/main/java/ltechnologies/onionphone/onionvpn/core/validation/TunnelValidator.kt` | check id tor.udp.blackhole defined | TunnelValidator* | Pass |
| AL-202 | validation | `core/validation/src/main/java/ltechnologies/onionphone/onionvpn/core/validation/path/DnsCryptPathValidator.kt` | check id dnscrypt.config.runtime defined | TunnelValidator* | Pass |
| AL-203 | validation | `core/validation/src/main/java/ltechnologies/onionphone/onionvpn/core/validation/path/DnsCryptPathValidator.kt` | check id dnscrypt.listener defined | TunnelValidator* | Pass |
| AL-204 | validation | `core/validation/src/main/java/ltechnologies/onionphone/onionvpn/core/validation/path/ExitIpValidator.kt` | check id tor.exit.ip defined | TunnelValidator* | Pass |
| AL-205 | validation | `core/validation/src/main/java/ltechnologies/onionphone/onionvpn/core/validation/path/ExitIpValidator.kt` | check id tor.exit.istor defined | TunnelValidator* | Pass |
| AL-206 | validation | `core/validation/src/main/java/ltechnologies/onionphone/onionvpn/core/validation/path/ExitIpValidator.kt` | check id vpn.address.not.public defined | TunnelValidator* | Pass |
| AL-207 | validation | `core/validation/src/main/java/ltechnologies/onionphone/onionvpn/core/validation/path/TorPathValidator.kt` | check id tor.config.content defined | TunnelValidator* | Pass |
| AL-208 | validation | `core/validation/src/main/java/ltechnologies/onionphone/onionvpn/core/validation/path/TorPathValidator.kt` | check id tor.remote.dns defined | TunnelValidator* | Pass |
| AL-209 | validation | `core/validation/src/main/java/ltechnologies/onionphone/onionvpn/core/validation/android/AndroidVpnInspector.kt` | check id android.connectivity.permission defined | TunnelValidator* | Pass |
| AL-210 | validation | `core/validation/src/main/java/ltechnologies/onionphone/onionvpn/core/validation/android/AndroidVpnInspector.kt` | check id android.connectivity.unavailable defined | TunnelValidator* | Pass |
| AL-211 | validation | `core/validation/src/main/java/ltechnologies/onionphone/onionvpn/core/validation/android/AndroidVpnInspector.kt` | check id android.vpn.underlying defined | TunnelValidator* | Pass |
| AL-212 | validation | `core/validation/src/main/java/ltechnologies/onionphone/onionvpn/core/validation/android/AndroidVpnInspector.kt` | check id android.vpn.default.network defined | TunnelValidator* | Pass |
| AL-213 | validation | `core/validation/src/main/java/ltechnologies/onionphone/onionvpn/core/validation/android/AndroidVpnInspector.kt` | check id android.vpn.competing defined | TunnelValidator* | Pass |
| AL-214 | validation | `core/validation/src/main/java/ltechnologies/onionphone/onionvpn/core/validation/android/AndroidVpnInspector.kt` | check id android.vpn.link.missing defined | TunnelValidator* | Pass |
| AL-215 | validation | `core/validation/src/main/java/ltechnologies/onionphone/onionvpn/core/validation/android/AndroidVpnInspector.kt` | check id android.vpn.route.default defined | TunnelValidator* | Pass |
| AL-216 | validation | `core/validation/src/main/java/ltechnologies/onionphone/onionvpn/core/validation/android/AndroidVpnInspector.kt` | check id android.vpn.route.ipv6 defined | TunnelValidator* | Pass |
| AL-217 | validation | `core/validation/src/main/java/ltechnologies/onionphone/onionvpn/core/validation/android/AndroidVpnInspector.kt` | check id android.vpn.dns.servers defined | TunnelValidator* | Pass |
| AL-218 | validation | `core/validation/src/main/java/ltechnologies/onionphone/onionvpn/core/validation/android/AndroidVpnInspector.kt` | check id android.vpn.address defined | TunnelValidator* | Pass |
| AL-219 | validation | `core/validation/src/main/java/ltechnologies/onionphone/onionvpn/core/validation/android/AndroidVpnInspector.kt` | check id android.vpn.interface defined | TunnelValidator* | Pass |
| AL-220 | validation | `core/validation/src/main/java/ltechnologies/onionphone/onionvpn/core/validation/leak/SystemLeakInspector.kt` | check id android.vpn.always_on defined | TunnelValidator* | Pass |
| AL-221 | validation | `core/validation/src/main/java/ltechnologies/onionphone/onionvpn/core/validation/leak/SystemLeakInspector.kt` | check id android.dns.private defined | TunnelValidator* | Pass |
| AL-222 | validation | `core/validation/src/main/java/ltechnologies/onionphone/onionvpn/core/validation/leak/SystemLeakInspector.kt` | check id android.captive_portal defined | TunnelValidator* | Pass |
| AL-223 | validation | `core/validation/src/main/java/ltechnologies/onionphone/onionvpn/core/validation/leak/SystemLeakInspector.kt` | check id android.http_proxy defined | TunnelValidator* | Pass |
| AL-224 | validation | `core/validation/src/main/java/ltechnologies/onionphone/onionvpn/core/validation/leak/SystemLeakInspector.kt` | check id android.vpn.permission defined | TunnelValidator* | Pass |
| AL-225 | validation | `core/validation/src/main/java/ltechnologies/onionphone/onionvpn/core/validation/leak/SystemLeakInspector.kt` | check id firewall.engine defined | TunnelValidator* | Pass |
| AL-226 | mapped-torsocks | `LeakPacketFilter.blackholeBeforeTorTcp` | deny UDP app traffic | AntiLeakMappedTest | Pass |
| AL-227 | mapped-torsocks | `DnsCrypt force_tcp + Tor SOCKS` | DNS via TCP/proxy not UDP clearnet | AntiLeakMappedTest | Pass |
| AL-228 | mapped-torsocks | `kill-switch Blocking TUN` | fail closed if cannot torify | AntiLeakMappedTest | Pass |
| AL-229 | mapped-path-spec | `TorConfigWriter SOCKS apps` | IsolateSOCKSAuth apps | AntiLeakMappedTest | Pass |
| AL-230 | mapped-path-spec | `TorConfigWriter` | KeepAliveIsolateSOCKSAuth apps | AntiLeakMappedTest | Pass |
| AL-231 | mapped-path-spec | `TorConfigWriter` | KeepAliveIsolateSOCKSAuth DNSCrypt | AntiLeakMappedTest | Pass |
| AL-232 | mapped-path-spec | `TunnelEndpoints.socksUserForUid` | per-app isolation tokens u{uid} | AntiLeakMappedTest | Pass |
| AL-233 | mapped-path-spec | `SESSION_GROUP_APPS` | SessionGroup APPS | AntiLeakMappedTest | Pass |
| AL-234 | mapped-path-spec | `SESSION_GROUP_DNSCRYPT` | SessionGroup DNSCRYPT | AntiLeakMappedTest | Pass |
| AL-235 | mapped-path-spec | `SESSION_GROUP_PROBE` | SessionGroup PROBE | AntiLeakMappedTest | Pass |
| AL-236 | mapped-path-spec | `SESSION_GROUP_DNS` | SessionGroup DNS | AntiLeakMappedTest | Pass |
| AL-237 | mapped-path-spec | `TorConfigWriterTest` | no IsolateDestPort on apps SocksPort | AntiLeakMappedTest | Pass |
| AL-238 | mapped-Whonix | `torDnsCryptSocksPort` | DNSCrypt separate circuit family | AntiLeakMappedTest | Pass |
| AL-239 | mapped-Whonix | `torProbeSocksPort` | probe socks never shares app circuits | AntiLeakMappedTest | Pass |
| AL-240 | mapped-TB | `HTTPTunnelPort 0` | no HTTP CONNECT exit DNS for apps | AntiLeakMappedTest | Pass |
| AL-241 | mapped-TB | `DNSPort AutomapHostsOnResolve` | SOCKS5 remote DNS for onion Automap | AntiLeakMappedTest | Pass |
| AL-242 | mapped-TB | `SocksUidBridge` | stream isolation via SOCKS auth | AntiLeakMappedTest | Pass |
| AL-243 | mapped-PrivacyGuides | `TunnelForegroundService.startTunnel` | kill-switch before bootstrap | AntiLeakMappedTest | Pass |
| AL-244 | mapped-PrivacyGuides | `seamless startConnected` | no clearnet window on rebind | AntiLeakMappedTest | Pass |
| AL-245 | mapped-PrivacyGuides | `SystemLeakInspector` | Always-on + Lockdown advisory | AntiLeakMappedTest | Pass |
| AL-246 | mapped-Android VPN | `UnderlyingNetworkTracker` | setUnderlyingNetworks for Tor egress | AntiLeakMappedTest | Pass |
| AL-247 | mapped-Android VPN | `VpnProfileBuilder.excludeOwnPackage` | addDisallowedApplication self | AntiLeakMappedTest | Pass |
| AL-248 | mapped-Android VPN | `addRoute 0.0.0.0/0` | full tunnel IPv4 | AntiLeakMappedTest | Pass |
| AL-249 | mapped-Android VPN | `addRoute ::/0` | full tunnel IPv6 | AntiLeakMappedTest | Pass |
| AL-250 | mapped-Android VPN | `VpnProfileBuilder docs` | never allowBypass | AntiLeakMappedTest | Pass |
| AL-251 | mapped-DNSCrypt draft | `proxy=socks5 dnscrypt` | encrypted upstream over Tor | AntiLeakMappedTest | Pass |
| AL-252 | mapped-DNSCrypt draft | `ignore_system_dns` | ignore system DNS | AntiLeakMappedTest | Pass |
| AL-253 | mapped-DNSCrypt draft | `dnscrypt_ephemeral_keys` | ephemeral keys | AntiLeakMappedTest | Pass |
| AL-254 | mapped-DNSCrypt draft | `tls_disable_session_tickets` | no TLS tickets | AntiLeakMappedTest | Pass |
| AL-255 | mapped-DNSCrypt draft | `block_ipv6` | block IPv6 resolvers | AntiLeakMappedTest | Pass |
| AL-256 | mapped-DNSCrypt | `bootstrap_resolvers loopback` | bootstrap via Tor DNSPort only | AntiLeakMappedTest | Pass |
| AL-257 | mapped-DNSCrypt | `netprobe_address` | netprobe via Tor DNSPort only | AntiLeakMappedTest | Pass |
| AL-258 | mapped-DNSCrypt | `blocked_names` | block DoH hostnames | AntiLeakMappedTest | Pass |
| AL-259 | mapped-DNSCrypt | `blocked_names` | block captive portal hosts | AntiLeakMappedTest | Pass |
| AL-260 | mapped-OnionVPN | `HevSocks5TunForwarder useMapDns=false` | FakeDNS disabled | AntiLeakMappedTest | Pass |
| AL-261 | mapped-OnionVPN | `divertDns=true` | divert UDP/53 always | AntiLeakMappedTest | Pass |
| AL-262 | mapped-OnionVPN | `TcpFlowUidIndex.peek` | UID peek non-consuming | AntiLeakMappedTest | Pass |
| AL-263 | mapped-OnionVPN | `TunDnsMux.handleDnsQuery` | DNS response ID match | AntiLeakMappedTest | Pass |
| AL-264 | mapped-OnionVPN | `TorProcessManager.downloadGeoIp` | GeoIP never NO_PROXY | AntiLeakMappedTest | Pass |
| AL-265 | mapped-OnionVPN | `Socks5Client` | protect fail-closed off-loopback | AntiLeakMappedTest | Pass |
| AL-266 | mapped-OnionVPN | `InteractiveFirewallEngine` | mid-flow fail-open after SYN gate | AntiLeakMappedTest | Pass |
| AL-267 | socket-hygiene | `TunDnsMux DnsScratch` | DatagramSocket bind 127.0.0.1 | AntiLeakSocketTest | Pass |
| AL-268 | socket-hygiene | `SocksUidBridge` | listen 127.0.0.1 only | AntiLeakSocketTest | Pass |
| AL-269 | socket-hygiene | `SocksPolicy` | accept 127.0.0.1 reject * | AntiLeakSocketTest | Pass |
| AL-270 | socket-hygiene | `Tor SOCKS apps` | LOOPBACK only | AntiLeakSocketTest | Pass |
| AL-271 | socket-hygiene | `PAC listen` | 18201 LOOPBACK | AntiLeakSocketTest | Pass |
| AL-272 | socket-hygiene | `PAC bridge` | 18202 LOOPBACK | AntiLeakSocketTest | Pass |
| AL-273 | socket-hygiene | `UID bridge` | 18203 LOOPBACK | AntiLeakSocketTest | Pass |
| AL-274 | socket-hygiene | `DomainReputation` | Tor probe SOCKS only | AntiLeakSocketTest | Pass |
| AL-275 | socket-hygiene | `ExitIpValidator` | OkHttp via Tor SOCKS | AntiLeakSocketTest | Pass |
| AL-276 | socket-hygiene | `Socks5Client apps` | USERNAME/PASSWORD required | AntiLeakSocketTest | Pass |
| AL-277 | socket-hygiene | `SocksUidBridge` | rewrite Automap via DnsHostnameCache | AntiLeakSocketTest | Pass |
| AL-278 | socket-hygiene | `FirewallBridge` | engine wired at app start | AntiLeakSocketTest | Pass |
| AL-279 | socket-hygiene | `LeakPacketFilter` | never forward clearnet UDP | AntiLeakSocketTest | Pass |
| AL-280 | race-control | `InteractiveFirewallEngine` | SYN without UID fail-closed | AntiLeakRaceTest | Pass |
| AL-281 | race-control | `InteractiveFirewallEngine` | mid-flow invalid UID fail-open | AntiLeakRaceTest | Pass |
| AL-282 | race-control | `InteractiveFirewallEngine` | mid-flow Automap without host fail-open | AntiLeakRaceTest | Pass |
| AL-283 | race-control | `InteractiveFirewallEngine` | mid-flow cache miss fail-open | AntiLeakRaceTest | Pass |
| AL-284 | race-control | `FirewallVerdictCaches` | prefer trim ALLOW keep DENY | AntiLeakRaceTest | Pass |
| AL-285 | race-control | `TcpFlowUidIndex` | peek keeps parallel CONNECT stamps | AntiLeakRaceTest | Pass |
| AL-286 | race-control | `SocksUidBridge` | UID_RETRY race window | AntiLeakRaceTest | Pass |
| AL-287 | race-control | `TunDnsMux` | stampTcpUid before writeHev | AntiLeakRaceTest | Pass |
| AL-288 | race-control | `TunDnsMux` | DNS AbortPolicy recycle on reject | AntiLeakRaceTest | Pass |
| AL-289 | race-control | `TunDnsMux` | DiscardOldest forbidden | AntiLeakRaceTest | Pass |
| AL-290 | race-control | `HevSocks5TunForwarder` | bridge start before hev | AntiLeakRaceTest | Pass |
| AL-291 | race-control | `OnionVpnService` | protectSocket to SocksUidBridge | AntiLeakRaceTest | Pass |
| AL-292 | race-control | `TunnelForegroundService` | Blocking TUN before Tor if kill-switch | AntiLeakRaceTest | Pass |
| AL-293 | race-control | `TunnelForegroundService` | no tear-down before Connected rebind | AntiLeakRaceTest | Pass |
| AL-294 | race-control | `DnsHostnameCache` | Automap remap scoped invalidate | AntiLeakRaceTest | Pass |
| AL-295 | endpoints | `TunnelEndpoints.LOOPBACK` | constant LOOPBACK defined | AntiLeakEndpointsTest | Pass |
| AL-296 | endpoints | `TunnelEndpoints.DEFAULT_TOR_SOCKS_PORT` | constant DEFAULT_TOR_SOCKS_PORT defined | AntiLeakEndpointsTest | Pass |
| AL-297 | endpoints | `TunnelEndpoints.DEFAULT_TOR_DNS_PORT` | constant DEFAULT_TOR_DNS_PORT defined | AntiLeakEndpointsTest | Pass |
| AL-298 | endpoints | `TunnelEndpoints.DEFAULT_DNSCRYPT_LISTEN_PORT` | constant DEFAULT_DNSCRYPT_LISTEN_PORT defined | AntiLeakEndpointsTest | Pass |
| AL-299 | endpoints | `TunnelEndpoints.TOR_SOCKS_PORT` | constant TOR_SOCKS_PORT defined | AntiLeakEndpointsTest | Pass |
| AL-300 | endpoints | `TunnelEndpoints.TOR_DNS_PORT` | constant TOR_DNS_PORT defined | AntiLeakEndpointsTest | Pass |
| AL-301 | endpoints | `TunnelEndpoints.DNSCRYPT_LISTEN_PORT` | constant DNSCRYPT_LISTEN_PORT defined | AntiLeakEndpointsTest | Pass |
| AL-302 | endpoints | `TunnelEndpoints.VPN_CLIENT_ADDRESS` | constant VPN_CLIENT_ADDRESS defined | AntiLeakEndpointsTest | Pass |
| AL-303 | endpoints | `TunnelEndpoints.VPN_DNS_ADDRESS` | constant VPN_DNS_ADDRESS defined | AntiLeakEndpointsTest | Pass |
| AL-304 | endpoints | `TunnelEndpoints.VPN_CLIENT_ADDRESS_V6` | constant VPN_CLIENT_ADDRESS_V6 defined | AntiLeakEndpointsTest | Pass |
| AL-305 | endpoints | `TunnelEndpoints.FAKE_DNS_NETWORK` | constant FAKE_DNS_NETWORK defined | AntiLeakEndpointsTest | Pass |
| AL-306 | endpoints | `TunnelEndpoints.FAKE_DNS_NETMASK` | constant FAKE_DNS_NETMASK defined | AntiLeakEndpointsTest | Pass |
| AL-307 | endpoints | `TunnelEndpoints.FAKE_DNS_CACHE_SIZE` | constant FAKE_DNS_CACHE_SIZE defined | AntiLeakEndpointsTest | Pass |
| AL-308 | endpoints | `TunnelEndpoints.VIRTUAL_ADDR_NETWORK` | constant VIRTUAL_ADDR_NETWORK defined | AntiLeakEndpointsTest | Pass |
| AL-309 | endpoints | `TunnelEndpoints.VIRTUAL_ADDR_PREFIX_LEN` | constant VIRTUAL_ADDR_PREFIX_LEN defined | AntiLeakEndpointsTest | Pass |
| AL-310 | endpoints | `TunnelEndpoints.FALLBACK_BLOCKING_DNS` | constant FALLBACK_BLOCKING_DNS defined | AntiLeakEndpointsTest | Pass |
| AL-311 | endpoints | `TunnelEndpoints.VPN_MTU` | constant VPN_MTU defined | AntiLeakEndpointsTest | Pass |
| AL-312 | endpoints | `TunnelEndpoints.SOCKS_UNKNOWN_USER` | constant SOCKS_UNKNOWN_USER defined | AntiLeakEndpointsTest | Pass |
| AL-313 | endpoints | `TunnelEndpoints.SOCKS_UNKNOWN_PASS` | constant SOCKS_UNKNOWN_PASS defined | AntiLeakEndpointsTest | Pass |
| AL-314 | endpoints | `TunnelEndpoints.SOCKS_ISOLATION_USER` | constant SOCKS_ISOLATION_USER defined | AntiLeakEndpointsTest | Pass |
| AL-315 | endpoints | `TunnelEndpoints.SOCKS_ISOLATION_PASS` | constant SOCKS_ISOLATION_PASS defined | AntiLeakEndpointsTest | Pass |
| AL-316 | endpoints | `TunnelEndpoints.SOCKS_DNSCRYPT_USER` | constant SOCKS_DNSCRYPT_USER defined | AntiLeakEndpointsTest | Pass |
| AL-317 | endpoints | `TunnelEndpoints.SOCKS_DNSCRYPT_PASS` | constant SOCKS_DNSCRYPT_PASS defined | AntiLeakEndpointsTest | Pass |
| AL-318 | endpoints | `TunnelEndpoints.SOCKS_PROBE_USER` | constant SOCKS_PROBE_USER defined | AntiLeakEndpointsTest | Pass |
| AL-319 | endpoints | `TunnelEndpoints.SOCKS_PROBE_PASS` | constant SOCKS_PROBE_PASS defined | AntiLeakEndpointsTest | Pass |
| AL-320 | endpoints | `TunnelEndpoints.SESSION_GROUP_APPS` | constant SESSION_GROUP_APPS defined | AntiLeakEndpointsTest | Pass |
| AL-321 | endpoints | `TunnelEndpoints.SESSION_GROUP_DNS` | constant SESSION_GROUP_DNS defined | AntiLeakEndpointsTest | Pass |
| AL-322 | endpoints | `TunnelEndpoints.SESSION_GROUP_DNSCRYPT` | constant SESSION_GROUP_DNSCRYPT defined | AntiLeakEndpointsTest | Pass |
| AL-323 | endpoints | `TunnelEndpoints.SESSION_GROUP_PROBE` | constant SESSION_GROUP_PROBE defined | AntiLeakEndpointsTest | Pass |
| AL-324 | endpoints | `TunnelEndpoints.PAC_LISTEN_PORT` | constant PAC_LISTEN_PORT defined | AntiLeakEndpointsTest | Pass |
| AL-325 | endpoints | `TunnelEndpoints.PAC_PATH` | constant PAC_PATH defined | AntiLeakEndpointsTest | Pass |
| AL-326 | endpoints | `TunnelEndpoints.PAC_BRIDGE_SOCKS_PORT` | constant PAC_BRIDGE_SOCKS_PORT defined | AntiLeakEndpointsTest | Pass |
| AL-327 | endpoints | `TunnelEndpoints.SOCKS_PAC_USER` | constant SOCKS_PAC_USER defined | AntiLeakEndpointsTest | Pass |
| AL-328 | endpoints | `TunnelEndpoints.SOCKS_PAC_PASS` | constant SOCKS_PAC_PASS defined | AntiLeakEndpointsTest | Pass |
| AL-329 | endpoints | `TunnelEndpoints.SOCKS_UID_BRIDGE_PORT` | constant SOCKS_UID_BRIDGE_PORT defined | AntiLeakEndpointsTest | Pass |
| AL-330 | ports | `TunnelPortAllocator` | distinct torSocksPort | AntiLeakPortsTest | Pass |
| AL-331 | ports | `TunnelPortAllocator` | distinct torDnsCryptSocksPort | AntiLeakPortsTest | Pass |
| AL-332 | ports | `TunnelPortAllocator` | distinct torProbeSocksPort | AntiLeakPortsTest | Pass |
| AL-333 | ports | `TunnelPortAllocator` | distinct torDnsPort | AntiLeakPortsTest | Pass |
| AL-334 | ports | `TunnelPortAllocator` | distinct dnsCryptListenPort | AntiLeakPortsTest | Pass |
| AL-335 | ports | `TunnelPortAllocator` | avoid fixed PAC/UID ports collision | AntiLeakPortsTest | Pass |

**Total: 335** — **Pass: 335** — **Fail: 0** (Pass = automated test and/or verified source invariant).

