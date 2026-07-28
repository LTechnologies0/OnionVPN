#!/usr/bin/env python3
"""Refresh bundled public-resolvers.md (+ minisig) and DnsCryptPublicResolvers.kt."""

from __future__ import annotations

import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "core/dnscrypt/src/main/assets"
OUT_KT = ROOT / (
    "core/dnscrypt/src/main/java/ltechnologies/onionphone/onionvpn/"
    "core/dnscrypt/config/DnsCryptPublicResolvers.kt"
)
BASE = "https://download.dnscrypt.info/resolvers-list/v3"
MINISIGN_KEY = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3"


def download(name: str) -> bytes:
    with urllib.request.urlopen(f"{BASE}/{name}", timeout=60) as resp:
        return resp.read()


def parse(text: str) -> list[dict]:
    parts = text.split("\n--\n", 1)
    body = parts[1] if len(parts) > 1 else text
    servers: list[dict] = []
    name = None
    desc_lines: list[str] = []
    stamps: list[str] = []

    def flush() -> None:
        nonlocal name, desc_lines, stamps
        if name and stamps:
            servers.append(
                {
                    "name": name,
                    "description": " ".join(desc_lines).strip(),
                    "stamps": stamps[:],
                    "ipv6": "ipv6" in name.lower() or "-ip6-" in name.lower(),
                }
            )
        name = None
        desc_lines = []
        stamps = []

    for line in body.splitlines():
        if line.startswith("## "):
            flush()
            name = line[3:].strip()
        elif line.startswith("sdns://"):
            stamps.append(line.strip())
        elif name is not None and line.strip() and not line.startswith("#"):
            desc_lines.append(line.strip())
    flush()
    return servers


def esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def main() -> None:
    ASSETS.mkdir(parents=True, exist_ok=True)
    md = download("public-resolvers.md")
    sig = download("public-resolvers.md.minisig")
    (ASSETS / "public-resolvers.md").write_bytes(md)
    (ASSETS / "public-resolvers.md.minisig").write_bytes(sig)
    servers = parse(md.decode("utf-8"))

    lines = [
        "package ltechnologies.onionphone.onionvpn.core.dnscrypt.config",
        "",
        "/**",
        " * Bundled DNSCrypt/DoH public resolver catalog (from public-resolvers.md).",
        " * Generated — do not edit by hand; refresh via scripts/update-dnscrypt-resolvers.py",
        " */",
        "object DnsCryptPublicResolvers {",
        '    const val AUTO = "auto"',
        '    const val SOURCE_CACHE_FILE = "public-resolvers.md"',
        f'    const val MINISIGN_KEY = "{MINISIGN_KEY}"',
        "",
        "    data class Entry(",
        "        val name: String,",
        "        val description: String,",
        "        val stamps: List<String>,",
        "        val ipv6: Boolean,",
        "    )",
        "",
        "    val all: List<Entry> = listOf(",
    ]
    for s in servers:
        stamps_kt = ", ".join(f'"{st}"' for st in s["stamps"])
        lines.append(
            f'        Entry("{s["name"]}", "{esc(s["description"])}", '
            f"listOf({stamps_kt}), {str(s['ipv6']).lower()}),"
        )
    lines += [
        "    )",
        "",
        "    val byName: Map<String, Entry> = all.associateBy { it.name }",
        "",
        "    /** First stamp per resolver (IPv4-preferred catalog for UI). */",
        "    val knownServers: Map<String, String> = all",
        "        .filterNot { it.ipv6 }",
        "        .associate { it.name to it.stamps.first() }",
        "",
        "    fun resolveName(requested: String): String {",
        '        val key = requested.trim().ifBlank { "cloudflare" }',
        "        if (key.equals(AUTO, ignoreCase = true)) return AUTO",
        "        LEGACY_ALIASES[key]?.let { return it }",
        "        if (byName.containsKey(key)) return key",
        '        return "cloudflare"',
        "    }",
        "",
        "    private val LEGACY_ALIASES = mapOf(",
        '        "adguard" to "adguard-dns",',
        '        "quad9" to "quad9-dnscrypt-ip4-nofilter-pri",',
        "    )",
        "}",
        "",
    ]
    OUT_KT.write_text("\n".join(lines))
    print(f"Wrote {len(servers)} resolvers → {OUT_KT}")


if __name__ == "__main__":
    main()
