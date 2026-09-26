#!/usr/bin/env python3
"""
hashid_tool.py - A hash type identifier for security assessments and CTFs.

Identifies the likely algorithm(s) that produced a given hash string based on
length, character set, and known structural patterns (e.g. hash prefixes like
$1$, $2b$, {SHA}, etc). This is a *classification* aid only -- it does not
crack hashes -- and is meant for use in authorized security testing, CTF
work, and forensics on systems you are permitted to test (e.g. Kali Linux).

Usage:
    python3 hashid_tool.py <hash_string>
    python3 hashid_tool.py -f hashes.txt
    python3 hashid_tool.py -f hashes.txt -o results.json
    echo "5f4dcc3b5aa765d61d8327deb882cf99" | python3 hashid_tool.py

Author: (your name here)
License: MIT
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass, field


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------

@dataclass
class HashMatch:
    name: str
    hashcat_mode: str = "N/A"
    john_format: str = "N/A"
    confidence: str = "possible"  # "likely" | "possible"

    def as_dict(self):
        return {
            "name": self.name,
            "hashcat_mode": self.hashcat_mode,
            "john_format": self.john_format,
            "confidence": self.confidence,
        }


# --------------------------------------------------------------------------
# Prefix-based rules (very high confidence -- structural markers)
# These are checked first since a prefix like $2b$ or $6$ is unambiguous.
# --------------------------------------------------------------------------

PREFIX_RULES = [
    (r"^\$1\$", HashMatch("MD5 Crypt (Unix)", "500", "md5crypt", "likely")),
    (r"^\$2a\$|^\$2b\$|^\$2y\$", HashMatch("bcrypt", "3200", "bcrypt", "likely")),
    (r"^\$5\$", HashMatch("SHA-256 Crypt (Unix)", "7400", "sha256crypt", "likely")),
    (r"^\$6\$", HashMatch("SHA-512 Crypt (Unix)", "1800", "sha512crypt", "likely")),
    (r"^\$y\$", HashMatch("yescrypt (Unix)", "N/A", "yescrypt", "likely")),
    (r"^\$argon2i\$", HashMatch("Argon2i", "N/A", "argon2", "likely")),
    (r"^\$argon2id\$", HashMatch("Argon2id", "N/A", "argon2", "likely")),
    (r"^\$P\$|^\$H\$", HashMatch("phpBB3 / WordPress (phpass)", "400", "phpass", "likely")),
    (r"^\$apr1\$", HashMatch("Apache APR1-MD5", "1600", "apr1", "likely")),
    (r"^\{SHA\}", HashMatch("SHA-1 (Base64, LDAP)", "101", "nsldap", "likely")),
    (r"^\{SSHA\}", HashMatch("Salted SHA-1 (LDAP)", "111", "ssha", "likely")),
    (r"^\$sha1\$", HashMatch("SHA-1 Crypt", "15100", "sha1crypt", "likely")),
    (r"^\$krb5", HashMatch("Kerberos AS-REP / TGS-REP", "18200/13100", "krb5", "likely")),
    (r"^\$NT\$|^[a-f0-9]{32}:[a-f0-9]{32}$", HashMatch("NTLM (formatted)", "1000", "nt", "possible")),
    (r"^\$office\$", HashMatch("MS Office (2007/2010/2013)", "9400-9600", "office", "likely")),
    (r"^\$pdf\$", HashMatch("PDF (Encrypted)", "10400-10700", "pdf", "likely")),
    (r"^\$zip2?\$", HashMatch("ZIP (WinZip/PKZIP)", "13600", "zip", "likely")),
    (r"^\$rar5\$", HashMatch("RAR5", "13000", "rar5", "likely")),
    (r"^\$dynamic_", HashMatch("Dynamic (JtR generic)", "N/A", "dynamic", "possible")),
]

# --------------------------------------------------------------------------
# Length + charset based rules (checked when no prefix matches, or in
# addition to it -- many raw hex digests are ambiguous between algorithms
# that share the same output length).
# --------------------------------------------------------------------------

HEX = "0-9a-fA-F"

LENGTH_RULES = [
    (32, rf"^[{HEX}]{{32}}$", [
        HashMatch("MD5", "0", "raw-md5", "possible"),
        HashMatch("NTLM", "1000", "nt", "possible"),
        HashMatch("MD4", "900", "raw-md4", "possible"),
        HashMatch("LM", "3000", "lm", "possible"),
    ]),
    (40, rf"^[{HEX}]{{40}}$", [
        HashMatch("SHA-1", "100", "raw-sha1", "possible"),
        HashMatch("MySQL5 (SHA-1 based)", "300", "mysql-sha1", "possible"),
        HashMatch("RIPEMD-160", "6000", "ripemd-160", "possible"),
    ]),
    (56, rf"^[{HEX}]{{56}}$", [
        HashMatch("SHA-224", "1300", "raw-sha224", "possible"),
        HashMatch("SHA3-224", "17300", "raw-sha3-224", "possible"),
    ]),
    (64, rf"^[{HEX}]{{64}}$", [
        HashMatch("SHA-256", "1400", "raw-sha256", "possible"),
        HashMatch("SHA3-256", "17400", "raw-sha3-256", "possible"),
        HashMatch("BLAKE2s-256", "N/A", "blake2s", "possible"),
        HashMatch("GOST R 34.11-94", "6900", "gost", "possible"),
    ]),
    (96, rf"^[{HEX}]{{96}}$", [
        HashMatch("SHA-384", "10800", "raw-sha384", "possible"),
        HashMatch("SHA3-384", "17384", "raw-sha3-384", "possible"),
    ]),
    (128, rf"^[{HEX}]{{128}}$", [
        HashMatch("SHA-512", "1700", "raw-sha512", "possible"),
        HashMatch("SHA3-512", "17500", "raw-sha3-512", "possible"),
        HashMatch("Whirlpool", "6100", "whirlpool", "possible"),
    ]),
]

# Base64-style hashes (e.g. Django, some LDAP variants) - checked separately.
BASE64_RULES = [
    (r"^[A-Za-z0-9+/]{27}=$", HashMatch("SHA-1 (Base64, 20 bytes)", "101", "nsldap", "possible")),
    (r"^[A-Za-z0-9+/]{43}=$", HashMatch("SHA-256 (Base64, 32 bytes)", "1400", "raw-sha256", "possible")),
    (r"^[A-Za-z0-9+/]{86}==$", HashMatch("SHA-512 (Base64, 64 bytes)", "1700", "raw-sha512", "possible")),
]


def identify(hash_str: str):
    """Return a list of HashMatch candidates for a single hash string."""
    h = hash_str.strip()
    matches = []

    if not h:
        return matches

    # 1. Prefix / structural rules first (highest confidence)
    for pattern, match in PREFIX_RULES:
        if re.search(pattern, h):
            matches.append(match)

    # If we found a strong structural match, still fall through to check
    # length rules only if nothing "likely" was found, to avoid clutter.
    if any(m.confidence == "likely" for m in matches):
        return matches

    # 2. Base64-flavoured hashes
    for pattern, match in BASE64_RULES:
        if re.match(pattern, h):
            matches.append(match)

    # 3. Pure length/charset based (raw hex digests)
    for length, pattern, candidates in LENGTH_RULES:
        if len(h) == length and re.match(pattern, h):
            matches.extend(candidates)

    # 4. Catch colon-delimited formats like user:hash or hash:salt
    if ":" in h and not matches:
        parts = h.split(":")
        if len(parts) == 2 and all(re.match(rf"^[{HEX}]+$", p) for p in parts):
            matches.append(HashMatch("Hash:Salt or Hash:Hash pair", "N/A", "N/A", "possible"))

    if not matches:
        matches.append(HashMatch(f"Unknown (length={len(h)}, non-standard format)",
                                  "N/A", "N/A", "possible"))

    return matches


def format_console(hash_str: str, matches):
    lines = [f"\nHash: {hash_str}", f"Length: {len(hash_str)} characters", "-" * 60]
    for i, m in enumerate(matches, 1):
        tag = "[LIKELY]" if m.confidence == "likely" else "[possible]"
        lines.append(f"  {i:>2}. {tag:<10} {m.name}")
        lines.append(f"       Hashcat mode: {m.hashcat_mode}   John format: {m.john_format}")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Identify likely hash algorithm(s) from a hash string. "
                     "For authorized security testing and CTF use only.",
    )
    parser.add_argument("hash", nargs="?", help="A single hash string to identify")
    parser.add_argument("-f", "--file", help="File containing one hash per line")
    parser.add_argument("-o", "--output", help="Write results as JSON to this file")
    parser.add_argument("--json", action="store_true", help="Print results as JSON to stdout")
    args = parser.parse_args()

    hashes = []
    if args.file:
        with open(args.file, "r", encoding="utf-8", errors="ignore") as fh:
            hashes = [line.strip() for line in fh if line.strip()]
    elif args.hash:
        hashes = [args.hash]
    elif not sys.stdin.isatty():
        hashes = [line.strip() for line in sys.stdin if line.strip()]
    else:
        parser.print_help()
        sys.exit(1)

    results = {}
    for h in hashes:
        results[h] = [m.as_dict() for m in identify(h)]

    if args.json or args.output:
        payload = json.dumps(results, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as out:
                out.write(payload)
            print(f"[+] Results written to {args.output}")
        if args.json:
            print(payload)
    else:
        for h, matches_dicts in results.items():
            matches = [HashMatch(**md) for md in matches_dicts]
            print(format_console(h, matches))
        print()


if __name__ == "__main__":
    main()
