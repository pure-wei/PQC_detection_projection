"""TLS cipher suite name parser.

Decomposes OpenSSL cipher suite names into constituent algorithms:
key exchange, authentication, symmetric encryption, and hash.

Supports both TLS 1.3 and TLS 1.2 naming conventions:
  - TLS 1.3: "TLS_AES_256_GCM_SHA384"
  - TLS 1.2: "ECDHE-RSA-AES128-GCM-SHA256"
"""

import re
from dataclasses import dataclass


@dataclass
class CipherSuite:
    """Decomposed cipher suite information."""
    original_name: str
    protocol: str               # "TLSv1.3" or "TLSv1.2"
    kex_algorithm: str          # e.g., "ECDHE-P256", "RSA", "Kyber768"
    auth_algorithm: str         # e.g., "RSA", "ECDSA", "Dilithium3"
    symmetric_algorithm: str    # e.g., "AES-256-GCM", "CHACHA20-POLY1305"
    hash_algorithm: str         # e.g., "SHA-384", "SHA-256"
    nist_security_level: int    # approximate


# Mapping tables
TLS13_CIPHER_MAP = {
    "TLS_AES_256_GCM_SHA384": {
        "kex": "ECDHE",
        "auth": "RSA/ECDSA",
        "enc": "AES-256-GCM",
        "hash": "SHA-384",
        "level": 3,
    },
    "TLS_AES_128_GCM_SHA256": {
        "kex": "ECDHE",
        "auth": "RSA/ECDSA",
        "enc": "AES-128-GCM",
        "hash": "SHA-256",
        "level": 1,
    },
    "TLS_CHACHA20_POLY1305_SHA256": {
        "kex": "ECDHE",
        "auth": "RSA/ECDSA",
        "enc": "CHACHA20-POLY1305",
        "hash": "SHA-256",
        "level": 1,
    },
    "TLS_AES_128_CCM_SHA256": {
        "kex": "ECDHE",
        "auth": "RSA/ECDSA",
        "enc": "AES-128-CCM",
        "hash": "SHA-256",
        "level": 1,
    },
    "TLS_AES_128_CCM_8_SHA256": {
        "kex": "ECDHE",
        "auth": "RSA/ECDSA",
        "enc": "AES-128-CCM-8",
        "hash": "SHA-256",
        "level": 1,
    },
}

# PQC / Hybrid Post-Quantum cipher suites (standardized and draft)
# These cipher suites use X25519 + ML-KEM-768 hybrid key exchange
PQC_CIPHER_SUITES = {
    # IETF draft-kwiatkowski-tls-ecdhe-mlkem (de facto standard in 2025-2026)
    "TLS_X25519MLKEM768_AES_256_GCM_SHA384": {
        "kex": "X25519+ML-KEM-768 (PQC Hybrid)",
        "auth": "RSA/ECDSA",
        "enc": "AES-256-GCM",
        "hash": "SHA-384",
        "level": 3,
        "pqc": True,
    },
    "TLS_X25519MLKEM768_AES_128_GCM_SHA256": {
        "kex": "X25519+ML-KEM-768 (PQC Hybrid)",
        "auth": "RSA/ECDSA",
        "enc": "AES-128-GCM",
        "hash": "SHA-256",
        "level": 1,
        "pqc": True,
    },
    "TLS_X25519MLKEM768_CHACHA20_POLY1305_SHA256": {
        "kex": "X25519+ML-KEM-768 (PQC Hybrid)",
        "auth": "RSA/ECDSA",
        "enc": "CHACHA20-POLY1305",
        "hash": "SHA-256",
        "level": 1,
        "pqc": True,
    },
    # Earlier experimental names
    "TLS_X25519KYBER768_AES_256_GCM_SHA384": {
        "kex": "X25519+Kyber-768 (PQC Hybrid)",
        "auth": "RSA/ECDSA",
        "enc": "AES-256-GCM",
        "hash": "SHA-384",
        "level": 3,
        "pqc": True,
    },
    # Pure PQC (future)
    "TLS_MLKEM1024_AES_256_GCM_SHA384": {
        "kex": "ML-KEM-1024 (PQC-only)",
        "auth": "ML-DSA / Dilithium",
        "enc": "AES-256-GCM",
        "hash": "SHA-384",
        "level": 5,
        "pqc": True,
    },
}

# Known PQC-capable CDN / infrastructure indicators
# Sites behind Cloudflare are automatically PQC-capable since 2022
PQC_CDN_INDICATORS = [
    "cloudflare", "cloudflare-nginx", "cloudflare-brotli",
]

# Common TLS 1.2 cipher suite patterns
TLS12_PATTERNS = [
    # ECDHE-RSA-AES256-GCM-SHA384 (real OpenSSL format, no dash after AES)
    re.compile(
        r"^(ECDHE|DHE|ECDH|DH)-(RSA|ECDSA|DSS)-"
        r"(AES\d+-GCM|AES-\d+-GCM|AES\d+-CBC|AES-\d+-CBC|CHACHA20-POLY1305|AES\d+-CCM|AES-\d+-CCM|CAMELLIA\d+-GCM|CAMELLIA-\d+-GCM)-"
        r"(SHA\d+|SHA-\d+)$"
    ),
    # ECDHE-ECDSA-AES256-GCM-SHA384 (duplicate pattern for ECDSA)
    re.compile(
        r"^(ECDHE|DHE|ECDH)-(ECDSA|RSA)-"
        r"(AES\d+-GCM|AES-\d+-GCM|AES\d+-CBC|AES-\d+-CBC|CHACHA20-POLY1305)-"
        r"(SHA\d+|SHA-\d+)$"
    ),
    # AES256-GCM-SHA384 (RSA key exchange, no forward secrecy)
    re.compile(
        r"^(AES\d+-GCM|AES-\d+-GCM|AES\d+-CBC|AES-\d+-CBC|CAMELLIA\d+-GCM|CAMELLIA-\d+-GCM)-"
        r"(SHA\d+|SHA-\d+)$"
    ),
]


def _normalize_alg(s: str) -> str:
    """Normalize OpenSSL algorithm token spellings to a canonical form.

    OpenSSL TLS 1.2 cipher suite names use compact tokens like "AES128-GCM"
    and "SHA256", while TLS 1.3 (and this project's translation tables) use
    "AES-128-GCM" and "SHA-256". Normalize so both protocol versions render
    and translate consistently.
    """
    # SHA256 -> SHA-256, SHA1 -> SHA-1 (leaves "SHA-256" untouched)
    s = re.sub(r"(SHA)(\d+)", r"\1-\2", s)
    # AES128 -> AES-128, CAMELLIA256 -> CAMELLIA-256 (leaves "AES-128" untouched)
    s = re.sub(r"(AES|CAMELLIA)(\d+)", r"\1-\2", s)
    return s


def parse_cipher_suite_name(name: str) -> CipherSuite:
    """Parse an OpenSSL cipher suite name string.

    Args:
        name: Cipher suite name, e.g. "TLS_AES_256_GCM_SHA384"
              or "TLS_X25519MLKEM768_AES_256_GCM_SHA384"

    Returns:
        CipherSuite with decomposed algorithm components
    """
    name = name.strip()

    # Check PQC cipher suites first
    if name in PQC_CIPHER_SUITES:
        info = PQC_CIPHER_SUITES[name]
        return CipherSuite(
            original_name=name,
            protocol="TLSv1.3",
            kex_algorithm=info["kex"],
            auth_algorithm=info["auth"],
            symmetric_algorithm=info["enc"],
            hash_algorithm=info["hash"],
            nist_security_level=info["level"],
        )

    # TLS 1.3
    if name.startswith("TLS_"):
        if name in TLS13_CIPHER_MAP:
            info = TLS13_CIPHER_MAP[name]
            return CipherSuite(
                original_name=name,
                protocol="TLSv1.3",
                kex_algorithm=info["kex"],
                auth_algorithm=info["auth"],
                symmetric_algorithm=info["enc"],
                hash_algorithm=info["hash"],
                nist_security_level=info["level"],
            )
        else:
            # Unknown TLS 1.3 suite — try to parse
            parts = name.replace("TLS_", "").split("_")
            enc = f"{parts[0]}-{parts[1]}-{parts[2]}" if len(parts) >= 3 else name
            h = f"SHA-{parts[-1]}" if parts[-1].startswith("SHA") else parts[-1]
            return CipherSuite(
                original_name=name,
                protocol="TLSv1.3",
                kex_algorithm="ECDHE",
                auth_algorithm="RSA/ECDSA",
                symmetric_algorithm=enc,
                hash_algorithm=h,
                nist_security_level=1,
            )

    # TLS 1.2
    for pattern in TLS12_PATTERNS:
        m = pattern.match(name)
        if m:
            groups = m.groups()
            if len(groups) == 4:  # ECDHE-RSA-AES256-GCM-SHA384
                kex, auth, enc, h = groups
            elif len(groups) == 3:  # ECDHE-ECDSA-AES256-GCM-SHA384 (duplicate pattern)
                kex, auth = groups[0], groups[1]
                enc, h = groups[2], groups[3] if len(groups) > 3 else "SHA-256"
            else:
                kex = "RSA"
                auth = "RSA"
                enc = groups[0]
                h = groups[1]

            level = 1
            if "256" in enc:
                level = 3
            if "128" in enc:
                level = 1

            # Normalize compact OpenSSL spellings (SHA256 → SHA-256, etc.)
            enc = _normalize_alg(enc)
            h = _normalize_alg(h)

            return CipherSuite(
                original_name=name,
                protocol="TLSv1.2",
                kex_algorithm=kex,
                auth_algorithm=auth,
                symmetric_algorithm=enc,
                hash_algorithm=h,
                nist_security_level=level,
            )

    # Fallback
    return CipherSuite(
        original_name=name,
        protocol="unknown",
        kex_algorithm="unknown",
        auth_algorithm="unknown",
        symmetric_algorithm="unknown",
        hash_algorithm="unknown",
        nist_security_level=0,
    )
