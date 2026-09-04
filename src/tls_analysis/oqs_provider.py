"""OQS (Open Quantum Safe) Provider detection for OpenSSL.

Checks whether the OQS provider (oqsprovider) is installed and available
in the system's OpenSSL, enabling direct PQC TLS handshake testing.

Installation:
  1. Build liboqs:    https://github.com/open-quantum-safe/liboqs
  2. Build oqsprovider: https://github.com/open-quantum-safe/oqs-provider
  3. Configure openssl.cnf to activate both default + oqsprovider

Or via MSYS2 on Windows:
  pacman -S mingw-w64-x86_64-liboqs mingw-w64-x86_64-oqs-provider
"""

import os
import subprocess
import shutil
import sys

from ..utils.logger import get_logger

log = get_logger(__name__)

# ── PQC TLS Group IDs (IANA / IETF draft) ──
# These are the TLS supported_groups identifiers for PQC key exchange.
# Ref: draft-ietf-tls-hybrid-design / draft-kwiatkowski-tls-ecdhe-mlkem
PQC_GROUP_IDS = {
    0x11EB: "X25519MLKEM512",
    0x11EC: "X25519MLKEM768",
    0x11ED: "X25519MLKEM1024",
    0x11E6: "X25519Kyber768Draft00",
    0x0239: "Kyber512",
    0x023A: "Kyber768",
    0x023C: "Kyber1024",
    0x023D: "MLKEM512",
    0x023E: "MLKEM768",
    0x023F: "MLKEM1024",
    0x2F39: "FrodoKEM-640-AES",
    0x2F3A: "FrodoKEM-976-AES",
    0x2F3C: "FrodoKEM-1344-AES",
}

# ── Classical TLS group IDs (IANA registry) ──
# Used to resolve the ACTUAL negotiated key_share group from a ServerHello,
# instead of inferring "ECDHE" from the cipher suite name (which, in TLS 1.3,
# does NOT encode the key exchange algorithm at all).
CLASSICAL_GROUP_IDS = {
    0x001D: "X25519",
    0x001E: "X448",
    0x0017: "secp256r1 (P-256)",
    0x0018: "secp384r1 (P-384)",
    0x0019: "secp521r1 (P-521)",
    0x0016: "secp256k1",
    0x0100: "ffdhe2048",
    0x0101: "ffdhe3072",
    0x0102: "ffdhe4096",
}


def lookup_group(group_id: int) -> tuple[str, bool]:
    """Resolve a TLS group ID to (group_name, is_pqc).

    This is the single source of truth for "what key exchange algorithm was
    actually negotiated" — it maps the numeric group ID from a ServerHello
    key_share extension back to a human-readable name, and flags whether the
    group is post-quantum (PQC) or classical.

    Args:
        group_id: 16-bit TLS supported_groups / key_share group ID.

    Returns:
        (name, is_pqc) — name is a human-readable algorithm name, is_pqc is
        True if the group is a post-quantum (or hybrid PQC) key exchange.
    """
    if group_id in PQC_GROUP_IDS:
        return PQC_GROUP_IDS[group_id], True
    if group_id in CLASSICAL_GROUP_IDS:
        return CLASSICAL_GROUP_IDS[group_id], False
    return f"Unknown(0x{group_id:04X})", False

# Build the -groups flag from the known PQC group IDs
_MINGW64_SSL_MODULES = [
    "D:/Git/mingw64/lib/ossl-modules",
    "C:/msys64/mingw64/lib/ossl-modules",
]

_EXTRA_SEARCH_PATHS = [
    "C:/Program Files/OpenSSL/lib/ossl-modules",
    "C:/OpenSSL/lib/ossl-modules",
]


# Search order for the openssl binary. PATH usually holds a 3.0.x build
# (Git Bash / conda ship 3.0.18) that has no ML-KEM, silently degrading
# Layer 1 detection to CDN inference — so probe every candidate and prefer
# a PQC-capable one (OpenSSL 3.5+ has ML-KEM built in).
_OPENSSL_BINARIES = [
    "D:/Git/mingw64/bin/openssl.exe",
    "C:/msys64/mingw64/bin/openssl.exe",
]


def _supports_pqc(openssl: str) -> bool:
    """True if this openssl binary exposes ML-KEM (built-in or via provider)."""
    try:
        result = subprocess.run(
            [openssl, "list", "-kem-algorithms"],
            capture_output=True, text=True, timeout=10,
        )
        combined = (result.stdout + result.stderr).lower()
        return "mlkem" in combined
    except Exception:
        return False


def find_openssl() -> str:
    """Locate the openssl binary, preferring a PQC-capable build.

    Returns the first candidate whose -kem-algorithms list contains ML-KEM;
    if none qualifies, falls back to the first available (Layer 2 behavior).
    """
    candidates = []
    which = shutil.which("openssl")
    if which:
        candidates.append(which)
    candidates.extend(p for p in _OPENSSL_BINARIES if os.path.exists(p))
    if not candidates:
        return "openssl"
    for openssl in candidates:
        if _supports_pqc(openssl):
            return openssl
    return candidates[0]


def check_oqs_available() -> bool:
    """Check if PQC TLS groups are available (built-in or via OQS provider)."""
    openssl = find_openssl()
    if _supports_pqc(openssl):
        return True
    try:
        # Fallback: check for OQS provider
        result = subprocess.run(
            [openssl, "list", "-providers", "-provider", "oqsprovider"],
            capture_output=True, text=True, timeout=10,
        )
        combined = (result.stdout + result.stderr).lower()
        if "unable to load provider oqsprovider" in combined:
            return False
        if "could not load the shared library" in combined:
            return False
        return "oqsprovider" in combined
    except Exception:
        return False


def get_oqs_group_flag() -> str:
    """Return the -groups flag string for PQC testing.

    Uses the standard hybrid group X25519MLKEM768 plus classical fallbacks.
    OpenSSL 3.5+ has built-in PQC support with these group names.
    """
    return "X25519MLKEM768:x25519:secp256r1"


def get_install_instructions() -> str:
    """Return platform-specific OQS installation instructions."""
    if sys.platform == "win32":
        return (
            "OQS Provider not found.\n\n"
            "Option 1 — MSYS2 (recommended for Windows):\n"
            "  pacman -S mingw-w64-x86_64-liboqs mingw-w64-x86_64-oqs-provider\n\n"
            "Option 2 — Build from source:\n"
            "  1. git clone https://github.com/open-quantum-safe/liboqs && cd liboqs\n"
            "     mkdir build && cd build && cmake .. -G 'Ninja' && ninja && ninja install\n"
            "  2. git clone https://github.com/open-quantum-safe/oqs-provider && cd oqs-provider\n"
            "     mkdir build && cd build && cmake .. -G 'Ninja' && ninja && ninja install\n\n"
            "Then configure openssl.cnf to activate oqsprovider."
        )
    else:
        return (
            "OQS Provider not found. Install via:\n"
            "  Ubuntu/Debian: sudo apt install oqs-provider\n"
            "  macOS: brew install open-quantum-safe/oqs/oqs-provider\n"
            "  Or build from source:\n"
            "    https://github.com/open-quantum-safe/oqs-provider"
        )


def detect_oqs_status() -> dict:
    """Full OQS detection: availability, paths, version.

    Returns:
        dict with status details
    """
    openssl_path = find_openssl()
    available = check_oqs_available()

    # Check for DLL on disk (Windows)
    dll_found = False
    dll_paths = []
    for d in _MINGW64_SSL_MODULES + _EXTRA_SEARCH_PATHS:
        dll = os.path.join(d, "oqsprovider.dll")
        if os.path.exists(dll):
            dll_found = True
            dll_paths.append(dll)

    # Get OpenSSL version
    version = "unknown"
    try:
        result = subprocess.run(
            [openssl_path, "version"],
            capture_output=True, text=True, timeout=5,
        )
        version = result.stdout.strip()
    except Exception:
        pass

    return {
        "oqs_available": available,
        "openssl_path": openssl_path,
        "openssl_version": version,
        "dll_on_disk": dll_found,
        "dll_paths": dll_paths,
        "install_instructions": "" if available else get_install_instructions(),
    }


def print_oqs_status():
    """Print OQS detection status to console."""
    status = detect_oqs_status()
    log.info("=" * 60)
    log.info("OQS Provider Detection")
    log.info("=" * 60)
    log.info(f"  OpenSSL:     {status['openssl_version']}")
    log.info(f"  Binary:      {status['openssl_path']}")
    log.info(f"  OQS Provider: {'AVAILABLE' if status['oqs_available'] else 'NOT INSTALLED'}")
    log.info(f"  DLL on disk: {status['dll_on_disk']}")
    if status['dll_paths']:
        for p in status['dll_paths']:
            log.info(f"    Found: {p}")
    log.info("=" * 60)

    if not status['oqs_available']:
        log.info("\n" + status['install_instructions'])
