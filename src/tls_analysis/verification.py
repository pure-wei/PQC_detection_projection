"""Anti-spoofing verification for TLS handshake data.

Verifies that actual cryptographic data matches declared algorithms,
and checks randomness quality of TLS handshake random values.

Two entry points:
  - run_pcap_verification(capture)  → from pcap hex dump
  - run_cert_verification(result)   → from CertAnalysis (Python ssl)
"""

import math
import hashlib
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional

from ..utils.logger import get_logger

log = get_logger(__name__)


# ═══════════════════════════════════════════════════════════════════
# Expected key_share body sizes per group ID
# body = group(2) + ke_len(2) + ke_data
# ═══════════════════════════════════════════════════════════════════
_EXPECTED_KEY_SHARE_SIZES = {
    0x001D: ("X25519", 36),           # 32 ke_data
    0x0017: ("secp256r1", 69),        # 65 ke_data
    0x0018: ("secp384r1", 101),       # 97 ke_data
    0x0019: ("secp521r1", 137),       # 133 ke_data
    0x11EB: ("X25519MLKEM512", 804),  # 32+768 ke_data
    0x11EC: ("X25519MLKEM768", 1124), # 32+1088 ke_data
    0x11ED: ("X25519MLKEM1024", 1604),# 32+1568 ke_data
    0x023D: ("MLKEM512", 772),        # 768 ke_data
    0x023E: ("MLKEM768", 1092),       # 1088 ke_data
    0x023F: ("MLKEM1024", 1572),      # 1568 ke_data
    0x0239: ("Kyber512", 772),
    0x023A: ("Kyber768", 1092),
    0x023C: ("Kyber1024", 1572),
    0x2F39: ("FrodoKEM-640-AES", 9760),
    0x2F3A: ("FrodoKEM-976-AES", 15648),
    0x2F3C: ("FrodoKEM-1344-AES", 21264),
}

# ═══════════════════════════════════════════════════════════════════
# Data structures
# ═══════════════════════════════════════════════════════════════════

@dataclass
class RandomnessResult:
    """Randomness quality check for one field."""
    label: str = ""
    byte_count: int = 0
    status: str = "SKIP"       # PASS / WARN / FAIL / SKIP
    entropy: float = 0.0       # bits per byte
    chi_squared: float = 0.0
    issues: list = field(default_factory=list)
    details: str = ""


@dataclass
class CertSigResult:
    """Certificate signature verification result."""
    status: str = "SKIP"       # PASS / WARN / FAIL / SKIP
    declared_oid: str = ""
    declared_name: str = ""
    signature_valid: Optional[bool] = None
    algo_match: bool = False   # declared algorithm consistent with pubkey type
    details: str = ""


@dataclass
class KeyShareResult:
    """Key exchange consistency check."""
    status: str = "SKIP"
    declared_group_id: int = 0
    declared_name: str = ""
    expected_size: int = 0
    actual_size: int = 0
    sizes_match: bool = False
    details: str = ""


@dataclass
class VerificationResult:
    """Complete verification result for one host."""
    host: str = ""
    overall: str = "SKIP"      # PASS / WARN / FAIL / SKIP
    randomness: list = field(default_factory=list)
    cert_sig: Optional[CertSigResult] = None
    key_share: Optional[KeyShareResult] = None
    failures: int = 0
    warnings: int = 0


# ═══════════════════════════════════════════════════════════════════
# Randomness verification
# ═══════════════════════════════════════════════════════════════════

def verify_randomness(data: bytes, label: str) -> RandomnessResult:
    """Check if a byte sequence appears cryptographically random.

    For 32-byte TLS random values, entropy is inherently limited
    (256 possible byte values with only 32 samples).
    Good CSPRNG output typically yields 4.5-5.5 bits/byte with 32 samples.
    """
    r = RandomnessResult(label=label, byte_count=len(data))

    if len(data) == 0:
        r.status = "SKIP"
        r.details = "empty value"
        return r

    # ── Pattern checks ──
    if all(b == 0x00 for b in data):
        r.status = "FAIL"
        r.issues.append("全零字节")
        r.details = "FAIL: all bytes are 0x00"
        r.entropy = 0.0
        return r

    if len(set(data)) == 1:
        r.status = "FAIL"
        r.issues.append("所有字节相同")
        r.details = f"FAIL: all bytes = 0x{data[0]:02X}"
        r.entropy = 0.0
        return r

    if all(data[i + 1] == (data[i] + 1) % 256 for i in range(len(data) - 1)):
        r.status = "FAIL"
        r.issues.append("递增序列")
        r.details = "FAIL: sequential increment pattern"
        r.entropy = 0.0
        return r

    half = len(data) // 2
    if data[:half] == data[half:2*half]:
        r.status = "FAIL"
        r.issues.append("重复模式（前半==后半）")
        r.details = "FAIL: first half equals second half"
        r.entropy = 0.0
        return r

    # ── Shannon entropy ──
    freq = Counter(data)
    n = len(data)
    ent = 0.0
    for count in freq.values():
        p = count / n
        ent -= p * math.log2(p)
    r.entropy = round(ent, 2)

    # ── Chi-squared test against uniform distribution ──
    expected = n / 256
    chi2 = sum((count - expected) ** 2 / expected for count in freq.values())
    # Add contribution from unobserved bytes (count=0)
    chi2 += (256 - len(freq)) * (expected)
    r.chi_squared = round(chi2, 1)

    # ── Status determination ──
    if ent < 3.0:
        r.status = "FAIL"
        r.issues.append(f"熵过低: {ent:.1f} bits/byte")
        r.details = f"FAIL: entropy={ent:.1f} bits/byte (expected >=4.5)"
    elif ent < 4.5:
        r.status = "WARN"
        r.details = f"WARN: entropy={ent:.1f} bits/byte, marginally low"
    else:
        r.status = "PASS"
        r.details = f"PASS: entropy={ent:.1f} bits/byte, chi²={chi2:.0f}"

    return r


# ═══════════════════════════════════════════════════════════════════
# Certificate signature verification
# ═══════════════════════════════════════════════════════════════════

def verify_cert_from_der(der_bytes: bytes) -> CertSigResult:
    """Verify certificate: load the full DER cert and check signature.

    1. Checks algo/pubkey type consistency (e.g. ECDSA OID must have EC pubkey)
    2. Attempts cryptographic self-verification of the certificate signature
    """
    r = CertSigResult()

    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa as rsa_mod, ed25519, ed448

        cert = x509.load_der_x509_certificate(der_bytes)
        sig_oid = cert.signature_algorithm_oid.dotted_string
        sig_bytes = cert.signature
        tbs_bytes = cert.tbs_certificate_bytes
        pubkey = cert.public_key()

        from .cert_analyzer import SIG_ALGORITHM_OIDS
        r.declared_oid = sig_oid
        r.declared_name = SIG_ALGORITHM_OIDS.get(sig_oid, f"Unknown ({sig_oid})")

        # ── Algo/pubkey consistency ──
        pk_type_map = {
            rsa_mod.RSAPublicKey: "RSA",
            ec.EllipticCurvePublicKey: "EC",
            ed25519.Ed25519PublicKey: "Ed25519",
            ed448.Ed448PublicKey: "Ed448",
        }
        pk_type = None
        for cls, name in pk_type_map.items():
            if isinstance(pubkey, cls):
                pk_type = name
                break

        # Consistency check
        if "10045" in sig_oid and pk_type != "EC":
            r.algo_match = False
        elif "113549" in sig_oid and pk_type != "RSA":
            r.algo_match = False
        elif sig_oid in ("1.3.101.112",) and pk_type != "Ed25519":
            r.algo_match = False
        elif sig_oid in ("1.3.101.113",) and pk_type != "Ed448":
            r.algo_match = False
        else:
            r.algo_match = True

        # ── Cryptographic signature verification ──
        hash_algo = _oid_to_hash(sig_oid)

        if isinstance(pubkey, rsa_mod.RSAPublicKey):
            # Try PKCS1v15 first, then PSS
            for pad in [padding.PKCS1v15(), padding.PSS(mgf=padding.MGF1(hash_algo), salt_length=hash_algo.digest_size)]:
                try:
                    pubkey.verify(sig_bytes, tbs_bytes, pad, hash_algo)
                    r.signature_valid = True
                    break
                except Exception:
                    continue
            else:
                r.signature_valid = False

        elif isinstance(pubkey, ec.EllipticCurvePublicKey):
            try:
                pubkey.verify(sig_bytes, tbs_bytes, ec.ECDSA(hash_algo))
                r.signature_valid = True
            except Exception:
                r.signature_valid = False

        elif isinstance(pubkey, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            try:
                pubkey.verify(sig_bytes, tbs_bytes)
                r.signature_valid = True
            except Exception:
                r.signature_valid = False
        else:
            r.signature_valid = None  # Unknown key type

    except Exception as e:
        log.debug(f"Cert verification error: {e}")
        r.signature_valid = None
        r.details = f"SKIP: certificate parsing failed ({e})"
        r.status = "SKIP"
        return r

    # ── Status ──
    if r.signature_valid is True and r.algo_match:
        r.status = "PASS"
        r.details = "PASS: signature valid, algo/pubkey consistent"
    elif r.signature_valid is True and not r.algo_match:
        r.status = "WARN"
        r.details = "WARN: signature valid but algo OID inconsistent with pubkey type [可能是伪造!]"
    elif r.signature_valid is False:
        r.status = "FAIL"
        r.details = "FAIL: signature verification failed [证书签名无效!]"
    elif r.algo_match:
        r.status = "PASS"
        r.details = "PASS: algo/pubkey consistent (PQC/unknown key — crypto verify skipped)"
    else:
        r.status = "WARN"
        r.details = "WARN: algo/pubkey mismatch (crypto verify unavailable)"

    return r


def verify_cert_self_consistency(result) -> CertSigResult:
    """Verify certificate using CertAnalysis result (from cert command).

    Requires the full DER bytes to be available through the analysis result.
    """
    r = CertSigResult()
    r.declared_oid = result.sig_algorithm_oid
    r.declared_name = result.sig_algorithm_name

    oid = result.sig_algorithm_oid
    pk_type = result.pubkey_type

    # ── Algorithm / pubkey consistency check ──
    if "10045" in oid and pk_type not in ("EC",):
        r.algo_match = False
        r.details = f"WARN: ECDSA OID ({oid}) but pubkey is {pk_type} [可能是伪造!]"
        r.status = "WARN"
        return r

    if "113549" in oid and pk_type not in ("RSA",):
        r.algo_match = False
        r.details = f"WARN: RSA OID ({oid}) but pubkey is {pk_type} [可能是伪造!]"
        r.status = "WARN"
        return r

    if oid in ("1.3.101.112", "1.3.101.113") and pk_type not in ("Ed25519", "Ed448"):
        r.algo_match = False
        r.details = f"WARN: EdDSA OID ({oid}) but pubkey is {pk_type} [可能是伪造!]"
        r.status = "WARN"
        return r

    r.algo_match = True
    r.status = "PASS"
    r.details = "PASS: algo/pubkey type consistent (full crypto verify use pcap --verify)"
    return r


def _oid_to_hash(oid: str):
    """Map signature algorithm OID to hash algorithm."""
    from cryptography.hazmat.primitives import hashes

    # ECDSA
    if oid == "1.2.840.10045.4.1":
        return hashes.SHA1()
    if oid == "1.2.840.10045.4.3.1":
        return hashes.SHA224()
    if oid == "1.2.840.10045.4.3.2":
        return hashes.SHA256()
    if oid == "1.2.840.10045.4.3.3":
        return hashes.SHA384()
    if oid == "1.2.840.10045.4.3.4":
        return hashes.SHA512()

    # RSA PKCS1v15
    if oid == "1.2.840.113549.1.1.5":
        return hashes.SHA1()
    if oid == "1.2.840.113549.1.1.11":
        return hashes.SHA256()
    if oid == "1.2.840.113549.1.1.12":
        return hashes.SHA384()
    if oid == "1.2.840.113549.1.1.13":
        return hashes.SHA512()
    if oid == "1.2.840.113549.1.1.14":
        return hashes.SHA224()

    # RSA-PSS (hash encoded elsewhere, use SHA256 as default)
    if oid == "1.2.840.113549.1.1.10":
        return hashes.SHA256()

    # EdDSA
    if oid in ("1.3.101.112", "1.3.101.113"):
        return hashes.SHA256()  # not used for EdDSA

    # SM2
    if "10197" in oid:
        return hashes.SHA256()  # SM3 fallback

    return hashes.SHA256()


# ═══════════════════════════════════════════════════════════════════
# Key share size verification
# ═══════════════════════════════════════════════════════════════════

def _verify_cert_chain(cert_der_list: list[bytes]) -> CertSigResult:
    """Verify certificate chain: each cert's signature using the issuer's pubkey.

    For the chain [leaf, intermediate, root]:
      - Verify leaf cert sig with intermediate's pubkey
      - Verify intermediate cert sig with root's pubkey
      - Root is self-signed: verify with its own pubkey

    Returns result for the leaf certificate (first in chain).
    Also checks algo/pubkey consistency.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa as rsa_mod, ed25519, ed448

    if not cert_der_list:
        return CertSigResult(status="SKIP", details="SKIP: no certificates in chain")

    r = CertSigResult()
    leaf_cert = None
    chain_results = []

    try:
        # Load all certs
        certs = []
        for der in cert_der_list:
            certs.append(x509.load_der_x509_certificate(der))

        leaf_cert = certs[0]
        sig_oid = leaf_cert.signature_algorithm_oid.dotted_string
        from .cert_analyzer import SIG_ALGORITHM_OIDS
        r.declared_oid = sig_oid
        r.declared_name = SIG_ALGORITHM_OIDS.get(sig_oid, f"Unknown ({sig_oid})")

        # ── Algo/pubkey consistency for leaf ──
        leaf_pubkey = leaf_cert.public_key()
        pk_type_map = {
            rsa_mod.RSAPublicKey: "RSA",
            ec.EllipticCurvePublicKey: "EC",
            ed25519.Ed25519PublicKey: "Ed25519",
            ed448.Ed448PublicKey: "Ed448",
        }
        leaf_pk_type = None
        for cls, name in pk_type_map.items():
            if isinstance(leaf_pubkey, cls):
                leaf_pk_type = name
                break

        if "10045" in sig_oid and leaf_pk_type != "EC":
            r.algo_match = False
        elif "113549" in sig_oid and leaf_pk_type != "RSA":
            r.algo_match = False
        elif sig_oid in ("1.3.101.112",) and leaf_pk_type != "Ed25519":
            r.algo_match = False
        elif sig_oid in ("1.3.101.113",) and leaf_pk_type != "Ed448":
            r.algo_match = False
        else:
            r.algo_match = True

        # ── Verify each cert in chain ──
        # Verify cert[i] using cert[i+1]'s pubkey.
        # Last cert is NOT verified (we don't have its issuer — root is pre-trusted).
        all_verified = True
        for i in range(len(certs) - 1):
            child = certs[i]
            issuer = certs[i + 1]
            issuer_pubkey = issuer.public_key()
            child_sig = child.signature
            child_tbs = child.tbs_certificate_bytes
            child_sig_oid = child.signature_algorithm_oid.dotted_string
            hash_algo = _oid_to_hash(child_sig_oid)

            verified = _try_verify_sig(issuer_pubkey, child_sig, child_tbs, hash_algo)
            if not verified:
                all_verified = False
                break

        r.signature_valid = all_verified

    except Exception as e:
        log.debug(f"Cert chain verification error: {e}")
        r.signature_valid = None

    # ── Status ──
    if r.signature_valid is True and r.algo_match:
        r.status = "PASS"
        r.details = f"PASS: {len(cert_der_list)}-cert chain verified, algo/pubkey consistent"
    elif r.signature_valid is True and not r.algo_match:
        r.status = "WARN"
        r.details = "WARN: chain verified but algo OID inconsistent with pubkey [可能是伪造!]"
    elif r.signature_valid is False:
        r.status = "FAIL"
        r.details = "FAIL: certificate chain signature verification failed [证书链签名无效!]"
    else:
        r.status = "PASS" if r.algo_match else "WARN"
        r.details = ("PASS: algo/pubkey consistent (crypto verify unavailable)"
                     if r.algo_match else "WARN: algo/pubkey mismatch")

    return r


def _try_verify_sig(pubkey, signature: bytes, tbs_bytes: bytes, hash_algo) -> bool:
    """Try to verify a signature using a public key. Returns True/False."""
    from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa as rsa_mod, ed25519, ed448

    try:
        if isinstance(pubkey, rsa_mod.RSAPublicKey):
            for pad in [padding.PKCS1v15(), padding.PSS(mgf=padding.MGF1(hash_algo), salt_length=hash_algo.digest_size)]:
                try:
                    pubkey.verify(signature, tbs_bytes, pad, hash_algo)
                    return True
                except Exception:
                    continue
            return False
        elif isinstance(pubkey, ec.EllipticCurvePublicKey):
            pubkey.verify(signature, tbs_bytes, ec.ECDSA(hash_algo))
            return True
        elif isinstance(pubkey, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            pubkey.verify(signature, tbs_bytes)
            return True
    except Exception:
        return False
    return False


def verify_key_share_size(group_id: int, actual_body_size: int) -> KeyShareResult:
    """Verify that the key_share extension body size matches the declared group."""
    r = KeyShareResult()
    r.declared_group_id = group_id
    r.actual_size = actual_body_size

    if group_id in _EXPECTED_KEY_SHARE_SIZES:
        name, expected = _EXPECTED_KEY_SHARE_SIZES[group_id]
        r.declared_name = name
        r.expected_size = expected
        tolerance = max(8, expected * 0.05)  # 5% or 8 bytes
        r.sizes_match = abs(actual_body_size - expected) <= tolerance
        if r.sizes_match:
            r.status = "PASS"
            r.details = f"PASS: {name} ({r.declared_group_id:#06X}) key_share={actual_body_size}B, expected={expected}B"
        else:
            r.status = "FAIL"
            r.details = f"FAIL: expected {expected}B for {name}, got {actual_body_size}B"
    else:
        r.declared_name = f"Unknown({group_id:#06X})"
        r.expected_size = 0
        r.sizes_match = True  # can't verify unknown groups
        r.status = "SKIP"
        r.details = f"SKIP: group {group_id:#06X} not in known-size table"

    return r


# ═══════════════════════════════════════════════════════════════════
# Main entry points
# ═══════════════════════════════════════════════════════════════════

def run_pcap_verification(capture) -> VerificationResult:
    """Run all verifications on a TLSPacketCapture.

    Extracts random values from ClientHello/ServerHello hex,
    parses certificate chain, and checks key_share consistency.
    """
    from .packet_capture import HANDSHAKE_TYPES

    vr = VerificationResult(host=capture.host)

    randomness_results = []
    cert_der_list = []
    key_share_group = None
    key_share_size = None

    for rec in capture.tls_records:
        raw = rec.raw_body_bytes
        if not raw or len(raw) < 4:
            continue

        hs_type = raw[0]

        # ── ClientHello: extract random (bytes 6-37) ──
        if hs_type == 0x01 and len(raw) >= 38:
            client_random = raw[6:38]
            randomness_results.append(
                verify_randomness(client_random, "ClientHello.random")
            )

        # ── ServerHello: extract random + key_share ──
        if hs_type == 0x02 and len(raw) >= 38:
            server_random = raw[6:38]
            randomness_results.append(
                verify_randomness(server_random, "ServerHello.random")
            )

            # Also extract key_share from ServerHello extensions
            ks = _extract_key_share_from_serverhello(raw)
            if ks is not None:
                key_share_group, key_share_size = ks

        # ── Certificate: extract DER cert chain ──
        if hs_type == 0x0B and len(raw) > 8:
            certs = _extract_cert_chain(raw, capture.protocol)
            cert_der_list.extend(certs)

    vr.randomness = randomness_results

    # ── Certificate signature verification ──
    if cert_der_list:
        vr.cert_sig = _verify_cert_chain(cert_der_list)
    else:
        vr.cert_sig = CertSigResult(status="SKIP", details="SKIP: no certificate found in capture")

    # ── Key share verification ──
    if key_share_group is not None and key_share_size is not None:
        vr.key_share = verify_key_share_size(key_share_group, key_share_size)
    else:
        vr.key_share = KeyShareResult(status="SKIP", details="SKIP: key_share not found in ServerHello")

    # ── Overall ──
    _compute_overall(vr)
    return vr


def run_cert_verification(result) -> VerificationResult:
    """Run verification using CertAnalysis (from Python ssl cert command)."""
    vr = VerificationResult(host=result.subject_cn or "unknown")

    # Certificate signature self-consistency
    vr.cert_sig = verify_cert_self_consistency(result)

    # Randomness and key_share not available from cert-only path
    vr.randomness = [
        RandomnessResult(label="random values", status="SKIP",
                         details="SKIP: not available from cert command (use pcap --verify)")
    ]
    vr.key_share = KeyShareResult(status="SKIP",
                                  details="SKIP: not available from cert command (use pcap --verify)")

    _compute_overall(vr)
    return vr


def _compute_overall(vr: VerificationResult):
    """Compute overall status from sub-checks."""
    vr.failures = 0
    vr.warnings = 0

    for r in vr.randomness:
        if r.status == "FAIL":
            vr.failures += 1
        elif r.status == "WARN":
            vr.warnings += 1

    if vr.cert_sig:
        if vr.cert_sig.status == "FAIL":
            vr.failures += 1
        elif vr.cert_sig.status == "WARN":
            vr.warnings += 1

    if vr.key_share:
        if vr.key_share.status == "FAIL":
            vr.failures += 1
        elif vr.key_share.status == "WARN":
            vr.warnings += 1

    if vr.failures > 0:
        vr.overall = "FAIL"
    elif vr.warnings > 0:
        vr.overall = "WARN"
    else:
        vr.overall = "PASS"


# ═══════════════════════════════════════════════════════════════════
# Hex parsing helpers (for pcap path)
# ═══════════════════════════════════════════════════════════════════

def _extract_key_share_from_serverhello(raw: bytes) -> Optional[tuple[int, int]]:
    """Parse key_share extension from ServerHello handshake body.

    Returns (group_id, extension_body_size) or None.
    Extension body = group(2) + ke_len(2) + ke_data(N).
    """
    try:
        pos = 4       # skip handshake header
        pos += 2      # legacy_version
        pos += 32     # random

        # session_id
        if pos >= len(raw):
            return None
        sid_len = raw[pos]
        pos += 1 + sid_len

        # cipher_suite
        if pos + 2 > len(raw):
            return None
        pos += 2

        # compression
        if pos >= len(raw):
            return None
        pos += 1

        # extensions
        if pos + 2 > len(raw):
            return None
        ext_total = int.from_bytes(raw[pos:pos + 2], "big")
        pos += 2
        ext_end = min(pos + ext_total, len(raw))

        while pos + 4 <= ext_end:
            ext_type = int.from_bytes(raw[pos:pos + 2], "big")
            ext_len = int.from_bytes(raw[pos + 2:pos + 4], "big")
            pos += 4

            if pos + ext_len > len(raw):
                break

            if ext_type == 0x0033 and ext_len >= 4:  # key_share
                group_id = int.from_bytes(raw[pos:pos + 2], "big")
                return (group_id, ext_len)

            pos += ext_len
    except Exception:
        pass

    return None


def _extract_cert_chain(raw: bytes, protocol: str) -> list[bytes]:
    """Extract DER certificates from Certificate handshake body.

    TLS 1.3 structure:
      cert_request_context<0..255>  (1B length + data)
      CertificateEntry list<0..2^24-1>  (3B total length)
        cert_data<1..2^24-1>  (3B length + DER)
        extensions<0..2^16-1> (2B length + data)

    TLS 1.2 structure:
      certificate_list<0..2^24-1>  (3B total length)
        ASN.1Cert<1..2^24-1>  (3B length + DER)
    """
    certs = []
    try:
        pos = 4  # skip handshake header
        is_tls13 = "TLSv1.3" in (protocol or "")

        if is_tls13 and pos < len(raw):
            ctx_len = raw[pos]
            pos += 1 + ctx_len

        if pos + 3 > len(raw):
            return certs

        chain_len = int.from_bytes(raw[pos:pos + 3], "big")
        pos += 3
        chain_end = min(pos + chain_len, len(raw))

        while pos + 3 <= chain_end:
            cert_len = int.from_bytes(raw[pos:pos + 3], "big")
            pos += 3
            if pos + cert_len <= chain_end:
                certs.append(raw[pos:pos + cert_len])
                pos += cert_len
                # TLS 1.3: skip per-cert extensions (2B length + data)
                if is_tls13 and pos + 2 <= chain_end:
                    ext_len = int.from_bytes(raw[pos:pos + 2], "big")
                    pos += 2 + ext_len
            else:
                break
    except Exception:
        pass

    return certs


# ═══════════════════════════════════════════════════════════════════
# Output helpers
# ═══════════════════════════════════════════════════════════════════

def format_verification(vr: VerificationResult) -> str:
    """Format verification result as readable text for CLI output."""
    icon = {"PASS": "[OK]", "WARN": "[!!]", "FAIL": "[XX]", "SKIP": "[--]"}

    lines = [
        "=" * 54,
        "  抗伪造验证 【Anti-Spoofing Verification】",
        f"  {vr.host}",
        "=" * 54,
        "",
        "  随机数质量 【Randomness Quality】",
    ]

    for r in vr.randomness:
        mark = icon.get(r.status, "[??]")
        lines.append(f"    {mark} {r.label:<24s}  {r.details}")

    lines.append("")
    lines.append("  证书签名验证 【Certificate Signature】")

    if vr.cert_sig:
        cs = vr.cert_sig
        mark = icon.get(cs.status, "[??]")
        lines.append(f"    {mark} 声明算法: {cs.declared_name} ({cs.declared_oid})")
        if cs.signature_valid is not None:
            sig_str = "有效" if cs.signature_valid else "无效"
            lines.append(f"        密码学验证: 签名{ sig_str}")
        lines.append(f"        算法/公钥一致性: {'一致' if cs.algo_match else '不一致'}")
        lines.append(f"        {cs.details}")

    lines.append("")
    lines.append("  密钥交换一致性 【Key Exchange Consistency】")

    if vr.key_share:
        ks = vr.key_share
        mark = icon.get(ks.status, "[??]")
        lines.append(f"    {mark} 声明组: {ks.declared_name} ({ks.declared_group_id:#06X})")
        if ks.expected_size > 0:
            lines.append(f"        期望大小: {ks.expected_size}B  实际大小: {ks.actual_size}B")
        lines.append(f"        {ks.details}")

    lines.append("")
    overall_mark = icon.get(vr.overall, "[??]")
    lines.append(f"  综合结论: {vr.overall}  ({vr.failures}严重问题, {vr.warnings}警告)")
    lines.append("=" * 54)

    return "\n".join(lines)
