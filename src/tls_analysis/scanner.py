"""Unified host scanner: capture → parse algorithms → quantum-safety verdict.

This module ties the three analysis layers together into one call, which is
exactly the workflow the platform is built for:

    抓包 (capture) → 解析密码算法 (parse which algorithm) → 判断是否抗量子 (verdict)

For a single host it:
  1. Captures the TLS handshake and parses the *actual* negotiated key-exchange
     group from the ServerHello key_share extension (not inferred from the
     cipher-suite name, which in TLS 1.3 does not encode the key exchange).
  2. Decomposes the cipher suite into key-exchange / auth / symmetric / hash.
  3. Parses the X.509 certificate (signature algorithm, public key type) and
     runs the NIST data-driven size check.
  4. Produces a single layered verdict combining the transport layer and the
     certificate layer.

Usage:
    from .scanner import scan_host
    r = scan_host("cloudflare.com")
    print(r.overall)
"""

import socket
import ssl

from dataclasses import dataclass, field

from .oqs_provider import check_oqs_available, lookup_group
from .pqc_detector import detect_pqc_support
from .connection import analyze_tls_connection
from .cert_analyzer import analyze_certificate
from .cipher_suite_parser import parse_cipher_suite_name
from ..utils.logger import get_logger

log = get_logger(__name__)


@dataclass
class ScanResult:
    """Complete layered analysis of one host."""

    host: str
    port: int = 443
    success: bool = False
    error: str = ""

    # ── Negotiated session ──
    protocol: str = ""
    cipher_suite_name: str = ""

    # ── Cipher suite decomposition (from the name) ──
    kex_algorithm: str = ""       # e.g. "ECDHE" (name-derived, may be generic)
    auth_algorithm: str = ""
    symmetric_algorithm: str = ""
    hash_algorithm: str = ""

    # ── Transport layer: the ACTUAL negotiated key-exchange group ──
    kex_group_id: str = ""        # hex, e.g. "0x11EC"
    kex_group_name: str = ""      # e.g. "X25519MLKEM768" / "X25519"
    kex_is_pqc: bool = False
    transport_pqc: bool = False
    transport_evidence: str = ""
    detect_method: str = ""       # "oqs_direct" / "cdn_inference" / "none"

    # ── Certificate layer ──
    cert_error: str = ""
    cert_subject: str = ""
    cert_issuer: str = ""
    cert_sig_algorithm: str = ""
    cert_sig_is_pqc: bool = False
    cert_pubkey_type: str = ""
    cert_pubkey_is_pqc: bool = False
    cert_quantum_safe: bool = False
    cert_nist_level: int = 0
    nist_checks: list = field(default_factory=list)

    # ── Combined verdict ──
    overall: str = ""             # human-readable quantum-safety verdict


def _get_leaf_cert(host: str, port: int, timeout: float = 10.0) -> bytes:
    """Get the leaf certificate DER bytes from a TLS connection."""
    context = ssl.create_default_context()
    context.check_hostname = True
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            return ssock.getpeercert(binary_form=True)


def scan_host(host: str, port: int = 443, timeout: float = 15.0) -> ScanResult:
    """Run a full layered analysis of one host.

    Args:
        host: Target hostname.
        port: Target port.
        timeout: Per-connection timeout in seconds.

    Returns:
        ScanResult with transport + certificate analysis and a combined verdict.
    """
    result = ScanResult(host=host, port=port)

    # ── Layer: transport / key exchange ──
    oqs_available = check_oqs_available()

    if oqs_available:
        det = detect_pqc_support(host, port, timeout=int(timeout))
        if det.success:
            cs = det.cipher_suite or parse_cipher_suite_name(det.cipher_suite_name)
            result.protocol = det.protocol
            result.cipher_suite_name = det.cipher_suite_name
            result.kex_algorithm = cs.kex_algorithm
            result.auth_algorithm = cs.auth_algorithm
            result.symmetric_algorithm = cs.symmetric_algorithm
            result.hash_algorithm = cs.hash_algorithm
            result.transport_pqc = det.pqc_supported
            result.transport_evidence = det.evidence
            result.detect_method = det.method

            # Resolve the ACTUAL negotiated group (PQC or classical).
            if det.pqc_group_id:
                try:
                    gid = int(det.pqc_group_id, 16)
                    name, is_pqc = lookup_group(gid)
                    result.kex_group_id = det.pqc_group_id
                    result.kex_group_name = name
                    result.kex_is_pqc = is_pqc
                except (ValueError, TypeError):
                    pass
            if not result.kex_group_name:
                result.kex_group_name = cs.kex_algorithm
        else:
            result.error = det.error
    else:
        # No OQS: fall back to Python ssl + CDN inference (no group available).
        info = analyze_tls_connection(host, port, timeout)
        if info.success:
            cs = info.cipher_suite or parse_cipher_suite_name(info.cipher_suite_name)
            result.protocol = info.protocol
            result.cipher_suite_name = info.cipher_suite_name
            result.kex_algorithm = cs.kex_algorithm
            result.auth_algorithm = cs.auth_algorithm
            result.symmetric_algorithm = cs.symmetric_algorithm
            result.hash_algorithm = cs.hash_algorithm
            result.transport_pqc = info.pqc_capable
            result.transport_evidence = info.pqc_evidence
            result.detect_method = "cdn_inference"
            result.kex_group_name = cs.kex_algorithm
            result.kex_is_pqc = info.pqc_capable
        else:
            result.error = info.error

    # ── Layer: certificate ──
    if result.protocol:
        try:
            der = _get_leaf_cert(host, port, timeout)
            cert = analyze_certificate(der)
            result.cert_subject = cert.subject_cn
            result.cert_issuer = cert.issuer_cn
            result.cert_sig_algorithm = cert.sig_algorithm_name
            result.cert_sig_is_pqc = cert.sig_is_pqc
            result.cert_pubkey_type = cert.pubkey_type
            result.cert_pubkey_is_pqc = cert.pubkey_is_pqc
            result.cert_quantum_safe = cert.is_quantum_safe
            result.cert_nist_level = cert.nist_security_level
            result.nist_checks = cert.nist_checks
        except Exception as e:
            result.cert_error = f"{type(e).__name__}: {e}"

    result.success = bool(result.protocol)
    result.overall = _verdict(result)
    return result


def _verdict(r: ScanResult) -> str:
    """Combine transport + certificate layers into a single verdict."""
    if not r.success:
        return "未知 (连接失败)"

    t = r.transport_pqc
    c = r.cert_quantum_safe

    if t and c:
        return "完全抗量子 (密钥交换 + 证书均为 PQC)"
    if t and not c:
        return "部分抗量子 (仅 TLS 密钥交换层，证书仍为经典)"
    if not t and c:
        return "部分抗量子 (仅证书层，密钥交换仍为经典)"
    return "不抗量子 (经典密码)"


def scan_to_dict(r: ScanResult) -> dict:
    """Convert ScanResult to a JSON-serializable dict."""
    return {
        "host": r.host,
        "port": r.port,
        "success": r.success,
        "error": r.error,
        "overall": r.overall,
        "protocol": r.protocol,
        "cipher_suite_name": r.cipher_suite_name,
        "cipher_decomposed": {
            "kex": r.kex_algorithm,
            "auth": r.auth_algorithm,
            "enc": r.symmetric_algorithm,
            "hash": r.hash_algorithm,
        },
        "kex_group_id": r.kex_group_id,
        "kex_group_name": r.kex_group_name,
        "kex_is_pqc": r.kex_is_pqc,
        "transport_pqc": r.transport_pqc,
        "transport_evidence": r.transport_evidence,
        "detect_method": r.detect_method,
        "cert_subject": r.cert_subject,
        "cert_issuer": r.cert_issuer,
        "cert_sig_algorithm": r.cert_sig_algorithm,
        "cert_sig_is_pqc": r.cert_sig_is_pqc,
        "cert_pubkey_type": r.cert_pubkey_type,
        "cert_pubkey_is_pqc": r.cert_pubkey_is_pqc,
        "cert_quantum_safe": r.cert_quantum_safe,
        "cert_nist_level": r.cert_nist_level,
        "nist_checks": r.nist_checks,
        "cert_error": r.cert_error,
    }


def format_scan(r: ScanResult) -> str:
    """Render a ScanResult as a readable CLI report."""
    def yesno(b: bool) -> str:
        return "是 (抗量子)" if b else "否 (经典)"

    lines = [
        "=" * 60,
        f"  统一安全扫描 【Unified PQC Scan】",
        f"  {r.host}:{r.port}",
        "=" * 60,
        f"  TLS 协议:      {r.protocol}",
        f"  密码套件:      {r.cipher_suite_name}",
        "  ── 密码套件组成 ──",
        f"    密钥交换:    {r.kex_algorithm}",
        f"    身份认证:    {r.auth_algorithm}",
        f"    对称加密:    {r.symmetric_algorithm}",
        f"    哈希算法:    {r.hash_algorithm}",
    ]

    # Transport layer — actual negotiated group
    lines.append("  ── 传输层 (密钥交换) ──")
    if r.kex_group_id:
        lines.append(f"    实际协商组:  {r.kex_group_name} (ID {r.kex_group_id})")
    else:
        lines.append(f"    密钥交换组:  {r.kex_group_name or '未知'}")
    lines.append(f"    抗量子:      {yesno(r.transport_pqc)}")
    if r.transport_evidence:
        lines.append(f"    证据:        {r.transport_evidence[:80]}")

    # Certificate layer
    lines.append("  ── 证书层 (签名/公钥) ──")
    if r.cert_error:
        lines.append(f"    证书解析失败: {r.cert_error}")
    else:
        lines.append(f"    主体 (CN):   {r.cert_subject or '-'}")
        lines.append(f"    签名算法:    {r.cert_sig_algorithm}"
                     + (" [抗量子]" if r.cert_sig_is_pqc else ""))
        lines.append(f"    公钥类型:    {r.cert_pubkey_type}"
                     + (" [抗量子]" if r.cert_pubkey_is_pqc else ""))
        lines.append(f"    抗量子:      {yesno(r.cert_quantum_safe)}")
        for check in r.nist_checks:
            lines.append(f"    NIST 校验:   {check}")

    lines.append("  ── 综合结论 ──")
    lines.append(f"    {r.overall}")
    lines.append("=" * 60)
    return "\n".join(lines)
