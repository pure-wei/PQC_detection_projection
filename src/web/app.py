"""PQC-HTTPS Web UI — Flask backend.

Usage:
    python -m src.web.app
    → open http://localhost:5000
"""

import os
import sys
import socket
import ssl
import subprocess
import re
from flask import Flask, render_template, request, jsonify

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from src.tls_analysis.packet_capture import capture_tls_handshake
from src.tls_analysis.pqc_detector import detect_pqc_support
from src.tls_analysis.cert_analyzer import analyze_certificate
from src.tls_analysis.cipher_suite_parser import parse_cipher_suite_name
from src.tls_analysis.oqs_provider import check_oqs_available
from src.tls_analysis.scanner import scan_host, scan_to_dict
from src.tls_analysis.verification import (
    _verify_cert_chain,
    verify_key_share_size,
    VerificationResult,
    CertSigResult,
    KeyShareResult,
)

app = Flask(__name__)

# ═══════════════════════════════════════════════════════════════════
# Shared helper — extract handshake data via quick openssl capture
# ═══════════════════════════════════════════════════════════════════

def _capture_handshake_data(host: str, port: int = 443, timeout: int = 8):
    """Extract random values + cert chain via a single openssl -msg run.

    Returns (randomness_results, cert_chain_der_list).
    """
    from src.tls_analysis.verification import verify_randomness, _extract_cert_chain
    from src.tls_analysis.oqs_provider import find_openssl

    randomness = []
    cert_chain = []
    openssl = find_openssl()

    try:
        cmd = [
            openssl, "s_client", "-connect", f"{host}:{port}",
            "-servername", host, "-msg",
        ]
        req = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        r = subprocess.run(cmd, input=req, capture_output=True, text=True, timeout=timeout)
        combined = r.stdout + "\n" + r.stderr

        # Detect protocol version
        proto = "TLSv1.3"
        pm = re.search(r"New,\s*(TLSv[0-9.]+)", combined)
        if pm:
            proto = pm.group(1)

        # Collect all hex blocks
        hex_blocks = []
        cur = []
        for line in combined.splitlines():
            if re.match(r"^\s{4,}[0-9a-fA-F]{2}", line):
                cur.append(line.strip())
            else:
                if len(cur) >= 2:
                    hex_blocks.append(" ".join(cur))
                cur = []
        if len(cur) >= 2:
            hex_blocks.append(" ".join(cur))

        client_done = False
        server_done = False

        for hb in hex_blocks:
            try:
                data = bytes.fromhex(hb.replace(" ", ""))
            except ValueError:
                continue

            if len(data) < 4:
                continue

            hs_type = data[0]

            # ClientHello: handshake type 0x01, random at bytes 6-37
            if not client_done and hs_type == 0x01 and len(data) >= 38:
                randomness.append(verify_randomness(data[6:38], "ClientHello.random"))
                client_done = True

            # ServerHello: handshake type 0x02, random at bytes 6-37
            if not server_done and hs_type == 0x02 and len(data) >= 38:
                randomness.append(verify_randomness(data[6:38], "ServerHello.random"))
                server_done = True

            # Certificate: handshake type 0x0B, extract DER chain
            if hs_type == 0x0B and not cert_chain:
                cert_chain = _extract_cert_chain(data, proto)

            if client_done and server_done and cert_chain:
                break

    except Exception:
        pass

    return randomness, cert_chain


# ═══════════════════════════════════════════════════════════════════
# Routes
# ═══════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return render_template("index.html")


# ═══════════════════════════════════════════════════════════════════
# API: pcap
# ═══════════════════════════════════════════════════════════════════

@app.route("/api/pcap")
def api_pcap():
    host = request.args.get("host", "").strip()
    port = int(request.args.get("port", 443))
    if not host:
        return jsonify({"ok": False, "error": "请输入域名"})

    try:
        cap = capture_tls_handshake(host, port, timeout=12)
        if not cap.success:
            return jsonify({"ok": False, "error": cap.error or "连接失败"})

        cs = parse_cipher_suite_name(cap.cipher_suite)

        records = []
        for rec in cap.tls_records:
            records.append({
                "dir": "↑" if rec.direction == ">>>" else "↓",
                "dir_label": "发送" if rec.direction == ">>>" else "接收",
                "type": rec.handshake_type or rec.content_type,
                "len": rec.record_length,
                "ver": rec.tls_version,
            })

        return jsonify({
            "ok": True,
            "host": host, "port": port,
            "protocol": cap.protocol,
            "cipher_suite": cap.cipher_suite,
            "cipher_decomposed": {
                "kex": cs.kex_algorithm, "auth": cs.auth_algorithm,
                "enc": cs.symmetric_algorithm, "hash": cs.hash_algorithm,
            },
            "total_bytes": cap.total_bytes,
            "total_sent": cap.total_sent_bytes,
            "total_recv": cap.total_recv_bytes,
            "record_count": cap.record_count,
            "records": records,
        })
    except Exception as e:
        return jsonify({"ok": False, "error": f"{type(e).__name__}: {e}"})


# ═══════════════════════════════════════════════════════════════════
# API: detect
# ═══════════════════════════════════════════════════════════════════

@app.route("/api/detect")
def api_detect():
    host = request.args.get("host", "").strip()
    port = int(request.args.get("port", 443))
    if not host:
        return jsonify({"ok": False, "error": "请输入域名"})

    try:
        oqs_available = check_oqs_available()

        if not oqs_available:
            from src.tls_analysis.connection import analyze_tls_connection
            info = analyze_tls_connection(host, port, timeout=10)
            if not info.success:
                return jsonify({"ok": False, "error": info.error or "连接失败"})

            cs = parse_cipher_suite_name(info.cipher_suite_name)

            return jsonify({
                "ok": True,
                "host": host, "port": port,
                "method": "CDN推测 (间接)",
                "protocol": info.protocol,
                "cipher_suite": info.cipher_suite_name,
                "cipher_decomposed": {
                    "kex": cs.kex_algorithm, "auth": cs.auth_algorithm,
                    "enc": cs.symmetric_algorithm, "hash": cs.hash_algorithm,
                },
                "pqc_supported": info.pqc_capable,
                "pqc_algorithm": "",
                "pqc_group_id": "",
                "evidence": f"CDN推测: {info.cdn_provider}" if info.pqc_capable else "未检测到PQC支持",
                "cdn_provider": info.cdn_provider,
                "verification": _build_detect_verification_dict(host, port),
            })

        # OQS direct
        result = detect_pqc_support(host, port, timeout=12)
        if not result.success:
            return jsonify({"ok": False, "error": result.error or "检测失败"})

        cs = parse_cipher_suite_name(result.cipher_suite_name)

        # Build verification: randomness + key_share
        randomness, _ = _capture_handshake_data(host, port)
        vr = VerificationResult(host=f"{host}:{port}")
        vr.randomness = randomness

        # Key share verification
        if result.pqc_group_id:
            try:
                gid = int(result.pqc_group_id, 16)
                vr.key_share = verify_key_share_size(gid, result.pqc_key_share_size)
            except Exception:
                vr.key_share = KeyShareResult(status="SKIP", details="key_share解析失败")
        else:
            vr.key_share = KeyShareResult(status="SKIP", details="未检测到key_share扩展")

        _compute_overall(vr)

        return jsonify({
            "ok": True,
            "host": host, "port": port,
            "method": result.method,
            "protocol": result.protocol,
            "cipher_suite": result.cipher_suite_name,
            "cipher_decomposed": {
                "kex": cs.kex_algorithm, "auth": cs.auth_algorithm,
                "enc": cs.symmetric_algorithm, "hash": cs.hash_algorithm,
            },
            "pqc_supported": result.pqc_supported,
            "pqc_algorithm": result.pqc_algorithm,
            "pqc_group_id": result.pqc_group_id,
            "pqc_key_share_size": result.pqc_key_share_size,
            "evidence": result.evidence,
            "handshake_bytes_sent": result.handshake_bytes_sent,
            "handshake_bytes_recv": result.handshake_bytes_recv,
            "verification": _vresult_dict(vr),
        })

    except Exception as e:
        return jsonify({"ok": False, "error": f"{type(e).__name__}: {e}"})


# ═══════════════════════════════════════════════════════════════════
# API: cert
# ═══════════════════════════════════════════════════════════════════

@app.route("/api/cert")
def api_cert():
    host = request.args.get("host", "").strip()
    port = int(request.args.get("port", 443))
    if not host:
        return jsonify({"ok": False, "error": "请输入域名"})

    try:
        der_bytes = _get_leaf_cert(host, port)
        if not der_bytes:
            return jsonify({"ok": False, "error": "获取证书失败"})

        result = analyze_certificate(der_bytes)

        # Real crypto verification: get chain + randomness from openssl
        randomness, cert_chain = _capture_handshake_data(host, port)

        vr = VerificationResult(host=f"{host}:{port}")
        vr.randomness = randomness
        vr.key_share = None

        # Cryptographic cert chain signature verification
        if cert_chain:
            vr.cert_sig = _verify_cert_chain(cert_chain)
        else:
            vr.cert_sig = CertSigResult(status="SKIP", details="证书链提取失败")

        _compute_overall(vr)

        return jsonify({
            "ok": True,
            "host": host, "port": port,
            "subject_cn": result.subject_cn or "-",
            "issuer_cn": result.issuer_cn or "-",
            "issuer_org": result.issuer_org or "-",
            "not_before": (result.not_before[:10] if result.not_before else "-"),
            "not_after": (result.not_after[:10] if result.not_after else "-"),
            "fingerprint": result.fingerprint_sha256[:32] + "...",
            "sig_algorithm": result.sig_algorithm_name,
            "sig_oid": result.sig_algorithm_oid,
            "sig_is_pqc": result.sig_is_pqc,
            "sig_is_sm": result.sig_is_sm,
            "pubkey_type": result.pubkey_type,
            "pubkey_size_bits": result.pubkey_size_bits,
            "pubkey_curve": result.pubkey_curve,
            "is_quantum_safe": result.is_quantum_safe,
            "nist_level": result.nist_security_level,
            "verification": _vresult_dict(vr),
        })

    except ssl.SSLCertVerificationError as e:
        return jsonify({"ok": False, "error": f"证书验证错误: {e}"})
    except Exception as e:
        return jsonify({"ok": False, "error": f"{type(e).__name__}: {e}"})


# ═══════════════════════════════════════════════════════════════════
# API: scan (unified)
# ═══════════════════════════════════════════════════════════════════

@app.route("/api/scan")
def api_scan():
    host = request.args.get("host", "").strip()
    port = int(request.args.get("port", 443))
    if not host:
        return jsonify({"ok": False, "error": "请输入域名"})

    try:
        result = scan_host(host, port, timeout=15)
        if not result.success:
            return jsonify({"ok": False, "error": result.error or "扫描失败"})
        return jsonify({"ok": True, **scan_to_dict(result)})
    except Exception as e:
        return jsonify({"ok": False, "error": f"{type(e).__name__}: {e}"})


# ═══════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════

def _get_leaf_cert(host: str, port: int) -> bytes:
    """Get DER certificate from a TLS connection."""
    context = ssl.create_default_context()
    context.check_hostname = True
    with socket.create_connection((host, port), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            return ssock.getpeercert(binary_form=True)


def _build_detect_verification_dict(host: str, port: int) -> dict:
    """Build verification dict for CDN fallback path (randomness only)."""
    randomness, _ = _capture_handshake_data(host, port)
    vr = VerificationResult(host=f"{host}:{port}")
    vr.randomness = randomness
    vr.key_share = KeyShareResult(status="SKIP", details="CDN推测模式无key_share数据")
    _compute_overall(vr)
    return _vresult_dict(vr)


def _compute_overall(vr: VerificationResult):
    """Compute overall status for a VerificationResult."""
    vr.failures = sum(1 for r in vr.randomness if r.status == "FAIL")
    vr.warnings = sum(1 for r in vr.randomness if r.status == "WARN")
    if vr.cert_sig:
        if vr.cert_sig.status == "FAIL": vr.failures += 1
        elif vr.cert_sig.status == "WARN": vr.warnings += 1
    if vr.key_share:
        if vr.key_share.status == "FAIL": vr.failures += 1
        elif vr.key_share.status == "WARN": vr.warnings += 1
    if vr.failures > 0:
        vr.overall = "FAIL"
    elif vr.warnings > 0:
        vr.overall = "WARN"
    else:
        vr.overall = "PASS"


def _vresult_dict(vr) -> dict:
    """VerificationResult → JSON dict."""
    return {
        "overall": vr.overall,
        "failures": vr.failures,
        "warnings": vr.warnings,
        "randomness": [{"label": r.label, "status": r.status, "entropy": r.entropy,
                         "chi_squared": r.chi_squared, "details": r.details}
                       for r in vr.randomness],
        "cert_sig": {
            "status": vr.cert_sig.status,
            "declared_name": vr.cert_sig.declared_name,
            "declared_oid": vr.cert_sig.declared_oid,
            "signature_valid": vr.cert_sig.signature_valid,
            "algo_match": vr.cert_sig.algo_match,
            "details": vr.cert_sig.details,
        } if vr.cert_sig else None,
        "key_share": {
            "status": vr.key_share.status,
            "declared_name": vr.key_share.declared_name,
            "declared_group_id": f"0x{vr.key_share.declared_group_id:04X}",
            "expected_size": vr.key_share.expected_size,
            "actual_size": vr.key_share.actual_size,
            "sizes_match": vr.key_share.sizes_match,
            "details": vr.key_share.details,
        } if vr.key_share else None,
    }


if __name__ == "__main__":
    print("PQC-HTTPS Web UI")
    print("启动地址: http://localhost:5000")
    app.run(host="127.0.0.1", port=5000, debug=True)
