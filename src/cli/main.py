#!/usr/bin/env python3
"""PQC-HTTPS CLI: Main entry point.

Usage:
    python -m src.cli.main cert cloudflare.com       # Certificate analysis
    python -m src.cli.main detect cloudflare.com      # PQC detection
    python -m src.cli.main pcap cloudflare.com        # Deep packet capture
"""

import argparse
import json
import os
import sys
import time
import webbrowser
import threading
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from src.tls_analysis.oqs_provider import check_oqs_available, get_install_instructions, lookup_group
from src.tls_analysis.pqc_detector import detect_pqc_support, result_to_dict
from src.tls_analysis.packet_capture import capture_tls_handshake, detect_capture_methods
from src.tls_analysis.cert_analyzer import analyze_certificate, cert_analysis_to_dict
from src.tls_analysis.cipher_suite_parser import parse_cipher_suite_name
from src.tls_analysis.scanner import scan_host, format_scan, scan_to_dict
from src.tls_analysis.verification import run_pcap_verification, run_cert_verification, format_verification
from src.utils.logger import get_logger
from src.utils.pdf_report import build_cert_pdf, build_detect_pdf, build_pcap_pdf

log = get_logger("pqc-https")


def _open_browser(host: str, port: int):
    url = f"https://{host}" if port == 443 else f"https://{host}:{port}"
    threading.Thread(target=lambda: webbrowser.open(url), daemon=True).start()


def _kex_display(result) -> str:
    """Best-effort key-exchange description: the ACTUAL negotiated group.

    The cipher-suite name in TLS 1.3 does not encode the key exchange, so
    "ECDHE" is misleading when the server actually negotiated X25519MLKEM768.
    Prefer the real group ID (parsed from the ServerHello key_share) when present.
    """
    cs = parse_cipher_suite_name(result.cipher_suite_name)
    if getattr(result, "pqc_group_id", ""):
        try:
            gid = int(result.pqc_group_id, 16)
            name, is_pqc = lookup_group(gid)
            tag = " (抗量子)" if is_pqc else " (经典)"
            return f"{name}{tag}"
        except (ValueError, TypeError):
            pass
    return cs.kex_algorithm


# ═══════════════════════════════════════════════════════════════════
# cert
# ═══════════════════════════════════════════════════════════════════

def cmd_cert(args):
    import socket
    import ssl

    host = args.host
    port = args.port

    _open_browser(host, port)
    time.sleep(2)
    log.info(f"正在连接 {host}:{port} 获取证书...")

    der_bytes = None
    try:
        context = ssl.create_default_context()
        context.check_hostname = True
        with socket.create_connection((host, port), timeout=args.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                der_bytes = ssock.getpeercert(binary_form=True)
    except ssl.SSLCertVerificationError as e:
        log.error(f"证书验证错误: {e}")
        return 1
    except Exception as e:
        log.error(f"连接失败: {e}")
        return 1

    if not der_bytes:
        log.error("获取证书失败")
        return 1

    result = analyze_certificate(der_bytes)
    if result.parse_error:
        log.warning(f"证书解析异常: {result.parse_error}")

    _print_cert_result(result, host, port)

    if args.verify:
        print("\n")
        vresult = run_cert_verification(result)
        vresult.host = f"{host}:{port}"
        print(format_verification(vresult))

    if not args.no_save:
        os.makedirs("output", exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = os.path.join("output", f"cert_{host}_{ts}.json")
        pdf_path = os.path.join("output", f"cert_{host}_{ts}.pdf")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(cert_analysis_to_dict(result), f, indent=2, ensure_ascii=False)
        build_cert_pdf(result, host, port, pdf_path)
        log.info(f"JSON: {json_path}")
        log.info(f"PDF:  {pdf_path}")

    return 0


def _print_cert_result(result, host: str, port: int):
    qs_icon = "是" if result.is_quantum_safe else "否 (经典密码)"
    print("\n" + "=" * 54)
    print(f"  证书深度分析 【Certificate Analysis】")
    print(f"  {host}:{port}")
    print("=" * 54)
    print(f"\n  基本信息")
    print(f"    域名 (CN):      {result.subject_cn or '-'}")
    print(f"    颁发者 (CN):    {result.issuer_cn or '-'}")
    if result.issuer_org:
        print(f"    颁发机构:       {result.issuer_org}")
    if result.not_before:
        print(f"    有效期:         {result.not_before[:10]} ~ {result.not_after[:10]}")
    print(f"    指纹 (SHA256):  {result.fingerprint_sha256[:32]}...")
    print(f"\n  签名算法")
    algo_detail = result.sig_algorithm_name
    if result.sig_is_sm: algo_detail += " [国密]"
    if result.sig_is_pqc: algo_detail += " [抗量子]"
    print(f"    {algo_detail}  (OID: {result.sig_algorithm_oid})")
    print(f"\n  公钥信息")
    pk_type = result.pubkey_type
    if result.pubkey_is_pqc: pk_type += " (抗量子)"
    print(f"    类型: {pk_type}    长度: {result.pubkey_size_bits} bits ({result.pubkey_raw_bytes}B DER)")
    if result.pubkey_curve:
        print(f"    曲线: {result.pubkey_curve}")
    print(f"\n  安全评估")
    print(f"    抗量子:         {qs_icon}")
    if result.nist_security_level > 0:
        print(f"    NIST 安全级别:  Level {result.nist_security_level}")
    if result.sig_is_sm:
        print(f"    国密算法:       SM2/SM3 (合规，非抗量子)")
    if result.nist_checks:
        print(f"\n  NIST 数据校验 (真实字节数对照)")
        for check in result.nist_checks:
            print(f"    {check}")
    print("=" * 54 + "\n")


# ═══════════════════════════════════════════════════════════════════
# detect
# ═══════════════════════════════════════════════════════════════════

def cmd_detect(args):
    host = args.host
    port = args.port

    _open_browser(host, port)
    time.sleep(2)
    oqs_available = check_oqs_available()

    # Layer 1 (OQS direct) when available, unless --force-fallback.
    # Otherwise auto-fallback to Layer 2 (CDN inference) instead of refusing.
    use_oqs = oqs_available and not args.force_fallback
    if not use_oqs:
        if args.force_fallback and oqs_available:
            log.info("已强制使用 CDN 推测模式 (--force-fallback)")
        else:
            log.warning("OQS Provider 未安装，自动降级为 CDN 推测模式 (间接)")

    if use_oqs:
        log.info(f"正在检测 {host}:{port} 的 PQC 支持 (Layer 1: OQS 直接实测)...")
        log.info("-" * 50)

        result = detect_pqc_support(host, port, timeout=args.timeout)

        if result.success:
            print("\n" + "=" * 54)
            print(f"  PQC 检测结果 【PQC Detection】")
            print(f"  {host}:{port}")
            print("=" * 54)
            print(f"  TLS 协议:       {result.protocol}")
            print(f"  密码套件:       {result.cipher_suite_name}")
            cs = parse_cipher_suite_name(result.cipher_suite_name)
            print(f"    密钥交换:     {_kex_display(result)}")
            print(f"    身份认证:     {cs.auth_algorithm}")
            print(f"    对称加密:     {cs.symmetric_algorithm}")
            print(f"    哈希算法:     {cs.hash_algorithm}")
            if result.pqc_group_id:
                print(f"    密钥交换组 ID: {result.pqc_group_id}")
            print(f"  PQC 支持:       {'是' if result.pqc_supported else '否'}")
            if result.pqc_supported:
                print(f"  PQC 算法:       {result.pqc_algorithm}")
                print(f"  PQC 组 ID:      {result.pqc_group_id}")
                print(f"  key_share:      {result.pqc_key_share_size} B")
            print(f"  证据:           {result.evidence[:80]}")
            print(f"  握手流量:       {result.handshake_bytes_sent}B发 / {result.handshake_bytes_recv}B收")
            print("=" * 54 + "\n")

            if not args.no_save:
                os.makedirs("output", exist_ok=True)
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                json_path = os.path.join("output", f"detect_{host}_{ts}.json")
                pdf_path = os.path.join("output", f"detect_{host}_{ts}.pdf")
                with open(json_path, "w", encoding="utf-8") as f:
                    json.dump(result_to_dict(result), f, indent=2, ensure_ascii=False)
                build_detect_pdf(result, host, port, pdf_path)
                log.info(f"JSON: {json_path}")
                log.info(f"PDF:  {pdf_path}")

            return 0
        else:
            log.error(f"检测失败: {result.error}")
            return 1
    else:
        log.info(f"正在检测 {host}:{port} 的 PQC 支持 (Layer 2: CDN 推测)...")
        log.info("-" * 50)

        from src.tls_analysis.connection import analyze_tls_connection

        info = analyze_tls_connection(host, port, timeout=args.timeout)

        if info.success:
            print("\n" + "=" * 54)
            print(f"  PQC 检测结果 【PQC Detection】")
            print(f"  {host}:{port}")
            print("=" * 54)
            print(f"  检测方式:       CDN 推测 (间接)")
            print(f"  TLS 协议:       {info.protocol}")
            print(f"  密码套件:       {info.cipher_suite_name}")
            cs = parse_cipher_suite_name(info.cipher_suite_name)
            print(f"    密钥交换:     {_kex_display(info)}")
            print(f"    身份认证:     {cs.auth_algorithm}")
            print(f"    对称加密:     {cs.symmetric_algorithm}")
            print(f"    哈希算法:     {cs.hash_algorithm}")
            print(f"  PQC 推测:       {'是' if info.pqc_capable else '否'}")
            if info.pqc_capable: print(f"  CDN 服务商:     {info.cdn_provider}")
            print(f"  证书主体:       {info.cert_subject.get('commonName', '-')}")
            print(f"  证书颁发:       {info.cert_issuer.get('organizationName', '-')}")
            print("=" * 54 + "\n")
            return 0 if info.pqc_capable else 0
        else:
            log.error(f"连接失败: {info.error}")
            return 1


# ═══════════════════════════════════════════════════════════════════
# pcap
# ═══════════════════════════════════════════════════════════════════

def cmd_pcap(args):
    methods = detect_capture_methods()
    log.info("可用抓包方法:")
    for name, avail in methods.items():
        log.info(f"  {name}: {'可用' if avail else '未找到'}")

    host = args.host
    port = args.port

    _open_browser(host, port)
    time.sleep(2)
    log.info(f"\n正在抓取 {host}:{port} 的 TLS 握手包...")

    cap = capture_tls_handshake(host, port, method=args.method, timeout=args.timeout)

    if cap.success:
        print("\n" + cap.summary())

        vresult = None
        if args.verify:
            vresult = run_pcap_verification(cap)
            vresult.host = f"{host}:{port}"
            print("\n")
            print(format_verification(vresult))

        log.info("\nTLS 记录详情:")
        log.info("-" * 50)
        for i, rec in enumerate(cap.tls_records):
            hs = f" ({rec.handshake_type})" if rec.handshake_type else ""
            direction = "发送" if rec.direction == ">>>" else "接收"
            log.info(f"  {i+1:2d}. {direction}  {rec.content_type}{hs}  [{rec.record_length}B]  {rec.tls_version}")

        os.makedirs("output", exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = os.path.join("output", f"pcap_{host}_{ts}.json")
        pdf_path = os.path.join("output", f"pcap_{host}_{ts}.pdf")

        data = {
            "host": cap.host, "port": cap.port, "timestamp": cap.timestamp,
            "capture_method": cap.capture_method,
            "cipher_suite": cap.cipher_suite, "protocol": cap.protocol,
            "total_sent_bytes": cap.total_sent_bytes, "total_recv_bytes": cap.total_recv_bytes,
            "record_count": cap.record_count,
            "records": [r.to_dict() for r in cap.tls_records],
        }
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        build_pcap_pdf(cap, host, port, pdf_path, vresult=vresult)
        log.info(f"JSON: {json_path}")
        log.info(f"PDF:  {pdf_path}")

        return 0
    else:
        log.error(f"抓包失败: {cap.error}")
        return 1


# ═══════════════════════════════════════════════════════════════════
# scan — unified: capture → parse algorithms → quantum-safety verdict
# ═══════════════════════════════════════════════════════════════════

def cmd_scan(args):
    host = args.host
    port = args.port

    _open_browser(host, port)
    time.sleep(2)
    log.info(f"正在对 {host}:{port} 执行统一安全扫描 (抓包 → 解析算法 → 判抗量子)...")

    result = scan_host(host, port, timeout=args.timeout)

    if not result.success:
        log.error(f"扫描失败: {result.error}")
        return 1

    print("\n" + format_scan(result))

    if not args.no_save:
        os.makedirs("output", exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = os.path.join("output", f"scan_{host}_{ts}.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(scan_to_dict(result), f, indent=2, ensure_ascii=False)
        log.info(f"JSON: {json_path}")

    return 0


# ═══════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="PQC-HTTPS: 抗量子密码 HTTPS 检测与证书分析",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python -m src.cli.main scan cloudflare.com        统一安全扫描 (抓包+算法解析+抗量子判定)
  python -m src.cli.main cert cloudflare.com        证书深度分析
  python -m src.cli.main detect cloudflare.com      PQC 握手检测
  python -m src.cli.main pcap cloudflare.com        深度抓包
        """,
    )

    sub = parser.add_subparsers(dest="command", help="可用命令")

    p = sub.add_parser("cert", help="X.509 证书深度分析（签名算法、公钥类型、安全评估）")
    p.add_argument("host", type=str, help="目标域名 (例: cloudflare.com)")
    p.add_argument("--port", type=int, default=443, help="目标端口 (默认: 443)")
    p.add_argument("--timeout", type=int, default=10, help="超时秒数 (默认: 10)")
    p.add_argument("--no-save", action="store_true", help="不保存 JSON 和 PDF 报告")
    p.add_argument("--verify", action="store_true", help="抗伪造验证：检查签名一致性、算法-公钥匹配")
    p.set_defaults(func=cmd_cert)

    p = sub.add_parser("detect", help="PQC 握手检测 — 判断网站是否支持抗量子密钥交换")
    p.add_argument("host", type=str, help="目标域名 (例: cloudflare.com)")
    p.add_argument("--port", type=int, default=443, help="目标端口 (默认: 443)")
    p.add_argument("--timeout", type=int, default=15, help="超时秒数 (默认: 15)")
    p.add_argument("--force-fallback", action="store_true", help="强制使用 CDN 推测模式")
    p.add_argument("--no-save", action="store_true", help="不保存 JSON 和 PDF 报告")
    p.set_defaults(func=cmd_detect)

    p = sub.add_parser("pcap", help="深度抓包 — TLS 握手 hex dump")
    p.add_argument("host", type=str, help="目标域名")
    p.add_argument("--port", type=int, default=443, help="目标端口 (默认: 443)")
    p.add_argument("--method", type=str, default="auto",
                   choices=["auto", "openssl_msg", "pktmon"],
                   help="抓包方法 (默认: auto)")
    p.add_argument("--timeout", type=int, default=15, help="超时秒数 (默认: 15)")
    p.add_argument("--verify", action="store_true", help="抗伪造验证：随机数质量、证书签名、密钥交换大小")
    p.set_defaults(func=cmd_pcap)

    p = sub.add_parser("scan", help="统一安全扫描 — 一次完成抓包/算法解析/抗量子判定")
    p.add_argument("host", type=str, help="目标域名 (例: cloudflare.com)")
    p.add_argument("--port", type=int, default=443, help="目标端口 (默认: 443)")
    p.add_argument("--timeout", type=int, default=15, help="超时秒数 (默认: 15)")
    p.add_argument("--no-save", action="store_true", help="不保存 JSON 报告")
    p.set_defaults(func=cmd_scan)

    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
