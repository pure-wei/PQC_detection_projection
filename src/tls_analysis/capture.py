"""TLS capture orchestrator: scans multiple target URLs,
extracts TLS parameters, and detects PQC support.

Detection strategy (dual-layer):
  Layer 1: OQS Provider direct test — openssl s_client with PQC groups,
           parses ServerHello key_share for direct evidence
  Layer 2: Python ssl module scan — CDN header inference (fallback)

Usage:
    from .capture import capture_tls_sessions

    df = capture_tls_sessions(targets=[("cloudflare.com", 443)])
    print(df[["host", "pqc_supported", "pqc_method"]])
"""

import json
import os
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

import pandas as pd

from .connection import analyze_tls_connection, session_to_dict, TLSSessionInfo
from .oqs_provider import check_oqs_available
from .pqc_detector import detect_pqc_support, result_to_dict as pqc_result_to_dict
from ..utils.logger import get_logger

log = get_logger(__name__)

# ═══════════════════════════════════════════════════════════════════
# Target website lists
# ═══════════════════════════════════════════════════════════════════

# PQC-capable websites (verified via CDN / OQS direct test)
PQC_ENABLED_SITES = [
    ("cloudflare.com", 443),
    ("blog.cloudflare.com", 443),
    ("github.io", 443),
    ("nist.gov", 443),
    ("aws.amazon.com", 443),
]

# Chinese websites (for domestic algorithm comparison)
CHINESE_SITES = [
    ("baidu.com", 443),
    ("qq.com", 443),
    ("alibaba.com", 443),
    ("jd.com", 443),
    ("bilibili.com", 443),
]

DEFAULT_TARGETS = PQC_ENABLED_SITES + CHINESE_SITES


def _detect_single_target(host: str, port: int, timeout: float, oqs_available: bool) -> dict:
    """Run PQC detection on a single target using the best available method.

    Layer 1 (preferred): OQS direct test — parses ServerHello key_share
    Layer 2 (fallback): Python ssl + CDN header inference
    """
    if oqs_available:
        # ── Layer 1: OQS Direct Detection ──
        try:
            result = detect_pqc_support(host, port, timeout=int(timeout))
            if result.success:
                d = pqc_result_to_dict(result)
                # Add CN-annotated fields for display compatibility
                kex = result.cipher_suite.kex_algorithm if result.cipher_suite else "?"
                enc = result.cipher_suite.symmetric_algorithm if result.cipher_suite else "?"
                d["kex_algorithm"] = kex
                d["symmetric_algorithm"] = enc
                d["hash_algorithm"] = result.cipher_suite.hash_algorithm if result.cipher_suite else "?"
                d["handshake_time_ms"] = round(result.connect_time_ms, 2)

                if result.pqc_supported:
                    log.info(
                        f"  ✓ {host}:{port} → {result.protocol}, "
                        f"KEX={kex}, ENC={enc}, "
                        f"PQC=YES [OQS] {result.pqc_algorithm} "
                        f"(ServerHello key_share: {result.pqc_group_id}, "
                        f"{result.pqc_key_share_size}B)"
                    )
                else:
                    log.info(
                        f"  ✓ {host}:{port} → {result.protocol}, "
                        f"KEX={kex}, ENC={enc}, "
                        f"PQC=NO (server chose {result.pqc_group_id or 'non-PQC'})"
                    )
                return d
            else:
                # OQS failed, fall through to Layer 2
                log.info(f"  OQS detection failed for {host}: {result.error}, falling back to Layer 2")
        except Exception as e:
            log.info(f"  OQS detection error for {host}: {e}, falling back to Layer 2")

    # ── Layer 2: Python ssl + CDN inference ──
    info = analyze_tls_connection(host, port, timeout)
    d = session_to_dict(info)

    if info.success:
        from ..utils.translations import PROTOCOL_CN, KEX_CN, SYM_CN, annotate
        proto_display = annotate(info.protocol, PROTOCOL_CN.get(info.protocol, ""))
        kex = info.cipher_suite.kex_algorithm if info.cipher_suite else "?"
        kex_display = annotate(kex, KEX_CN.get(kex, ""))
        enc = info.cipher_suite.symmetric_algorithm if info.cipher_suite else "?"
        enc_display = annotate(enc, SYM_CN.get(enc, ""))

        cdn_tag = f" [via {info.cdn_provider}]" if info.cdn_provider else ""
        pqc_tag = "PQC 抗量子" if info.pqc_capable else ""
        cn_indicator = f" [{pqc_tag}]" if info.pqc_capable else ""

        log.info(
            f"  ✓ {host}:{port} → {proto_display}, "
            f"KEX={kex_display}, ENC={enc_display}, "
            f"PQC={'YES' if info.pqc_capable else 'NO'}"
            f"{cdn_tag}{cn_indicator}"
        )

        # Enrich with Layer 2 specifics
        d["pqc_method"] = "cdn_inference" if info.pqc_capable else "none"
        d["pqc_evidence"] = info.pqc_evidence
        d["cdn_provider"] = info.cdn_provider
    else:
        log.warning(f"  ✗ {host}:{port} → {info.error}")
        d["pqc_method"] = "none"

    return d


def capture_tls_sessions(
    targets: Optional[list] = None,
    max_workers: int = 5,
    output_dir: str = "output",
    timeout: float = 10.0,
) -> pd.DataFrame:
    """Capture TLS session parameters from multiple target hosts.

    Uses dual-layer PQC detection:
      Layer 1: OQS direct (openssl s_client + key_share parsing)
      Layer 2: Python ssl + CDN header inference

    Args:
        targets: List of (host, port) tuples. Uses DEFAULT_TARGETS if None.
        max_workers: Number of concurrent connections
        output_dir: Directory to save results
        timeout: Per-connection timeout

    Returns:
        DataFrame with TLS session information
    """
    if targets is None:
        targets = DEFAULT_TARGETS

    oqs_available = check_oqs_available()

    log.info("=" * 60)
    log.info(f"TLS Traffic Analysis: Scanning {len(targets)} targets")
    log.info(f"PQC Detection: {'Layer 1 (OQS Direct)' if oqs_available else 'Layer 2 (CDN Inference)'}")
    log.info("=" * 60)

    results = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {
            executor.submit(_detect_single_target, host, port, timeout, oqs_available): (host, port)
            for host, port in targets
        }

        for future in as_completed(future_map):
            host, port = future_map[future]
            try:
                d = future.result()
                results.append(d)
            except Exception as e:
                log.error(f"  ✗ {host}:{port} → {e}")
                results.append({
                    "host": host, "port": port,
                    "success": False, "error": str(e),
                    "pqc_supported": False, "pqc_method": "none",
                })

    df = pd.DataFrame(results)

    # Save results
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    json_path = os.path.join(output_dir, f"tls_capture_{timestamp}.json")
    df.to_json(json_path, orient="records", indent=2)

    csv_path = os.path.join(output_dir, f"tls_capture_{timestamp}.csv")
    df.to_csv(csv_path, index=False)

    # Summary
    successful = df[df["success"] == True]
    log.info(f"\nCaptured {len(successful)}/{len(targets)} successful connections")
    log.info(f"Results saved to: {csv_path}")

    # Algorithm usage summary
    if not successful.empty:
        log.info("\nAlgorithm Usage Summary:")
        log.info("-" * 40)

        if "protocol" in successful.columns:
            for proto, count in successful["protocol"].value_counts().items():
                log.info(f"  {proto}: {count} sites")

        if "kex_algorithm" in successful.columns:
            for kex, count in successful["kex_algorithm"].value_counts().items():
                log.info(f"  Key Exchange '{kex}': {count} sites")

        if "symmetric_algorithm" in successful.columns:
            for enc, count in successful["symmetric_algorithm"].value_counts().items():
                log.info(f"  Encryption '{enc}': {count} sites")

    # PQC Summary
    if "pqc_supported" in successful.columns:
        pqc_count = successful["pqc_supported"].sum()
        log.info(f"\n  PQC Supported: {pqc_count}/{len(successful)} sites")

        if "pqc_method" in successful.columns:
            for method, count in successful["pqc_method"].value_counts().items():
                method_label = {
                    "oqs_direct": "OQS Direct (key_share parsing)",
                    "oqs_textual": "OQS Textual (keyword match)",
                    "cdn_inference": "CDN Inference",
                    "none": "Not detected",
                }.get(method, method)
                log.info(f"    [{method_label}]: {count} sites")

        if "pqc_algorithm" in successful.columns:
            pqc_algos = successful[successful["pqc_supported"] == True]
            if not pqc_algos.empty and "pqc_algorithm" in pqc_algos.columns:
                for algo, count in pqc_algos["pqc_algorithm"].value_counts().items():
                    log.info(f"    Algorithm '{algo}': {count} sites")

    return df
