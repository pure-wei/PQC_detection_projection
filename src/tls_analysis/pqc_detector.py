"""Direct PQC detection via OpenSSL s_client with OQS provider.

Layer 1 (this module): Active PQC handshake attempt
  - Runs `openssl s_client` with PQC group (`X25519MLKEM768`)
  - Parses ServerHello hex to check if server selected the PQC group
  - Provides DIRECT evidence: "Server chose PQC group 0x11EC"

Layer 2 (fallback in capture.py): Python ssl + CDN header inference

Usage:
    from .pqc_detector import detect_pqc_support, PQCDetectionResult

    result = detect_pqc_support("cloudflare.com", 443)
    if result.pqc_supported:
        print(f"PQC: {result.pqc_algorithm} ({result.evidence})")
"""

import subprocess
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from .cipher_suite_parser import parse_cipher_suite_name, CipherSuite
from .oqs_provider import (
    check_oqs_available,
    get_oqs_group_flag,
    PQC_GROUP_IDS,
    find_openssl,
)
from ..utils.logger import get_logger

log = get_logger(__name__)

# ── PQC-related keywords for simple string matching fallback ──
PQC_KEYWORDS = [
    "MLKEM", "KYBER", "X25519ML", "FRODO", "BIKE", "HQC",
    "DILITHIUM", "FALCON", "SPHINCS",
]


@dataclass
class PQCDetectionResult:
    """Result of PQC detection for a single host."""

    host: str
    port: int = 443
    success: bool = False
    error: str = ""

    # PQC detection
    pqc_supported: bool = False
    pqc_algorithm: str = ""          # e.g. "X25519MLKEM768"
    pqc_group_id: str = ""           # e.g. "0x11EC"
    pqc_key_share_size: int = 0     # bytes
    method: str = ""                 # "oqs_direct", "cdn_inference", "none"

    # TLS session info
    protocol: str = ""
    cipher_suite_name: str = ""
    cipher_suite: Optional[CipherSuite] = None

    # Handshake stats
    handshake_bytes_sent: int = 0
    handshake_bytes_recv: int = 0
    connect_time_ms: float = 0.0


def _run_openssl_pqc_handshake(
    host: str, port: int = 443, timeout: int = 15
) -> tuple[str, str, int, float]:
    """Run openssl s_client with PQC groups and -msg flag.

    Returns (stdout, stderr, returncode, elapsed_seconds).
    """
    openssl = find_openssl()
    groups = get_oqs_group_flag()

    cmd = [
        openssl, "s_client",
        "-connect", f"{host}:{port}",
        "-servername", host,
        "-groups", groups,
        "-msg",
        "-tlsextdebug",
    ]

    # Simple HTTP request to trigger a complete handshake
    request = f"GET / HTTP/1.1\r\nHost: {host}\r\nAccept: */*\r\nConnection: close\r\n\r\n"

    t0 = time.perf_counter()
    try:
        result = subprocess.run(
            cmd,
            input=request,
            capture_output=True, text=True, timeout=timeout,
            env={**os.environ},
        )
        elapsed = time.perf_counter() - t0
        return result.stdout, result.stderr, result.returncode, elapsed
    except subprocess.TimeoutExpired:
        elapsed = time.perf_counter() - t0
        return "", "Connection timed out", -1, elapsed
    except FileNotFoundError:
        elapsed = time.perf_counter() - t0
        return "", "openssl not found", -2, elapsed
    except Exception as e:
        elapsed = time.perf_counter() - t0
        return "", str(e), -3, elapsed


def _parse_serverhello_key_share(
    stdout: str, stderr: str
) -> Optional[tuple[int, int]]:
    """Parse ServerHello hex to find the selected key_share group.

    Scans the -msg output for the ServerHello handshake message,
    locates the key_share extension (0x0033), and reads the
    server's chosen group.

    TLS 1.3 ServerHello (handshake body, after 4-byte header):
        legacy_version:   2 bytes (0x0303)
        random:          32 bytes
        session_id_len:   1 byte  + N bytes (usually 0x00 = empty)
        cipher_suite:     2 bytes
        compression:      1 byte (0x00)
        ext_total_len:    2 bytes
          [extensions...]
            ext_type:     2 bytes
            ext_body_len: 2 bytes
            ext_body:     N bytes
        ...
        key_share ext (0x0033):
            group:        2 bytes
            ke_len:       2 bytes
            ke_data:      N bytes

    Returns:
        (group_id, key_exchange_size) or None if not found
    """
    combined = stdout + "\n" + stderr
    lines = combined.splitlines()

    # Find ServerHello handshake message: line contains "ServerHello"
    # followed by hex lines. Format:
    #   <<< TLS 1.3, Handshake [length XXXX], ServerHello
    #       02 00 04 b6 03 03 ...
    in_serverhello = False
    hex_lines = []
    for line in lines:
        if "ServerHello" in line and "<<<" in line:
            in_serverhello = True
            continue
        if in_serverhello:
            # Hex data lines start with 4+ spaces and contain hex bytes
            if re.match(r"^\s{4,}[0-9a-fA-F]{2}", line):
                hex_lines.append(line.strip())
            elif len(hex_lines) > 0:
                # First non-hex line after collecting hex — done
                break

    if not hex_lines:
        return None

    # Reconstruct the ServerHello handshake body as bytes
    hex_str = " ".join(hex_lines)
    try:
        sh_bytes = bytes.fromhex(hex_str.replace(" ", ""))
    except ValueError:
        return None

    # --- Parse ServerHello structure ---
    # Handshake header: type(1) + length(3)
    pos = 4  # Skip handshake header

    if pos + 2 > len(sh_bytes):
        return None
    # legacy_version (2 bytes) — skip
    pos += 2

    # random (32 bytes)
    pos += 32

    # session_id (1 byte length + data)
    if pos >= len(sh_bytes):
        return None
    sid_len = sh_bytes[pos]
    pos += 1 + sid_len

    # cipher_suite (2 bytes)
    if pos + 2 > len(sh_bytes):
        return None
    pos += 2

    # compression (1 byte)
    if pos >= len(sh_bytes):
        return None
    pos += 1

    # extensions total length (2 bytes)
    if pos + 2 > len(sh_bytes):
        return None
    ext_total_len = int.from_bytes(sh_bytes[pos : pos + 2], "big")
    pos += 2
    ext_end = pos + ext_total_len

    # Scan extensions for key_share (0x0033)
    while pos + 4 <= min(ext_end, len(sh_bytes)):
        ext_type = int.from_bytes(sh_bytes[pos : pos + 2], "big")
        ext_len = int.from_bytes(sh_bytes[pos + 2 : pos + 4], "big")
        pos += 4

        if pos + ext_len > len(sh_bytes):
            break

        if ext_type == 0x0033:  # key_share
            if ext_len >= 4:  # group(2) + ke_len(2)
                group_id = int.from_bytes(sh_bytes[pos : pos + 2], "big")
                ke_len = int.from_bytes(sh_bytes[pos + 2 : pos + 4], "big")
                ke_total = 4 + ke_len  # group + ke_len + ke_data
                return (group_id, ke_total)
            else:
                return None

        pos += ext_len

    return None


def _textual_pqc_check(stdout: str, stderr: str) -> dict:
    """Fallback: detect PQC via textual output analysis.

    Searches for PQC keywords in cipher suite name, TLS extensions,
    and key exchange info from the openssl s_client output.
    Also tries to find the selected key_share group for evidence
    even when PQC is not supported.
    """
    combined = stdout + "\n" + stderr

    result = {"found": False, "algorithm": "", "evidence": ""}

    # Check cipher suite name for PQC indicators
    cipher_match = re.search(r"Cipher is\s+(\S+)", combined)
    cipher_name = ""
    if cipher_match:
        cipher_name = cipher_match.group(1)
        upper = cipher_name.upper()
        for kw in PQC_KEYWORDS:
            if kw in upper:
                result["found"] = True
                result["algorithm"] = cipher_name
                result["evidence"] = f"PQC cipher suite negotiated: {cipher_name}"
                return result

    # Check tlsextdebug output for PQC groups
    for line in combined.splitlines():
        upper = line.upper()
        for kw in PQC_KEYWORDS:
            if kw in upper:
                result["found"] = True
                result["algorithm"] = line.strip()[:120]
                result["evidence"] = f"PQC extension/keyword found: {line.strip()[:120]}"
                return result

    # ── No PQC found — try to identify what group WAS selected ──
    group_id = _find_selected_group_textual(combined)
    if group_id is not None:
        group_name = PQC_GROUP_IDS.get(group_id, f"Unknown(0x{group_id:04X})")
        result["evidence"] = (
            f"ServerHello key_share: 0x{group_id:04X} ({group_name}) "
            f"— not a PQC group"
        )
    else:
        result["evidence"] = "No PQC indicators found in handshake output"

    return result


def _find_selected_group_textual(combined: str) -> Optional[int]:
    """Try to find the selected key_share group from the handshake output.

    Method 1: tlsextdebug prints lines like:
        shared group: X25519 (0x001d)
    Method 2: Parse ServerHello hex from -msg output for the key_share
        extension (0x0033), same logic as _parse_serverhello_key_share
        but more lenient.
    """
    # Method 1: tlsextdebug
    m = re.search(r'shared group:\s*\S+\s*\(0x([0-9a-fA-F]+)\)', combined)
    if m:
        return int(m.group(1), 16)

    # Method 2: parse ServerHello hex from -msg output
    return _parse_key_share_from_msg_output(combined)


def _parse_key_share_from_msg_output(combined: str) -> Optional[int]:
    """Parse the key_share group from -msg hex output.

    Scans all hex blocks in the output for a key_share extension (0x0033),
    regardless of which TLS message contains it.
    """
    # Collect all hex blocks from the output
    hex_blocks = []
    current_block = []
    for line in combined.splitlines():
        if re.match(r"^\s{4,}[0-9a-fA-F]{2}", line):
            current_block.append(line.strip())
        else:
            if len(current_block) >= 2:
                hex_blocks.append(" ".join(current_block))
            current_block = []

    if len(current_block) >= 2:
        hex_blocks.append(" ".join(current_block))

    for hex_str in hex_blocks:
        try:
            data = bytes.fromhex(hex_str.replace(" ", ""))
        except ValueError:
            continue

        if len(data) < 8:
            continue

        # Scan the entire hex block for key_share extension (0x0033)
        # The extension can appear inside ServerHello at variable offset.
        # Search byte-by-byte for 0x0033 followed by a reasonable length.
        i = 0
        while i + 6 <= len(data):
            if data[i] == 0x00 and data[i + 1] == 0x33:
                ext_len = int.from_bytes(data[i + 2 : i + 4], "big")
                if ext_len >= 4 and i + 4 + ext_len <= len(data):
                    group_id = int.from_bytes(data[i + 4 : i + 6], "big")
                    # Only return if it looks like a valid TLS group ID
                    # (known range: 0x0001–0xFFFF)
                    if 0x0001 <= group_id <= 0xFFFF:
                        return group_id
            i += 1

    return None


def detect_pqc_support(
    host: str,
    port: int = 443,
    timeout: int = 15,
    use_oqs: bool = True,
) -> PQCDetectionResult:
    """Detect PQC support by actively attempting a PQC TLS handshake.

    This is the primary (Layer 1) detection method. It runs openssl
    s_client with PQC groups and parses the ServerHello to see if the
    server actually selected the PQC key exchange.

    Args:
        host: Target hostname
        port: Target port
        timeout: Connection timeout in seconds
        use_oqs: Attempt OQS provider for PQC groups (auto-detected)

    Returns:
        PQCDetectionResult with PQC support status and evidence
    """
    result = PQCDetectionResult(host=host, port=port)

    oqs_available = check_oqs_available() if use_oqs else False

    if not oqs_available:
        result.method = "none"
        result.error = "OQS provider not available"
        return result

    # ── Run OQS handshake ──
    stdout, stderr, rc, elapsed = _run_openssl_pqc_handshake(
        host, port, timeout
    )
    result.connect_time_ms = elapsed * 1000

    combined = stdout + "\n" + stderr
    connected = rc == 0 or "CONNECTED" in combined

    if not connected:
        result.error = stderr.strip()[:200] if stderr else "Connection failed"
        return result

    result.success = True

    # ── Extract cipher suite ──
    cipher_match = re.search(r"Cipher is\s+(\S+)", combined)
    if cipher_match:
        result.cipher_suite_name = cipher_match.group(1)
        result.cipher_suite = parse_cipher_suite_name(result.cipher_suite_name)

    proto_match = re.search(r"New,\s*(TLSv[0-9.]+)", combined)
    if proto_match:
        result.protocol = proto_match.group(1)

    # ── Parse handshake bytes from -msg output ──
    for line in combined.splitlines():
        m = re.search(r">>>.*?\[length\s*(\w+)\]", line)
        if m:
            try:
                result.handshake_bytes_sent += int(m.group(1), 16)
            except ValueError:
                pass
        m = re.search(r"<<<.*?\[length\s*(\w+)\]", line)
        if m:
            try:
                result.handshake_bytes_recv += int(m.group(1), 16)
            except ValueError:
                pass

    # ── Method 1: Parse ServerHello key_share (direct evidence) ──
    ks = _parse_serverhello_key_share(stdout, stderr)
    if ks is not None:
        group_id, ke_size = ks
        if group_id in PQC_GROUP_IDS:
            result.pqc_supported = True
            result.pqc_algorithm = PQC_GROUP_IDS[group_id]
            result.pqc_group_id = f"0x{group_id:04X}"
            result.pqc_key_share_size = ke_size
            result.method = "oqs_direct"
            result.evidence = (
                f"ServerHello key_share: 0x{group_id:04X} "
                f"({PQC_GROUP_IDS[group_id]}, {ke_size} bytes)"
            )
        else:
            result.pqc_supported = False
            result.pqc_group_id = f"0x{group_id:04X}"
            result.method = "oqs_direct"
            result.evidence = (
                f"Server chose non-PQC group 0x{group_id:04X} "
                f"despite PQC being offered"
            )
        return result

    # ── Method 2: Textual fallback ──
    textual = _textual_pqc_check(stdout, stderr)
    if textual["found"]:
        result.pqc_supported = True
        result.pqc_algorithm = textual["algorithm"]
        result.method = "oqs_textual"
        result.evidence = textual["evidence"]
    else:
        result.pqc_supported = False
        result.method = "oqs_textual"
        result.evidence = "No PQC indicators found in handshake output"

    return result


def detect_pqc_batch(
    hosts: list[tuple[str, int]],
    max_workers: int = 3,
    timeout: int = 15,
) -> list[PQCDetectionResult]:
    """Run PQC detection on multiple hosts concurrently.

    Args:
        hosts: List of (host, port) tuples
        max_workers: Concurrent connections
        timeout: Per-connection timeout

    Returns:
        List of PQCDetectionResult
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    oqs_avail = check_oqs_available()
    log.info("=" * 60)
    log.info(f"PQC Direct Detection: {len(hosts)} targets")
    log.info(f"Method: {'OQS Direct (key_share parsing)' if oqs_avail else 'OQS not available'}")
    log.info("=" * 60)

    results = []

    with ThreadPoolExecutor(max_workers=min(max_workers, len(hosts))) as executor:
        future_map = {
            executor.submit(
                detect_pqc_support, host, port, timeout, use_oqs=oqs_avail
            ): (host, port)
            for host, port in hosts
        }

        for future in as_completed(future_map):
            host, port = future_map[future]
            try:
                info = future.result()
                results.append(info)
                if info.success:
                    if info.pqc_supported:
                        log.info(
                            f"  ✓ {host}:{port} → PQC: YES [{info.method}] "
                            f"{info.pqc_algorithm} ({info.pqc_group_id})"
                        )
                    else:
                        log.info(
                            f"  ✓ {host}:{port} → PQC: NO "
                            f"(server chose {info.pqc_group_id or 'non-PQC group'})"
                        )
                else:
                    log.warning(f"  ✗ {host}:{port} → {info.error}")
            except Exception as e:
                log.error(f"  ✗ {host}:{port} → {e}")
                results.append(PQCDetectionResult(
                    host=host, port=port, error=str(e)
                ))

    # Summary
    successful = [r for r in results if r.success]
    pqc_sites = [r for r in successful if r.pqc_supported]
    log.info(f"\nResults: {len(successful)}/{len(hosts)} connected, "
             f"{len(pqc_sites)} with PQC support")
    for r in pqc_sites:
        log.info(f"  {r.host}: {r.pqc_algorithm} [{r.method}]")
    log.info(f"  {r.evidence}")

    return results


def result_to_dict(r: PQCDetectionResult) -> dict:
    """Convert PQCDetectionResult to JSON-serializable dict."""
    return {
        "host": r.host,
        "port": r.port,
        "success": r.success,
        "error": r.error,
        "pqc_supported": r.pqc_supported,
        "pqc_algorithm": r.pqc_algorithm,
        "pqc_group_id": r.pqc_group_id,
        "pqc_key_share_size": r.pqc_key_share_size,
        "method": r.method,
        "evidence": r.evidence,
        "protocol": r.protocol,
        "cipher_suite_name": r.cipher_suite_name,
        "handshake_bytes_sent": r.handshake_bytes_sent,
        "handshake_bytes_recv": r.handshake_bytes_recv,
        "connect_time_ms": round(r.connect_time_ms, 2),
    }
