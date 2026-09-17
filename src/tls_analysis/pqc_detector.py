"""Layer 1 主动式 PQC 检测：带 PQC 组发起握手，解析 ServerHello key_share。

方法优先级：
  oqs_direct  — 解析 ServerHello key_share 组 ID，直接证据，最可信；
  oqs_textual — 二进制解析失败时在 s_client 文本输出中做关键字兜底。
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


@dataclass
class PQCDetectionResult:
    """单个主机的 PQC 检测结果。"""

    host: str
    port: int = 443
    success: bool = False           # TLS 连接是否成功（不代表支持 PQC）
    error: str = ""
    evidence: str = ""              # 判定依据

    pqc_supported: bool = False     # 服务器是否实际选中了 PQC 组
    pqc_algorithm: str = ""         # 如 "X25519MLKEM768"
    pqc_group_id: str = ""          # 如 "0x11EC"
    pqc_key_share_size: int = 0     # key_share 数据长度（字节）
    method: str = ""                # "oqs_direct" / "oqs_textual" / "none"

    protocol: str = ""              # 如 "TLSv1.3"
    cipher_suite_name: str = ""
    cipher_suite: Optional[CipherSuite] = None

    handshake_bytes_sent: int = 0
    handshake_bytes_recv: int = 0
    connect_time_ms: float = 0.0


def detect_pqc_support(
    host: str,
    port: int = 443,
    timeout: int = 15,
    use_oqs: bool = True,
) -> PQCDetectionResult:
    """对单个主机执行主动式 PQC 检测（主入口）。

    流程：检查 OQS/ML-KEM 可用 → 发起带 PQC 组的握手 → 解析
    ServerHello key_share 得出直接结论；解析失败再用文本关键字兜底。
    """
    result = PQCDetectionResult(host=host, port=port)

    oqs_available = check_oqs_available() if use_oqs else False
    if not oqs_available:
        result.method = "none"
        result.error = "OQS provider not available"
        return result

    stdout, stderr, rc, elapsed = _run_openssl_pqc_handshake(host, port, timeout)
    result.connect_time_ms = elapsed * 1000

    combined = stdout + "\n" + stderr
    if not (rc == 0 or "CONNECTED" in combined):
        result.error = stderr.strip()[:200] if stderr else "Connection failed"
        return result

    result.success = True

    # 提取协商元信息
    cipher_match = re.search(r"Cipher is\s+(\S+)", combined)
    if cipher_match:
        result.cipher_suite_name = cipher_match.group(1)
        result.cipher_suite = parse_cipher_suite_name(result.cipher_suite_name)
    proto_match = re.search(r"New,\s*(TLSv[0-9.]+)", combined)
    if proto_match:
        result.protocol = proto_match.group(1)

    # 统计握手流量：">>>" 客户端发出，"<<<" 服务端发来，length 为十六进制
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

    # 方法 1：ServerHello key_share 解析——直接证据
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
            # 客户端已提供 PQC 选项，服务器仍选经典组——明确不支持
            result.pqc_supported = False
            result.pqc_group_id = f"0x{group_id:04X}"
            result.method = "oqs_direct"
            result.evidence = (
                f"Server chose non-PQC group 0x{group_id:04X} "
                f"despite PQC being offered"
            )
        return result

    # 方法 2：文本关键字兜底
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


def _run_openssl_pqc_handshake(
    host: str, port: int = 443, timeout: int = 15
) -> tuple[str, str, int, float]:
    """执行一次带 PQC 组的 openssl s_client 握手。

    -msg 输出握手报文 hex 原文，-tlsextdebug 输出扩展调试行，
    是后续 key_share 解析的数据源。stdin 注入 HTTP 请求促使
    openssl 完成完整握手后正常退出。

    Returns:
        (stdout, stderr, returncode, elapsed_seconds)
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
    """严格解析：定位 ServerHello hex 块，按 TLS 1.3 布局找 key_share。

    Returns:
        (group_id, key_exchange_size)，找不到时返回 None
    """
    combined = stdout + "\n" + stderr

    # 收集 "<<< ... ServerHello" 标记行之后的 hex 数据行
    in_serverhello = False
    hex_lines = []
    for line in combined.splitlines():
        if "ServerHello" in line and "<<<" in line:
            in_serverhello = True
            continue
        if in_serverhello:
            if re.match(r"^\s{4,}[0-9a-fA-F]{2}", line):
                hex_lines.append(line.strip())
            elif len(hex_lines) > 0:
                break

    if not hex_lines:
        return None

    try:
        sh_bytes = bytes.fromhex(" ".join(hex_lines).replace(" ", ""))
    except ValueError:
        return None

    # TLS 1.3 ServerHello 布局（握手头 4 字节之后）：
    #   legacy_version(2) random(32) session_id(1+N) cipher_suite(2)
    #   compression(1) ext_total_len(2) [ext_type(2) ext_len(2) body(N)]...
    # key_share(0x0033) body: group(2) ke_len(2) ke_data(N)
    pos = 4  # 跳过握手头 type(1)+length(3)

    if pos + 2 > len(sh_bytes):
        return None
    pos += 2  # legacy_version

    pos += 32  # random

    if pos >= len(sh_bytes):
        return None
    sid_len = sh_bytes[pos]
    pos += 1 + sid_len  # session_id

    if pos + 2 > len(sh_bytes):
        return None
    pos += 2  # cipher_suite

    if pos >= len(sh_bytes):
        return None
    pos += 1  # compression

    if pos + 2 > len(sh_bytes):
        return None
    ext_total_len = int.from_bytes(sh_bytes[pos : pos + 2], "big")
    pos += 2
    ext_end = pos + ext_total_len

    while pos + 4 <= min(ext_end, len(sh_bytes)):
        ext_type = int.from_bytes(sh_bytes[pos : pos + 2], "big")
        ext_len = int.from_bytes(sh_bytes[pos + 2 : pos + 4], "big")
        pos += 4

        if pos + ext_len > len(sh_bytes):
            break

        if ext_type == 0x0033:  # key_share
            if ext_len >= 4:
                group_id = int.from_bytes(sh_bytes[pos : pos + 2], "big")
                ke_len = int.from_bytes(sh_bytes[pos + 2 : pos + 4], "big")
                return (group_id, 4 + ke_len)
            else:
                return None

        pos += ext_len

    return None


# ServerHello 二进制解析失败时，用于文本兜底匹配的后量子算法关键字
PQC_KEYWORDS = [
    "MLKEM", "KYBER", "X25519ML", "FRODO", "BIKE", "HQC",
    "DILITHIUM", "FALCON", "SPHINCS",
]


def _textual_pqc_check(stdout: str, stderr: str) -> dict:
    """文本兜底：依次查 cipher suite 名称和 tlsextdebug 行中的 PQC 关键字。

    均未命中时，尝试识别服务器实际选择的（非 PQC）组作为反证。
    """
    combined = stdout + "\n" + stderr

    result = {"found": False, "algorithm": "", "evidence": ""}

    cipher_match = re.search(r"Cipher is\s+(\S+)", combined)
    if cipher_match:
        cipher_name = cipher_match.group(1)
        upper = cipher_name.upper()
        for kw in PQC_KEYWORDS:
            if kw in upper:
                result["found"] = True
                result["algorithm"] = cipher_name
                result["evidence"] = f"PQC cipher suite negotiated: {cipher_name}"
                return result

    for line in combined.splitlines():
        upper = line.upper()
        for kw in PQC_KEYWORDS:
            if kw in upper:
                result["found"] = True
                result["algorithm"] = line.strip()[:120]
                result["evidence"] = f"PQC extension/keyword found: {line.strip()[:120]}"
                return result

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
    """从文本输出推断服务器选中的组 ID。

    优先用 tlsextdebug 打印的 "shared group: X25519 (0x001d)" 行，
    否则对 hex 块做宽松扫描。
    """
    m = re.search(r'shared group:\s*\S+\s*\(0x([0-9a-fA-F]+)\)', combined)
    if m:
        return int(m.group(1), 16)

    return _parse_key_share_from_msg_output(combined)


def _parse_key_share_from_msg_output(combined: str) -> Optional[int]:
    """宽松扫描：在所有 hex 块中逐字节找 "00 33 + 合理长度 + 组 ID" 模式。

    不区分报文类型、容忍任意偏移，作为严格解析的兜底。
    """
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

        i = 0
        while i + 6 <= len(data):
            if data[i] == 0x00 and data[i + 1] == 0x33:
                ext_len = int.from_bytes(data[i + 2 : i + 4], "big")
                if ext_len >= 4 and i + 4 + ext_len <= len(data):
                    group_id = int.from_bytes(data[i + 4 : i + 6], "big")
                    if 0x0001 <= group_id <= 0xFFFF:
                        return group_id
            i += 1

    return None


def detect_pqc_batch(
    hosts: list[tuple[str, int]],
    max_workers: int = 3,
    timeout: int = 15,
) -> list[PQCDetectionResult]:
    """并发检测多个主机，实时打印进度并汇总。"""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    # OQS 探测只做一次，结果传给每个子任务
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

    successful = [r for r in results if r.success]
    pqc_sites = [r for r in successful if r.pqc_supported]
    log.info(f"\nResults: {len(successful)}/{len(hosts)} connected, "
             f"{len(pqc_sites)} with PQC support")
    for r in pqc_sites:
        log.info(f"  {r.host}: {r.pqc_algorithm} [{r.method}]")
    log.info(f"  {r.evidence}")

    return results


def result_to_dict(r: PQCDetectionResult) -> dict:
    """转成可直接 JSON 序列化的 dict。"""
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
