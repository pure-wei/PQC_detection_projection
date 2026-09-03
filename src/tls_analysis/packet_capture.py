"""TLS handshake packet capture and analysis.

Provides three capture methods (auto-selected by availability):

1. OpenSSL -msg  — Hex dump of TLS records via openssl s_client -msg
   (Always available, requires openssl in PATH)
2. pktmon       — Windows 10/11 built-in packet monitor
   (Available on Windows 10+, no extra install needed)
3. tcpdump      — Standard Unix packet capture
   (Available on Linux/macOS)

Usage:
    from .packet_capture import capture_tls_handshake, TLSPacketCapture

    cap = capture_tls_handshake("cloudflare.com", 443)
    print(f"Records captured: {len(cap.tls_records)}")
    print(f"Total bytes: {cap.total_bytes}")
    cap.save("output/capture.json")
"""

import subprocess
import os
import sys
import re
import json
import time
import hashlib
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from .oqs_provider import find_openssl, get_oqs_group_flag
from ..utils.logger import get_logger

log = get_logger(__name__)


@dataclass
class TLSRecord:
    """A single TLS record captured from the handshake."""
    direction: str = ""         # ">>>" sent, "<<<" received
    content_type: str = ""      # Handshake, ChangeCipherSpec, ApplicationData
    record_length: int = 0
    tls_version: str = ""
    hex_data: str = ""
    record_hex: str = ""        # Full record as hex

    # Parsed handshake type (if Handshake content type)
    handshake_type: str = ""    # ClientHello, ServerHello, Certificate, etc.

    # Full untruncated handshake body bytes (for verification)
    raw_body_bytes: bytes = field(default_factory=bytes)

    def to_dict(self) -> dict:
        return {
            "direction": self.direction,
            "content_type": self.content_type,
            "record_length": self.record_length,
            "tls_version": self.tls_version,
            "handshake_type": self.handshake_type,
            "hex_data": self.hex_data[:200] + ("..." if len(self.hex_data) > 200 else ""),
        }


@dataclass
class TLSPacketCapture:
    """Complete TLS handshake packet capture."""
    host: str
    port: int = 443
    timestamp: str = ""
    success: bool = False
    error: str = ""
    capture_method: str = ""      # "openssl_msg", "pktmon", "tcpdump"

    # Handshake records
    tls_records: list = field(default_factory=list)
    total_sent_bytes: int = 0
    total_recv_bytes: int = 0

    # Summary
    cipher_suite: str = ""
    protocol: str = ""
    server_name: str = ""

    # Raw data
    raw_output: str = ""

    @property
    def total_bytes(self) -> int:
        return self.total_sent_bytes + self.total_recv_bytes

    @property
    def record_count(self) -> int:
        return len(self.tls_records)

    def save(self, path: str):
        """Save capture as JSON."""
        data = {
            "host": self.host,
            "port": self.port,
            "timestamp": self.timestamp,
            "capture_method": self.capture_method,
            "cipher_suite": self.cipher_suite,
            "protocol": self.protocol,
            "total_sent_bytes": self.total_sent_bytes,
            "total_recv_bytes": self.total_recv_bytes,
            "record_count": self.record_count,
            "records": [r.to_dict() for r in self.tls_records],
        }
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        log.info(f"Capture saved to: {path}")

    def summary(self) -> str:
        """Return a human-readable summary."""
        from .cipher_suite_parser import parse_cipher_suite_name
        cs = parse_cipher_suite_name(self.cipher_suite)
        lines = [
            "=" * 60,
            f"TLS Handshake Capture: {self.host}:{self.port}",
            f"Method: {self.capture_method}",
            f"Records: {self.record_count} ({self.total_sent_bytes}B sent, {self.total_recv_bytes}B recv)",
            f"Total: {self.total_bytes}B",
            f"Cipher: {self.cipher_suite}",
            f"  Key Exchange:   {cs.kex_algorithm}",
            f"  Authentication: {cs.auth_algorithm}",
            f"  Encryption:     {cs.symmetric_algorithm}",
            f"  Hash:           {cs.hash_algorithm}",
            f"Protocol: {self.protocol}",
            "-" * 60,
        ]
        for i, rec in enumerate(self.tls_records):
            lines.append(
                f"  {i+1:2d}. {rec.direction} {rec.handshake_type or rec.content_type:<20s} "
                f"{rec.record_length:>5d}B  {rec.tls_version}"
            )
        lines.append("=" * 60)
        return "\n".join(lines)


# ── TLS handshake type constants ──
HANDSHAKE_TYPES = {
    0x01: "ClientHello",
    0x02: "ServerHello",
    0x0B: "Certificate",
    0x0C: "ServerKeyExchange",
    0x0D: "CertificateRequest",
    0x0E: "ServerHelloDone",
    0x0F: "CertificateVerify",
    0x10: "ClientKeyExchange",
    0x14: "Finished",
    0x18: "HelloRetryRequest",
    0xFE: "MessageHash",
}

CONTENT_TYPES = {
    0x14: "ChangeCipherSpec",
    0x15: "Alert",
    0x16: "Handshake",
    0x17: "ApplicationData",
    0x18: "Heartbeat",
}


def _parse_tls_record(hex_str: str, direction: str,
                      record_type: str = "Handshake",
                      record_len: int = 0,
                      tls_version: str = "TLSv1.x") -> Optional[TLSRecord]:
    """Parse a single TLS handshake message from hex string.

    The openssl s_client -msg output emits handshake message bodies
    (NOT full TLS records). Each message starts with:
        HandshakeType (1 byte) | Length (3 bytes) | Body

    Args:
        hex_str: Hex string from openssl -msg output
        direction: ">>>" (sent) or "<<<" (received)
        record_type: Content type label from openssl (Handshake, ChangeCipherSpec, etc.)
        record_len: Record length from the [length XXXX] annotation
    """
    try:
        hex_bytes = bytes.fromhex(hex_str.replace(" ", "").replace("\n", ""))
    except ValueError:
        return None

    if len(hex_bytes) < 1:
        return None

    rec = TLSRecord(
        direction=direction,
        content_type=record_type,
        record_length=record_len,
        record_hex=hex_str[:120],
        tls_version=tls_version,
        raw_body_bytes=hex_bytes,  # full untruncated handshake body
    )

    # Store hex data
    rec.hex_data = hex_str.strip()[:500]

    # Parse handshake type from first byte
    if record_type == "ChangeCipherSpec":
        rec.handshake_type = "ChangeCipherSpec"
    elif record_type == "Handshake" and len(hex_bytes) >= 4:
        hs_type = hex_bytes[0]
        rec.handshake_type = HANDSHAKE_TYPES.get(hs_type, f"Handshake(0x{hs_type:02x})")
    elif record_type == "Handshake" and len(hex_bytes) == 1:
        # Encrypted handshake (Finished) — just 1 byte record
        rec.handshake_type = "Finished"

    return rec


def _capture_via_openssl_msg(host: str, port: int = 443,
                              use_oqs: bool = False,
                              timeout: int = 15) -> TLSPacketCapture:
    """Capture TLS handshake using openssl s_client -msg.

    The -msg flag prints every TLS record as a hex dump:
      >>> TLS 1.3 Handshake [length 0512]
      01 00 05 0e 03 03 ...
    """
    cap = TLSPacketCapture(
        host=host, port=port,
        timestamp=datetime.now().isoformat(),
        capture_method="openssl_msg",
    )

    cmd = [
        find_openssl(), "s_client",
        "-connect", f"{host}:{port}",
        "-servername", host,
        "-msg",
    ]

    if use_oqs:
        # OpenSSL 3.5+ has built-in ML-KEM groups; use the canonical names.
        cmd.extend(["-groups", get_oqs_group_flag()])

    request = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"

    try:
        result = subprocess.run(
            cmd,
            input=request,
            capture_output=True, text=True, timeout=timeout,
            env={**os.environ},
        )
        output = result.stdout + "\n" + result.stderr
        cap.raw_output = output
    except subprocess.TimeoutExpired:
        cap.error = "Connection timed out"
        return cap
    except FileNotFoundError:
        cap.error = "openssl not found in PATH"
        return cap
    except Exception as e:
        cap.error = str(e)
        return cap

    # Parse handshake records from -msg output
    # Format:
    #   >>> TLS 1.0, RecordHeader [length 0005]
    #   >>> TLS 1.3, Handshake [length 060d], ClientHello
    #       01 00 06 09 03 03 ...
    lines = output.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        # Match: ">>> TLS 1.0, RecordHeader [length 0005]" or
        #         ">>> TLS 1.3, Handshake [length 060d], ClientHello"
        m = re.match(
            r'(>>>|<<<)\s+(TLS\s+[\d.]+)\s*,\s*(\S+)\s+\[length\s+(\w+)\](?:,\s*(.+))?',
            line,
        )
        if m:
            direction = m.group(1)
            tls_ver = "TLSv" + m.group(2).split()[-1]  # "TLS 1.3" -> "TLSv1.3"
            record_type = m.group(3)
            label = (m.group(5) or "").strip()

            try:
                record_len = int(m.group(4), 16)
            except ValueError:
                record_len = 0

            # Skip RecordHeader meta-entries (only wrap TLS records)
            if record_type == "RecordHeader":
                i += 1
                continue

            # Collect hex data from following lines
            hex_lines = []
            j = i + 1
            while j < len(lines) and re.match(r'^\s{4,}[0-9a-fA-F]{2}', lines[j]):
                hex_lines.append(lines[j].strip())
                j += 1

            if hex_lines:
                hex_str = " ".join(hex_lines)
                rec = _parse_tls_record(hex_str, direction, record_type, record_len, tls_ver)
                if rec:
                    # Use openssl's label (e.g. "ClientHello") when available
                    if label:
                        rec.handshake_type = label
                    cap.tls_records.append(rec)
                    if direction == ">>>":
                        cap.total_sent_bytes += rec.record_length
                    else:
                        cap.total_recv_bytes += rec.record_length
            i = j
        else:
            i += 1

    # Extract cipher suite from output
    cipher_match = re.search(r'Cipher is\s+(\S+)', output)
    if cipher_match:
        cap.cipher_suite = cipher_match.group(1)

    proto_match = re.search(r'New,\s*(TLSv[0-9.]+)', output)
    if proto_match:
        cap.protocol = proto_match.group(1)

    cap.success = len(cap.tls_records) > 0

    if cap.success:
        log.info(
            f"  Captured {len(cap.tls_records)} TLS records "
            f"({cap.total_sent_bytes}B tx, {cap.total_recv_bytes}B rx)"
        )

    return cap


def _capture_via_pktmon(host: str, port: int = 443,
                         timeout: int = 15) -> TLSPacketCapture:
    """Capture TLS handshake using Windows pktmon.

    pktmon is built into Windows 10/11. No extra install needed.

    CAUTION: Requires Administrator privileges.
    """
    cap = TLSPacketCapture(
        host=host, port=port,
        timestamp=datetime.now().isoformat(),
        capture_method="pktmon",
    )

    # pktmon needs admin rights
    if sys.platform != "win32":
        cap.error = "pktmon is only available on Windows"
        return cap

    # Check if pktmon is available
    try:
        subprocess.run(["pktmon", "help"], capture_output=True, timeout=5)
    except FileNotFoundError:
        cap.error = "pktmon not found (requires Windows 10 build 1809+)"
        return cap

    # pktmon workflow: start → wait → stop → parse
    # Use a temp file for the capture
    etl_file = os.path.join(tempfile.gettempdir(), f"pqc_capture_{int(time.time())}.etl")
    txt_file = etl_file.replace(".etl", ".txt")

    try:
        # 1. Start capture
        log.info(f"  Starting pktmon capture on tcp port {port}...")
        subprocess.run(
            ["pktmon", "start", "--capture", "--pkt-size", "0",
             "--filter", f"tcp port {port}"],
            capture_output=True, timeout=10,
        )

        # 2. Wait briefly — we need to make a connection during this window
        # The caller must have already made (or will make) the TLS connection
        time.sleep(timeout)

        # 3. Stop capture
        subprocess.run(["pktmon", "stop"], capture_output=True, timeout=10)

        # 4. Convert ETL to text
        subprocess.run(
            ["pktmon", "etl2txt", etl_file, "--out", txt_file],
            capture_output=True, timeout=10,
        )

        # 5. Read parsed output
        if os.path.exists(txt_file):
            with open(txt_file, "r", encoding="utf-8", errors="ignore") as f:
                cap.raw_output = f.read()
            cap.success = True
        else:
            cap.error = "pktmon output file not found"

    except subprocess.TimeoutExpired:
        cap.error = "pktmon timed out"
        subprocess.run(["pktmon", "stop"], capture_output=True, timeout=5)
    except Exception as e:
        cap.error = f"pktmon error: {e}"
        try:
            subprocess.run(["pktmon", "stop"], capture_output=True, timeout=5)
        except Exception:
            pass
    finally:
        # Cleanup temp files
        for f in [etl_file, txt_file]:
            try:
                if os.path.exists(f):
                    os.remove(f)
            except Exception:
                pass

    return cap


def capture_tls_handshake(host: str, port: int = 443,
                          method: str = "auto",
                          use_oqs: bool = False,
                          timeout: int = 15) -> TLSPacketCapture:
    """Capture a TLS handshake from a live connection.

    Args:
        host: Target hostname
        port: Target port
        method: "auto" (prefer openssl_msg), "openssl_msg", or "pktmon"
        use_oqs: Use OQS provider for PQC cipher suites
        timeout: Connection timeout in seconds

    Returns:
        TLSPacketCapture with parsed handshake records
    """
    log.info(f"Capturing TLS handshake from {host}:{port}...")

    if method == "pktmon":
        return _capture_via_pktmon(host, port, timeout)

    # Default: openssl_msg (always available)
    return _capture_via_openssl_msg(host, port, use_oqs, timeout)


def detect_capture_methods() -> dict:
    """Check which capture methods are available on this system."""
    methods = {
        "openssl_msg": False,
        "pktmon": False,
        "tcpdump": False,
    }

    # openssl_msg — always check
    try:
        openssl = find_openssl()
        subprocess.run([openssl, "version"], capture_output=True, timeout=5)
        methods["openssl_msg"] = True
    except Exception:
        pass

    # pktmon — Windows only
    if sys.platform == "win32":
        try:
            subprocess.run(["pktmon", "help"], capture_output=True, timeout=5)
            methods["pktmon"] = True
        except Exception:
            pass

    # tcpdump — Unix
    import shutil
    if shutil.which("tcpdump"):
        methods["tcpdump"] = True

    return methods
