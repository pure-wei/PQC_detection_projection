"""OQS / OpenSSL PQC 能力检测 + TLS group ID 对照表。

职责：
1. 定位本机 openssl，优先选择支持 ML-KEM 的构建（检测分岔口的依据）；
2. 维护 PQC / 经典密钥交换组 ID 对照表，用于解读 ServerHello key_share；
3. 输出 OQS 安装指引与状态汇总。

安装 OQS provider（OpenSSL 3.5+ 已内置 ML-KEM，无需此步）：
  MSYS2:  pacman -S mingw-w64-x86_64-liboqs mingw-w64-x86_64-oqs-provider
  源码:   https://github.com/open-quantum-safe/liboqs + oqs-provider
"""

import os
import subprocess
import shutil
import sys

from ..utils.logger import get_logger

log = get_logger(__name__)

# PATH 里常见的 3.0.x 构建（Git Bash / conda 的 3.0.18）没有 ML-KEM，
# 会让 Layer 1 检测静默退化成 CDN 推断，因此额外维护候选列表择优。
_OPENSSL_BINARIES = [
    "D:/Git/mingw64/bin/openssl.exe",
    "C:/msys64/mingw64/bin/openssl.exe",
]

# Windows 下 oqsprovider.dll 的磁盘搜索路径（仅 detect_oqs_status 用）
_MINGW64_SSL_MODULES = [
    "D:/Git/mingw64/lib/ossl-modules",
    "C:/msys64/mingw64/lib/ossl-modules",
]

_EXTRA_SEARCH_PATHS = [
    "C:/Program Files/OpenSSL/lib/ossl-modules",
    "C:/OpenSSL/lib/ossl-modules",
]


def _supports_pqc(openssl: str) -> bool:
    """openssl 能否列出 ML-KEM（内置或 provider 加载均算）。"""
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
    """定位 openssl，优先返回 PQC-capable 的构建。

    逐个探测 PATH 与已知安装路径里的候选，返回第一个支持 ML-KEM 的；
    都不支持时回退第一个候选（保持 Layer 2 可用），没有候选则返回
    "openssl" 交给 subprocess 报错。
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
    """系统是否可用于 PQC TLS 测试（内置 ML-KEM 或 OQS provider）。"""
    openssl = find_openssl()
    if _supports_pqc(openssl):
        return True
    try:
        # 慢路径：显式加载 oqsprovider，按错误文案区分未安装/已加载
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
    """s_client 的 -groups 参数：首选 X25519MLKEM768，附经典回退组。"""
    return "X25519MLKEM768:x25519:secp256r1"


# ── TLS group ID 对照表（IANA / IETF 草案） ────────────────────────────────
# TLS 1.3 的 cipher suite 名不编码密钥交换算法，实际协商的算法只记录在
# ServerHello key_share 的数字组 ID 里，靠下面两张表还原。
# 参考：draft-ietf-tls-hybrid-design / draft-kwiatkowski-tls-ecdhe-mlkem

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
    """组 ID → (算法名, 是否抗量子)。两张表都未命中时按经典处理。"""
    if group_id in PQC_GROUP_IDS:
        return PQC_GROUP_IDS[group_id], True
    if group_id in CLASSICAL_GROUP_IDS:
        return CLASSICAL_GROUP_IDS[group_id], False
    return f"Unknown(0x{group_id:04X})", False


def get_install_instructions() -> str:
    """按平台返回 OQS provider 安装指引。"""
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
    """OQS 状态汇总：可用性、openssl 路径/版本、oqsprovider.dll 是否落盘。"""
    openssl_path = find_openssl()
    available = check_oqs_available()

    dll_found = False
    dll_paths = []
    for d in _MINGW64_SSL_MODULES + _EXTRA_SEARCH_PATHS:
        dll = os.path.join(d, "oqsprovider.dll")
        if os.path.exists(dll):
            dll_found = True
            dll_paths.append(dll)

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
    """把 OQS 状态格式化打印到控制台。"""
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
