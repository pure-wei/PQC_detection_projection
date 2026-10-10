# -*- coding: utf-8 -*-
"""抗量子密码（PQC）检测核心逻辑。

参考 PQC-HTTPS 检测平台的两层判定思路，使用 cryptography + pqcrypto 实现，
不依赖外部 openssl 二进制，可被 GUI 直接调用，也可脱离界面复用。

判定分两层，分别下结论：

* 传输层（密钥交换）：主动构造 ClientHello，把混合抗量子组
  X25519MLKEM768 (0x11EC) / SecP256r1MLKEM768 (0x11EB) 排在前面，后面跟经典组兜底；
  读 ServerHello 的 key_share 扩展，看服务器实际选了哪个组 —— 这是直接证据，
  不是推测。再用 IANA/NIST 的 key_share 长度表交叉校验，长度对不上说明
  "标识与数据不符"，判为异常。
* 证书层（身份认证）：解析服务器证书真实字节，取签名算法 OID、公钥算法 OID 与
  原始公钥/签名字节，与 FIPS 203/204/205 参数表比对长度 —— OID 只是标签，
  长度不符即"标识与数据不符，可能伪造"。

主要接口：
    detect(host, port=443, timeout=12, check_cert=True, log=None) -> dict
    probe_tls(host, port=443, timeout=12, groups=None) -> dict
    analyze_cert_der(der) -> dict
    report_rows(report) -> OrderedDict    # 供界面表格显示
    report_to_json(report) -> dict        # 供导出
"""

from __future__ import annotations
import base64

import os
import re
import shutil
import socket
import ssl
import struct
import subprocess
import time
from collections import OrderedDict
from functools import lru_cache

__all__ = [
    "PQC_GROUP_IDS", "CLASSICAL_GROUP_IDS", "HYBRID_GROUP_IDS",
    "KEY_SHARE_BODY_SIZES", "PQC_PARAMS",
    "lookup_group", "build_client_hello", "probe_tls",
    "fetch_server_cert", "analyze_cert_der", "detect",
    "report_rows", "report_to_json", "normalize_target",
    "analyze_file", "analyze_public_key_der",
]

# ===================================================================
# TLS supported_groups 标识表（IANA TLS Supported Groups 注册表）
# ===================================================================

#: 抗量子（含混合）密钥交换组
PQC_GROUP_IDS = {
    # FIPS 203 ML-KEM，独立使用
    0x0200: "MLKEM512",
    0x0201: "MLKEM768",
    0x0202: "MLKEM1024",
    # 混合组：经典 ECDH + ML-KEM（TLS 1.3 事实标准）
    0x11EB: "SecP256r1MLKEM768",
    0x11EC: "X25519MLKEM768",
    0x11ED: "SecP384r1MLKEM1024",
    0x11EE: "X25519MLKEM1024",
    # 旧版 Kyber 草案，现网仍可见
    0x6399: "X25519Kyber768Draft00",
    0x639A: "SecP256r1Kyber768Draft00",
    0x11E6: "X25519Kyber768Draft00 (alt)",
    0x0239: "Kyber512 (round-3)",
    0x023A: "Kyber768 (round-3)",
    0x023C: "Kyber1024 (round-3)",
    # 编码类 KEM 候选
    0x2F39: "FrodoKEM-640-AES",
    0x2F3A: "FrodoKEM-976-AES",
    0x2F3C: "FrodoKEM-1344-AES",
}

#: 经典（非抗量子）密钥交换组
CLASSICAL_GROUP_IDS = {
    0x0016: "secp256k1",
    0x0017: "secp256r1 (P-256)",
    0x0018: "secp384r1 (P-384)",
    0x0019: "secp521r1 (P-521)",
    0x001A: "brainpoolP256r1",
    0x001B: "brainpoolP384r1",
    0x001C: "brainpoolP512r1",
    0x001D: "X25519",
    0x001E: "X448",
    0x0100: "ffdhe2048",
    0x0101: "ffdhe3072",
    0x0102: "ffdhe4096",
    0x0103: "ffdhe6144",
    0x0104: "ffdhe8192",
}

#: 混合组（经典 + 抗量子）：单独标注，部署中出现最多的就是这一类
HYBRID_GROUP_IDS = {0x11EB, 0x11EC, 0x11ED, 0x11EE, 0x6399, 0x639A, 0x11E6}

#: ServerHello key_share 扩展体长度（group(2) + ke_len(2) + ke_data），用于反伪造校验
KEY_SHARE_BODY_SIZES = {
    0x0017: 69,      # secp256r1: 65 + 4
    0x0018: 101,     # secp384r1: 97 + 4
    0x0019: 137,     # secp521r1: 133 + 4
    0x001D: 36,      # X25519: 32 + 4
    0x001E: 60,      # X448: 56 + 4
    0x11EB: 1157,    # SecP256r1MLKEM768: 65 + 1088 + 4
    0x11EC: 1124,    # X25519MLKEM768: 32 + 1088 + 4
    0x11ED: 1669,    # SecP384r1MLKEM1024: 97 + 1568 + 4
    0x11EE: 1604,    # X25519MLKEM1024: 32 + 1568 + 4
    0x0200: 772,     # MLKEM512: 768 + 4
    0x0201: 1092,    # MLKEM768: 1088 + 4
    0x0202: 1572,    # MLKEM1024: 1568 + 4
    0x0239: 772,     # Kyber512 (round 3)
    0x023A: 1092,    # Kyber768 (round 3)
    0x023C: 1572,    # Kyber1024 (round 3)
    0x2F39: 9760,    # FrodoKEM-640-AES
    0x2F3A: 15648,   # FrodoKEM-976-AES
    0x2F3C: 21264,   # FrodoKEM-1344-AES
}

#: 本工具 ClientHello 中提供的 key_share 数据长度
#: （X25519/ECDH 部分用 cryptography，ML-KEM 部分用 pqcrypto 生成真实公钥）
CLIENT_SHARE_SIZES = {
    0x0017: 65,          # P-256 未压缩点
    0x0018: 97,          # P-384 未压缩点
    0x001D: 32,          # X25519
    0x11EB: 65 + 1184,   # SecP256r1 + ML-KEM-768 封装密钥
    0x11EC: 32 + 1184,   # X25519 + ML-KEM-768 封装密钥
    0x11ED: 97 + 1568,   # SecP384r1 + ML-KEM-1024 封装密钥
    0x11EE: 32 + 1568,   # X25519 + ML-KEM-1024 封装密钥
    0x6399: 32 + 1184,   # X25519 + Kyber768Draft00（旧草案，仅证据探测）
    0x0200: 800,         # ML-KEM-512 封装密钥
    0x0201: 1184,        # ML-KEM-768 封装密钥
    0x0202: 1568,        # ML-KEM-1024 封装密钥
}

#: 默认提供的组（顺序即优先级，抗量子混合组放最前）
DEFAULT_GROUPS = [0x11EC, 0x11EB, 0x001D, 0x0017]
#: 纯经典组，用于回退复测
CLASSICAL_ONLY_GROUPS = [0x001D, 0x0017]
# 多轮探测候选组：逐个试探，拼出服务器的 PQC 支持矩阵
MATRIX_PROBE_GROUPS = [0x11EC, 0x11EB, 0x11ED, 0x11EE, 0x0201, 0x0202]

#: 客户端在 ClientHello 中提供的密码套件（TLS 1.3 优先，TLS 1.2 兜底）
CLIENT_CIPHER_SUITES = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0x009C]
#: 客户端提供的签名算法：抗量子（ML-DSA / SLH-DSA，FIPS 204/205）在前，经典在后。
#: 服务器若只配了抗量子证书，客户端不提供这些 code point 会被握手拒绝（alert 40）。
CLIENT_SIG_ALGS = [
    0x0904, 0x0905, 0x0906,                       # ML-DSA-44/65/87
    0x0907, 0x0908, 0x0909, 0x090A, 0x090B, 0x090C,  # SLH-DSA SHA2 系列
    0x0403, 0x0503, 0x0603,                       # ECDSA
    0x0804, 0x0805, 0x0806, 0x0807, 0x0808,       # RSA-PSS / EdDSA
    0x0401,                                       # RSA PKCS#1
]

#: 签名算法 code point → 名称（仅列本工具提供的）
SIG_ALG_NAMES = {
    0x0904: "mldsa44", 0x0905: "mldsa65", 0x0906: "mldsa87",
    0x0907: "slh_dsa_sha2_128s", 0x0908: "slh_dsa_sha2_128f",
    0x0909: "slh_dsa_sha2_192s", 0x090A: "slh_dsa_sha2_192f",
    0x090B: "slh_dsa_sha2_256s", 0x090C: "slh_dsa_sha2_256f",
    0x0403: "ecdsa_secp256r1_sha256", 0x0503: "ecdsa_secp384r1_sha384",
    0x0603: "ecdsa_secp521r1_sha512",
    0x0804: "rsa_pss_rsae_sha256", 0x0805: "rsa_pss_rsae_sha384",
    0x0806: "rsa_pss_rsae_sha512", 0x0807: "ed25519", 0x0808: "ed448",
    0x0401: "rsa_pkcs1_sha256",
}

#: TLS 扩展类型 → 名称（用于展示服务器扩展）
EXT_NAMES = {
    0: "server_name (SNI)", 5: "status_request", 11: "ec_point_formats",
    13: "signature_algorithms", 16: "ALPN", 18: "signed_certificate_timestamp",
    21: "padding", 23: "extended_master_secret", 27: "compress_certificate",
    28: "record_size_limit", 35: "session_ticket", 41: "pre_shared_key",
    42: "early_data", 43: "supported_versions", 44: "cookie",
    45: "psk_key_exchange_modes", 51: "key_share",
    0x001C: "record_size_limit", 0x002B: "supported_versions",
}

#: HelloRetryRequest 的固定 random 值（RFC 8446 4.1.3）
HRR_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")

# ===================================================================
# 证书层：OID 表 + NIST 参数表
# ===================================================================

SIG_ALGORITHM_OIDS = {
    "1.2.840.113549.1.1.5": "RSA-SHA1",
    "1.2.840.113549.1.1.11": "RSA-SHA256",
    "1.2.840.113549.1.1.12": "RSA-SHA384",
    "1.2.840.113549.1.1.13": "RSA-SHA512",
    "1.2.840.113549.1.1.14": "RSA-SHA224",
    "1.2.840.113549.1.1.10": "RSA-PSS",
    "1.2.840.10045.4.1": "ECDSA-SHA1",
    "1.2.840.10045.4.3.1": "ECDSA-SHA224",
    "1.2.840.10045.4.3.2": "ECDSA-SHA256",
    "1.2.840.10045.4.3.3": "ECDSA-SHA384",
    "1.2.840.10045.4.3.4": "ECDSA-SHA512",
    "1.2.840.10040.4.3": "DSA-SHA1",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
    # 国密
    "1.2.156.10197.1.301": "SM2-with-SM3",
    "1.2.156.10197.1.501": "SM2-SM3 (variant)",
    "1.2.156.10197.1.504": "SM2-SHA256",
    # NIST PQC 签名算法（FIPS 204 / 205 与早期 Dilithium、Falcon、SPHINCS+ 标识）
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
    "2.16.840.1.101.3.4.3.20": "SLH-DSA-SHA2-128s",
    "2.16.840.1.101.3.4.3.21": "SLH-DSA-SHA2-128f",
    "2.16.840.1.101.3.4.3.22": "SLH-DSA-SHA2-192s",
    "2.16.840.1.101.3.4.3.23": "SLH-DSA-SHA2-192f",
    "2.16.840.1.101.3.4.3.24": "SLH-DSA-SHA2-256s",
    "2.16.840.1.101.3.4.3.25": "SLH-DSA-SHA2-256f",
    "1.3.6.1.4.1.2.267.7.4.4": "ML-DSA-44 (Dilithium2)",
    "1.3.6.1.4.1.2.267.7.6.5": "ML-DSA-65 (Dilithium3)",
    "1.3.6.1.4.1.2.267.7.8.7": "ML-DSA-87 (Dilithium5)",
    "1.3.9999.3.1": "Falcon-512",
    "1.3.9999.3.4": "Falcon-1024",
    "1.3.9999.6.4.1": "SPHINCS+-SHA2-128s",
    "1.3.9999.6.4.3": "SPHINCS+-SHA2-128f",
    "1.3.9999.6.5.3": "SPHINCS+-SHA2-192s",
    "1.3.9999.6.6.3": "SPHINCS+-SHA2-256s",
}

PUBKEY_ALGORITHM_OIDS = {
    "1.2.840.113549.1.1.1": "RSA",
    "1.2.840.10045.2.1": "EC (ECDSA)",
    "1.2.840.10040.4.1": "DSA",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
    "1.2.156.10197.1.301": "SM2",
    # FIPS 203 ML-KEM（含早期 Kyber 标识）
    "2.16.840.1.101.3.4.4.1": "ML-KEM-512",
    "2.16.840.1.101.3.4.4.2": "ML-KEM-768",
    "2.16.840.1.101.3.4.4.3": "ML-KEM-1024",
    "1.3.6.1.4.1.2.267.5.1.1": "ML-KEM-512 (Kyber512)",
    "1.3.6.1.4.1.2.267.5.2.2": "ML-KEM-768 (Kyber768)",
    "1.3.6.1.4.1.2.267.5.3.3": "ML-KEM-1024 (Kyber1024)",
    # FIPS 204 / 205 签名公钥
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
    "1.3.6.1.4.1.2.267.7.4.4": "ML-DSA-44 (Dilithium2)",
    "1.3.6.1.4.1.2.267.7.6.5": "ML-DSA-65 (Dilithium3)",
    "1.3.6.1.4.1.2.267.7.8.7": "ML-DSA-87 (Dilithium5)",
    "1.3.9999.3.1": "Falcon-512",
    "1.3.9999.3.4": "Falcon-1024",
}

EC_CURVE_OIDS = {
    "1.2.840.10045.3.1.7": "secp256r1 (P-256)",
    "1.3.132.0.34": "secp384r1 (P-384)",
    "1.3.132.0.35": "secp521r1 (P-521)",
    "1.3.132.0.10": "secp256k1",
    "1.2.840.10045.3.1.1": "secp192r1 (P-192)",
    "1.3.101.110": "X25519",
    "1.3.101.111": "X448",
    "1.2.156.10197.1.301": "SM2 (curveSM2)",
}

#: 历史 OID 命名空间参考；不能按此前缀直接判为抗量子（其中也含经典算法）。
PQC_OID_PREFIXES = (
    "2.16.840.1.101.3.4.3.",   # ML-DSA / SLH-DSA
    "2.16.840.1.101.3.4.4.",   # ML-KEM
    "1.3.6.1.4.1.2.267",       # NIST PQC 早期标识
    "1.3.9999",                # Falcon / SPHINCS+ 早期标识
    "2.16.840.1.114027",       # 复合签名
    "1.3.6.1.4.1.22554",       # BSI / 德国 PQC
)

#: OID -> (名称, 公钥字节数, 签名字节数, NIST 安全等级)
#: 依据 FIPS 203（ML-KEM）/ FIPS 204（ML-DSA）/ FIPS 205（SLH-DSA）与 Falcon 参数表。
#: OID 只是标签，必须用真实字节长度交叉校验才能确认算法。
PQC_PARAMS = {
    "2.16.840.1.101.3.4.4.1": ("ML-KEM-512", 800, 768, 1),
    "2.16.840.1.101.3.4.4.2": ("ML-KEM-768", 1184, 1088, 3),
    "2.16.840.1.101.3.4.4.3": ("ML-KEM-1024", 1568, 1568, 5),
    "1.3.6.1.4.1.2.267.5.1.1": ("ML-KEM-512", 800, 768, 1),
    "1.3.6.1.4.1.2.267.5.2.2": ("ML-KEM-768", 1184, 1088, 3),
    "1.3.6.1.4.1.2.267.5.3.3": ("ML-KEM-1024", 1568, 1568, 5),
    "2.16.840.1.101.3.4.3.17": ("ML-DSA-44", 1312, 2420, 2),
    "2.16.840.1.101.3.4.3.18": ("ML-DSA-65", 1952, 3309, 3),
    "2.16.840.1.101.3.4.3.19": ("ML-DSA-87", 2592, 4627, 5),
    "1.3.6.1.4.1.2.267.7.4.4": ("ML-DSA-44", 1312, 2420, 2),
    "1.3.6.1.4.1.2.267.7.6.5": ("ML-DSA-65", 1952, 3309, 3),
    "1.3.6.1.4.1.2.267.7.8.7": ("ML-DSA-87", 2592, 4627, 5),
    "2.16.840.1.101.3.4.3.20": ("SLH-DSA-SHA2-128s", 32, 7856, 1),
    "2.16.840.1.101.3.4.3.21": ("SLH-DSA-SHA2-128f", 32, 17088, 1),
    "2.16.840.1.101.3.4.3.22": ("SLH-DSA-SHA2-192s", 48, 16224, 3),
    "2.16.840.1.101.3.4.3.23": ("SLH-DSA-SHA2-192f", 48, 35664, 3),
    "2.16.840.1.101.3.4.3.24": ("SLH-DSA-SHA2-256s", 64, 29792, 5),
    "2.16.840.1.101.3.4.3.25": ("SLH-DSA-SHA2-256f", 64, 49856, 5),
    "1.3.9999.3.1": ("Falcon-512", 897, 666, 1),
    "1.3.9999.3.4": ("Falcon-1024", 1793, 1280, 5),
    "1.3.9999.6.4.1": ("SPHINCS+-SHA2-128s", 32, 7856, 1),
    "1.3.9999.6.4.3": ("SPHINCS+-SHA2-128f", 32, 17088, 1),
    "1.3.9999.6.5.3": ("SPHINCS+-SHA2-192s", 48, 16224, 3),
    "1.3.9999.6.6.3": ("SPHINCS+-SHA2-256s", 64, 29792, 5),
}


# ===================================================================
# 公共小工具
# ===================================================================

def lookup_group(group_id: int):
    """TLS 组 ID → (名称, 是否抗量子)。混合组同样算抗量子。"""
    if group_id in PQC_GROUP_IDS:
        name = PQC_GROUP_IDS[group_id]
        if group_id in HYBRID_GROUP_IDS:
            name = "%s（混合）" % name
        return name, True
    if group_id in CLASSICAL_GROUP_IDS:
        return CLASSICAL_GROUP_IDS[group_id], False
    return "未知组(0x%04X)" % group_id, False


def _is_pqc_oid(oid: str) -> bool:
    # The NIST signature arc also contains classical DSA / ECDSA with SHA-3.
    # Unknown OIDs cannot establish PQC support merely by sharing a prefix.
    return bool(oid) and oid in PQC_PARAMS


def normalize_target(text: str):
    """把用户输入（域名 / URL / host:port）规范化为 (host, port)。"""
    s = (text or "").strip()
    if not s:
        raise ValueError("请输入目标域名或 URL")
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0].split("?", 1)[0].strip()
    port = None
    if s.startswith("["):                       # IPv6 字面量
        host, _, rest = s[1:].partition("]")
        if rest.startswith(":"):
            port = rest[1:]
    elif ":" in s:
        host, _, port = s.partition(":")
    else:
        host = s
    host = host.strip()
    if not host:
        raise ValueError("无法从输入中解析出域名")
    if port:
        try:
            port = int(port)
        except ValueError:
            raise ValueError("端口不是合法数字：%s" % port)
    else:
        port = 443
    if not (0 < port < 65536):
        raise ValueError("端口超出范围：%d" % port)
    return host, port


def _u16(v: int) -> bytes:
    return struct.pack(">H", v)


def _ext(etype: int, body: bytes) -> bytes:
    """构造一个 TLS 扩展（type + len + body）。"""
    return _u16(etype) + _u16(len(body)) + body


def _cipher_name(code: int) -> str:
    try:
        from modules import tls_parser
        return tls_parser._cipher_name_for(code)
    except Exception:
        return "0x%04X" % code


# ===================================================================
# 传输层：主动构造 ClientHello 探测
# ===================================================================

def _client_share_bytes(group_id: int) -> bytes:
    """只取 key_share 数据（不需要私钥时使用）。"""
    return _client_share_and_key(group_id)[0]


def _client_share_and_key(group_id: int):
    """按组生成 key_share 数据与对应的**私钥材料**。

    返回 (share_bytes, key_handle)：
      key_handle 为 None（仅旧版未实现组使用随机填充）或
      ("x25519", priv) / ("ec", priv) / ("mlkem", priv) / ("hybrid", kem_priv, "x25519"|"ec", ec_priv)
    深度验证需要这些私钥来验证服务器握手（ML-KEM 解封装 + ECDH）。
    """
    n = CLIENT_SHARE_SIZES.get(group_id, 32)
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric import ec, x25519

    def _x():
        k = x25519.X25519PrivateKey.generate()
        return k, k.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def _ec(kind):
        curve = ec.SECP384R1() if kind == 0x0018 else ec.SECP256R1()
        k = ec.generate_private_key(curve)
        return k, k.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)

    def _kem(size):
        from pqcrypto.kem import ml_kem_512, ml_kem_768, ml_kem_1024
        module = {800: ml_kem_512, 1184: ml_kem_768,
                  1568: ml_kem_1024}[size]
        return module.generate_keypair()  # (public, secret)

    if group_id == 0x11EC:            # ML-KEM-768 公钥 + X25519 公钥
        ks, kem_secret = _kem(1184)
        xk, xs = _x()
        return ks + xs, ("hybrid", kem_secret, "x25519", xk)
    if group_id == 0x11EB:            # SecP256r1 公钥 + ML-KEM-768 公钥
        ks, kem_secret = _kem(1184)
        ek, es = _ec(0x0017)
        return es + ks, ("hybrid", kem_secret, "ec", ek)
    if group_id == 0x11ED:            # SecP384r1 公钥 + ML-KEM-1024 公钥
        ks, kem_secret = _kem(1568)
        ek, es = _ec(0x0018)
        return es + ks, ("hybrid", kem_secret, "ec", ek)
    if group_id == 0x11EE:            # ML-KEM-1024 公钥 + X25519 公钥
        ks, kem_secret = _kem(1568)
        xk, xs = _x()
        return ks + xs, ("hybrid", kem_secret, "x25519", xk)
    if group_id in (0x0200, 0x0201, 0x0202):
        size = {0x0200: 800, 0x0201: 1184, 0x0202: 1568}[group_id]
        ks, kem_secret = _kem(size)
        return ks, ("mlkem", kem_secret)
    if group_id == 0x001D:
        xk, xs = _x()
        return xs, ("x25519", xk)
    if group_id in (0x0017, 0x0018):
        ek, es = _ec(group_id)
        return es, ("ec", ek)
    return os.urandom(n), None


def build_client_hello(host: str, groups=None, share_groups=None, return_keys=False):
    """构造一条包含抗量子组的 TLS 1.3 ClientHello 记录。

    groups 决定 supported_groups 的顺序（优先级），share_groups 决定实际附带
    key_share 的组；默认两者一致。分开设置可用于"只声明不给 share"的探测方式
    （服务器若支持该组会用 HelloRetryRequest 要求补上）。
    return_keys=True 时返回 (record_bytes, {group_id: 私钥材料})，供深度验证服务器握手。
    """
    groups = list(groups if groups is not None else DEFAULT_GROUPS)
    share_groups = list(share_groups if share_groups is not None else groups)
    ciphers = CLIENT_CIPHER_SUITES
    sigs = CLIENT_SIG_ALGS
    random = os.urandom(32)
    session_id = os.urandom(32)

    exts = b""
    hn = host.encode("idna") if host.isascii() else host.encode("utf-8")
    exts += _ext(0, _u16(len(hn) + 3) + b"\x00" + _u16(len(hn)) + hn)      # SNI
    exts += _ext(10, _u16(2 * len(groups)) + b"".join(_u16(g) for g in groups))
    exts += _ext(13, _u16(2 * len(sigs)) + b"".join(_u16(s) for s in sigs))
    alpn = b"".join(bytes([len(p)]) + p for p in (b"h2", b"http/1.1"))
    exts += _ext(16, _u16(len(alpn)) + alpn)                              # ALPN
    exts += _ext(43, b"\x04\x03\x04\x03\x03")                             # supported_versions
    exts += _ext(45, b"\x01\x01")                                         # psk_key_exchange_modes
    shares = b""
    keys = {}
    for g in share_groups:
        share, key = _client_share_and_key(g)
        if key is not None:
            keys[g] = key
        shares += _u16(g) + _u16(len(share)) + share
    exts += _ext(51, _u16(len(shares)) + shares)                          # key_share

    body = b"\x03\x03" + random + bytes([len(session_id)]) + session_id
    body += _u16(2 * len(ciphers)) + b"".join(_u16(c) for c in ciphers)
    body += b"\x01\x00" + _u16(len(exts)) + exts
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    record = b"\x16\x03\x01" + _u16(len(hs)) + hs
    if return_keys:
        return record, keys
    return record


def _split_records(data: bytes):
    """拆分 TLS 记录，返回 [(type, version, payload)]。"""
    recs, off = [], 0
    while off + 5 <= len(data):
        typ = data[off]
        ver = struct.unpack(">H", data[off + 1:off + 3])[0]
        ln = struct.unpack(">H", data[off + 3:off + 5])[0]
        if off + 5 + ln > len(data):
            break
        recs.append((typ, ver, data[off + 5:off + 5 + ln]))
        off += 5 + ln
    return recs


def _record_label(rtype: int, payload: bytes = b"") -> str:
    """记录类型标签（只做帧说明，不做内容解析）。"""
    name = {20: "change_cipher_spec", 21: "alert", 22: "handshake",
            23: "application_data"}.get(rtype, "type=%d" % rtype)
    if rtype == 23:
        name += "（加密）"
    if rtype == 21 and len(payload) >= 2:
        name += " level=%d description=%d" % (payload[0], payload[1])
    return name


def hexdump(data: bytes, width: int = 16) -> str:
    """标准 hex dump（偏移 + 十六进制 + ASCII）。"""
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hexs = " ".join("%02X" % b for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append("%08X  %-*s  %s" % (off, width * 3 - 1, hexs, text))
    return "\n".join(lines) if lines else "(空)"


def _split_handshakes(payload: bytes):
    msgs, off = [], 0
    while off + 4 <= len(payload):
        mt = payload[off]
        ln = int.from_bytes(payload[off + 1:off + 4], "big")
        if off + 4 + ln > len(payload):
            break
        msgs.append((mt, payload[off + 4:off + 4 + ln]))
        off += 4 + ln
    return msgs


def _parse_server_hello(body: bytes):
    """解析 ServerHello：版本 / 选套件 / 扩展列表。"""
    d = {"legacy_version": 0, "random": b"", "cipher_code": 0, "exts": []}
    if len(body) < 38:
        return d
    d["legacy_version"] = struct.unpack(">H", body[0:2])[0]
    d["random"] = body[2:34]
    sid_len = body[34]
    off = 35 + sid_len
    if off + 3 > len(body):
        return d
    d["cipher_code"] = struct.unpack(">H", body[off:off + 2])[0]
    off += 3                                    # + compression method
    if off + 2 > len(body):
        return d
    ext_len = struct.unpack(">H", body[off:off + 2])[0]
    off += 2
    end = min(off + ext_len, len(body))
    while off + 4 <= end:
        etype = struct.unpack(">H", body[off:off + 2])[0]
        elen = struct.unpack(">H", body[off + 2:off + 4])[0]
        d["exts"].append((etype, body[off + 4:off + 4 + elen]))
        off += 4 + elen
    return d


def describe_client_hello(host: str, groups, share_groups=None, total_len: int = 0):
    """描述我们发出的 ClientHello（供交互细节展示）。"""
    groups = list(groups if groups is not None else DEFAULT_GROUPS)
    share_groups = list(share_groups if share_groups is not None else groups)
    d = OrderedDict()
    d["record_len"] = total_len
    d["handshake_len"] = max(0, total_len - 9)      # 5 字节记录头 + 4 字节握手头
    d["sni"] = host
    d["versions"] = "TLS 1.3 (0x0304), TLS 1.2 (0x0303)"
    d["cipher_suites"] = ["0x%04X %s" % (c, _cipher_name(c)) for c in CLIENT_CIPHER_SUITES]
    d["sig_algs"] = ["0x%04X %s" % (c, SIG_ALG_NAMES.get(c, "?")) for c in CLIENT_SIG_ALGS]
    d["groups"] = []
    for g in groups:
        name, is_pqc = lookup_group(g)
        size = CLIENT_SHARE_SIZES.get(g, 0)
        d["groups"].append({
            "id": g, "name": name, "pqc": is_pqc, "share_len": size,
            "share_sent": g in share_groups,
        })
    d["key_share_note"] = ("ML-KEM 公钥由 pqcrypto、ECDHE 公钥由 cryptography 现场生成；"
                           "X25519 混合组为 ML-KEM ‖ ECDHE，P-256/P-384 混合组为 ECDHE ‖ ML-KEM")
    return d


def describe_server_hello(sh: dict, body_len: int, alert: bytes = b""):
    """描述服务器回的 ServerHello（供交互细节展示）。"""
    d = OrderedDict()
    d["body_len"] = body_len
    d["legacy_version"] = "0x%04X" % sh.get("legacy_version", 0)
    d["is_hrr"] = (sh.get("random", b"") == HRR_RANDOM)
    d["random_hex"] = sh.get("random", b"").hex()
    d["cipher_code"] = sh.get("cipher_code", 0)
    d["cipher_name"] = _cipher_name(sh.get("cipher_code", 0))
    d["extensions"] = []
    for etype, ev in sh.get("exts", []):
        item = {"id": etype, "name": EXT_NAMES.get(etype, "0x%04X" % etype), "len": len(ev),
                "summary": ""}
        if etype == 43 and len(ev) >= 2:
            ver = struct.unpack(">H", ev[0:2])[0]
            item["summary"] = {0x0304: "TLS 1.3", 0x0303: "TLS 1.2"}.get(
                ver, "0x%04X" % ver)
        elif etype == 51 and len(ev) >= 2:
            gid = struct.unpack(">H", ev[0:2])[0]
            name, is_pqc = lookup_group(gid)
            if len(ev) == 2:                     # HelloRetryRequest：只有组号
                item["summary"] = "HelloRetryRequest 请求的组 = 0x%04X %s" % (gid, name)
            else:
                klen = struct.unpack(">H", ev[2:4])[0]
                expect = KEY_SHARE_BODY_SIZES.get(gid, 0)
                item["summary"] = ("group=0x%04X %s，ke_len=%d，扩展体=%d 字节"
                                   "%s" % (gid, name, klen, len(ev),
                                           "" if not expect else
                                           "（规范 %d 字节 → %s）" % (
                                               expect,
                                               "一致" if len(ev) == expect else "不一致")))
        elif etype == 0 and len(ev) > 3:
            item["summary"] = "status_request 应答"
        else:
            item["summary"] = ev.hex()[:40] + ("…" if len(ev) > 20 else "")
        d["extensions"].append(item)
    if alert:
        d["alert"] = "alert level=%d description=%d" % (alert[0], alert[1])
    return d


def _probe_once(host: str, port: int = 443, timeout: float = 12.0, groups=None):
    """单次主动握手探测（不处理 HRR 重试）。"""
    groups = list(groups if groups is not None else DEFAULT_GROUPS)
    out = {
        "host": host, "port": port, "ok": False, "error": "", "alert": "",
        "hrr": False, "protocol": "", "cipher_suite": "", "cipher_code": 0,
        "group_id": 0, "group_name": "", "is_pqc": False,
        "key_share_body": 0, "expect_body": 0, "size_ok": None,
        "tls12": False,
        "offered": ["%s (0x%04X)" % (lookup_group(g)[0], g) for g in groups],
        "elapsed_ms": 0.0, "bytes_recv": 0,
    }
    t0 = time.perf_counter()
    hello = build_client_hello(host, groups)
    out["client_hello"] = describe_client_hello(host, groups, groups, len(hello))
    trace = [{"dir": "→", "kind": "handshake（ClientHello）", "raw": hello}]
    data, server_hello, alert = b"", None, b""
    consumed = 0
    t_connect = t_sent = t_first = None
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            t_connect = time.perf_counter()
            sock.settimeout(timeout)
            sock.sendall(hello)
            t_sent = time.perf_counter()
            while True:
                try:
                    chunk = sock.recv(8192)
                except socket.timeout:
                    break
                if not chunk:
                    break
                if t_first is None:
                    t_first = time.perf_counter()
                data += chunk
                while consumed + 5 <= len(data):
                    typ = data[consumed]
                    ln = struct.unpack(">H", data[consumed + 3:consumed + 5])[0]
                    if consumed + 5 + ln > len(data):
                        break
                    raw = data[consumed:consumed + 5 + ln]
                    payload = data[consumed + 5:consumed + 5 + ln]
                    consumed += 5 + ln
                    trace.append({"dir": "←", "kind": _record_label(typ, payload), "raw": raw})
                    if typ == 21 and len(payload) >= 2:
                        alert = payload
                    elif typ == 22:
                        for mt, mbody in _split_handshakes(payload):
                            if mt == 2 and server_hello is None:
                                server_hello = mbody
                if server_hello is not None or alert:
                    break
                if len(data) > 262144:
                    break
    except Exception as e:
        out["error"] = "%s: %s" % (type(e).__name__, e)
        out["elapsed_ms"] = (time.perf_counter() - t0) * 1000
        return out

    out["trace"] = trace
    out["elapsed_ms"] = (time.perf_counter() - t0) * 1000
    out["bytes_recv"] = len(data)
    out["timings"] = {
        "connect_ms": ((t_connect or t0) - t0) * 1000,
        "server_hello_ms": ((t_first - t_sent) * 1000) if (t_first and t_sent) else None,
        "total_ms": out["elapsed_ms"],
    }
    if alert:
        out["alert"] = "level=%d description=%d" % (alert[0], alert[1])
        out["server_alert"] = {"level": alert[0], "description": alert[1]}
        out["error"] = "服务器返回告警（alert %d）" % alert[1]
        return out
    if server_hello is None:
        out["error"] = "未收到 ServerHello（服务器未完成握手应答）"
        return out

    sh = _parse_server_hello(server_hello)
    out["server_hello"] = describe_server_hello(sh, len(server_hello))
    out["hrr"] = (sh["random"] == HRR_RANDOM)
    out["protocol"] = {0x0304: "TLS 1.3", 0x0303: "TLS 1.2",
                       0x0302: "TLS 1.1", 0x0301: "TLS 1.0"}.get(
        sh["legacy_version"], "0x%04X" % sh["legacy_version"])
    out["cipher_code"] = sh["cipher_code"]
    out["cipher_suite"] = _cipher_name(sh["cipher_code"])
    for etype, ev in sh["exts"]:
        if etype == 43 and len(ev) >= 2:      # supported_versions：服务器选中的版本
            ver = struct.unpack(">H", ev[0:2])[0]
            out["protocol"] = {0x0304: "TLS 1.3", 0x0303: "TLS 1.2"}.get(
                ver, "0x%04X" % ver)
        elif etype == 51 and len(ev) >= 2:    # key_share：服务器选中的组
            gid = struct.unpack(">H", ev[0:2])[0]
            name, is_pqc = lookup_group(gid)
            out["group_id"] = gid
            out["group_name"] = name
            out["is_pqc"] = is_pqc
            out["key_share_body"] = len(ev)
            out["expect_body"] = KEY_SHARE_BODY_SIZES.get(gid, 0)
            if out["expect_body"]:
                out["size_ok"] = (len(ev) == out["expect_body"])
            out["ok"] = True
    if out["ok"] and out["hrr"]:
        # HelloRetryRequest 里 key_share 只带"请求重试的组"，没有服务端公钥，
        # 因此不做长度校验（长度表针对正式 ServerHello）。
        out["key_share_body"] = 0
        out["expect_body"] = 0
        out["size_ok"] = None
    if not out["ok"]:
        # 收到了 ServerHello 但没有 key_share：TLS 1.2 应答（或不支持 TLS 1.3）。
        # ML-KEM 混合组只在 TLS 1.3 下存在，因此这是明确的"不支持"结论。
        out["tls12"] = True
        out["error"] = ("服务器以 %s 应答，ServerHello 无 key_share 扩展 —— "
                        "未使用 TLS 1.3 抗量子混合组" % (out["protocol"] or "旧版本"))
    return out


def probe_tls(host: str, port: int = 443, timeout: float = 12.0, groups=None):
    """主动握手探测；遇到 HelloRetryRequest 时按服务器要求自动重试一次。"""
    groups = list(groups if groups is not None else DEFAULT_GROUPS)
    out = _probe_once(host, port, timeout, groups)
    if not (out.get("hrr") and out.get("group_id")):
        return out

    # HelloRetryRequest：服务器要求补某个组的 key_share。
    # 重新建连，把该组放到最前并附带真实 share，再探测一次。
    want = out["group_id"]
    if want not in CLIENT_SHARE_SIZES:
        out["error"] = ("服务器要求 HelloRetryRequest 的组 0x%04X 无法生成 key_share"
                        % want)
        return out
    retry_groups = [want] + [g for g in groups if g != want]
    retry = _probe_once(host, port, timeout, retry_groups)
    retry["hrr_first"] = True
    retry["hrr_requested_group"] = "%s (0x%04X)" % (lookup_group(want)[0], want)
    retry["trace"] = (out.get("trace") or []) + [{"dir": "↻",
                    "kind": "HelloRetryRequest 后重试", "raw": b""}] + (retry.get("trace") or [])
    return retry


def probe_group_matrix(host: str, port: int = 443, timeout: float = 8.0,
                       log=None, skip_groups=None, cancel_event=None):
    """多轮分组探测：逐个试探候选 PQC 组，返回服务器支持矩阵。

    对每个候选组 G 单独发起一次 ClientHello（groups=[G, X25519]），
    服务器选中 G 即为支持；选中 X25519 即为不支持。一次一条连接，
    结果不参与总体结论，只作为附加证据展示。
    """
    def _log(msg):
        if log:
            try:
                log(msg)
            except Exception:
                pass

    skip = set(skip_groups or [])
    rows = []
    for gid in MATRIX_PROBE_GROUPS:
        if cancel_event is not None and cancel_event.is_set():
            break
        if gid in skip:
            continue
        name, _ = lookup_group(gid)
        r = probe_tls(host, port, timeout, groups=[gid, 0x001D])
        supported = bool(r.get("ok") and r.get("group_id") == gid)
        rows.append({
            "group_id": "0x%04X" % gid, "group_name": name,
            "supported": supported,
            "selected": ("%s (0x%04X)" % (r.get("group_name"), r.get("group_id")))
                        if r.get("ok") else "—",
            "size_ok": r.get("size_ok"),
            "note": "" if r.get("ok") else (r.get("error") or "未取得应答"),
        })
        _log("支持矩阵：%s → %s" % (name, "支持" if supported else "不支持"))
    return rows


# ===================================================================
# 证书层：抓取并解析服务器证书真实字节
# ===================================================================

# ===================================================================
# 深度验证：验证服务器 TLS 1.3 握手飞行中的 Finished 与 CertificateVerify
# ===================================================================

#: 密码套件 -> (哈希名, 哈希长度, AEAD 密钥长度, AEAD 类型)
_TLS13_SUITES = {
    0x1301: ("sha256", 32, 16, "aes"),
    0x1302: ("sha384", 48, 32, "aes"),
    0x1303: ("sha256", 32, 32, "chacha"),
}

HANDSHAKE_NAMES = {
    1: "ClientHello", 2: "ServerHello", 4: "NewSessionTicket", 5: "EndOfEarlyData",
    8: "EncryptedExtensions", 11: "Certificate", 13: "CertificateRequest",
    15: "CertificateVerify", 20: "Finished", 24: "KeyUpdate", 254: "MessageHash",
}


def _hkdf_extract(salt: bytes, ikm: bytes, hash_name: str) -> bytes:
    import hmac as _hmac
    return _hmac.new(salt, ikm, hash_name).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int, hash_name: str) -> bytes:
    import hmac as _hmac
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = _hmac.new(prk, t + info + bytes([i]), hash_name).digest()
        okm += t
        i += 1
    return okm[:length]


def _expand_label(secret: bytes, label: bytes, context: bytes, length: int,
                  hash_name: str) -> bytes:
    """HKDF-Expand-Label（RFC 8446 §7.1）。"""
    full = b"tls13 " + label
    info = (length.to_bytes(2, "big") + bytes([len(full)]) + full
            + bytes([len(context)]) + context)
    return _hkdf_expand(secret, info, length, hash_name)


def _derive_secret(secret: bytes, label: bytes, transcript: bytes,
                   hash_name: str, hash_len: int) -> bytes:
    import hashlib
    th = hashlib.new(hash_name, transcript).digest()
    return _expand_label(secret, label, th, hash_len, hash_name)


def _tls13_handshake_keys(shared: bytes, cipher: int, transcript_ch_sh: bytes) -> dict:
    """按 RFC 8446 派生握手阶段的服务器流量密钥。"""
    hash_name, hlen, klen, aead = _TLS13_SUITES[cipher]
    zeros = b"\x00" * hlen
    early = _hkdf_extract(zeros, zeros, hash_name)
    derived = _derive_secret(early, b"derived", b"", hash_name, hlen)
    hs_secret = _hkdf_extract(derived, shared, hash_name)
    s_hs = _derive_secret(hs_secret, b"s hs traffic", transcript_ch_sh, hash_name, hlen)
    return {
        "hash_name": hash_name, "hash_len": hlen, "aead": aead,
        "server_key": _expand_label(s_hs, b"key", b"", klen, hash_name),
        "server_iv": _expand_label(s_hs, b"iv", b"", 12, hash_name),
        "server_finished_key": _expand_label(s_hs, b"finished", b"", hlen, hash_name),
    }


def _aead_decrypt(aead: str, key: bytes, nonce: bytes, aad: bytes, ct: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    if aead == "aes":
        return AESGCM(key).decrypt(nonce, ct, aad)
    return ChaCha20Poly1305(key).decrypt(nonce, ct, aad)


def _nonce(iv: bytes, seq: int) -> bytes:
    s = b"\x00" * 4 + seq.to_bytes(8, "big")
    return bytes(a ^ b for a, b in zip(iv, s))


def _derive_shared(group_id: int, server_share: bytes, key_handle):
    """用我们的私钥与服务器的 key_share 算出共享密钥（混合组为两段拼接）。"""
    from cryptography.hazmat.primitives.asymmetric import ec, x25519
    from pqcrypto.kem import ml_kem_512, ml_kem_768, ml_kem_1024

    kem_module = {
        0x0200: ml_kem_512, 0x0201: ml_kem_768, 0x0202: ml_kem_1024,
        0x11EC: ml_kem_768, 0x11EB: ml_kem_768,
        0x11ED: ml_kem_1024, 0x11EE: ml_kem_1024,
    }.get(group_id)
    kind = key_handle[0]
    if kind == "x25519":
        return key_handle[1].exchange(
            x25519.X25519PublicKey.from_public_bytes(server_share))
    if kind == "ec":
        priv = key_handle[1]
        pub = ec.EllipticCurvePublicKey.from_encoded_point(priv.curve, server_share)
        return priv.exchange(ec.ECDH(), pub)
    if kind == "mlkem":
        if len(server_share) != kem_module.CIPHERTEXT_SIZE:
            raise ValueError("ML-KEM 封装密文长度不符")
        return kem_module.decrypt(key_handle[1], server_share)
    if kind == "hybrid":
        _, kem, ec_kind, ec_priv = key_handle
        if ec_kind == "x25519":
            ecdh_len = 32
        else:
            ecdh_len = 65 if isinstance(ec_priv.curve, ec.SECP256R1) else 97

        def _ecdh(pub_bytes):
            if ec_kind == "x25519":
                return ec_priv.exchange(x25519.X25519PublicKey.from_public_bytes(pub_bytes))
            return ec_priv.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(
                ec_priv.curve, pub_bytes))

        if len(server_share) != kem_module.CIPHERTEXT_SIZE + ecdh_len:
            raise ValueError("混合组 key_share 长度不符")
        if group_id in (0x11EC, 0x11EE):
            kem_ct, ec_pub = server_share[:-ecdh_len], server_share[-ecdh_len:]
            return kem_module.decrypt(kem, kem_ct) + _ecdh(ec_pub)
        ec_pub, kem_ct = server_share[:ecdh_len], server_share[ecdh_len:]
        return _ecdh(ec_pub) + kem_module.decrypt(kem, kem_ct)
    raise ValueError("不支持的密钥交换组 0x%04X" % group_id)


def _replay_private_material(key_handle):
    """Serialize a generated client private key for same-session replay."""
    from cryptography.hazmat.primitives import serialization
    if key_handle[0] == "mlkem":
        return base64.b64encode(key_handle[1]).decode("ascii")
    if key_handle[0] == "x25519":
        raw = key_handle[1].private_bytes(serialization.Encoding.Raw,
                                          serialization.PrivateFormat.Raw,
                                          serialization.NoEncryption())
        return base64.b64encode(raw).decode("ascii")
    if key_handle[0] == "ec":
        der = key_handle[1].private_bytes(serialization.Encoding.DER,
                                          serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption())
        return base64.b64encode(der).decode("ascii")
    if key_handle[0] == "hybrid":
        _, kem_secret, classical_kind, classical_key = key_handle
        classical = _replay_private_material(
            ("x25519", classical_key) if classical_kind == "x25519" else ("ec", classical_key))
        classical_algorithm = ("X25519" if classical_kind == "x25519" else
                               "P-256" if isinstance(classical_key.curve, ec.SECP256R1)
                               else "P-384")
        return {"ecdh_algorithm": classical_algorithm,
                "kem_private_key": base64.b64encode(kem_secret).decode("ascii"),
                "ecdh_private_key": classical}
    raise RuntimeError("cannot serialize this client private key")


def _cert_chain_from_certificate(body: bytes):
    """严格解析 TLS 1.3 Certificate 列表，保留同一次握手的全部证书。"""
    if not body:
        raise ValueError("Certificate 消息为空")
    off = 1 + body[0]
    if off + 3 > len(body):
        raise ValueError("Certificate 上下文或列表长度截断")
    end = off + 3 + int.from_bytes(body[off:off + 3], "big")
    off += 3
    if end != len(body):
        raise ValueError("Certificate 列表长度与消息不符")
    chain = []
    while off < end:
        if off + 3 > end:
            raise ValueError("Certificate 证书长度截断")
        cert_len = int.from_bytes(body[off:off + 3], "big")
        off += 3
        if not cert_len or off + cert_len + 2 > end:
            raise ValueError("Certificate 证书内容截断或为空")
        chain.append(body[off:off + cert_len])
        off += cert_len
        ext_len = int.from_bytes(body[off:off + 2], "big")
        off += 2
        ext_end = off + ext_len
        if ext_end > end:
            raise ValueError("Certificate 扩展列表截断")
        while off < ext_end:
            if off + 4 > ext_end:
                raise ValueError("Certificate 扩展头截断")
            size = int.from_bytes(body[off + 2:off + 4], "big")
            off += 4 + size
            if off > ext_end:
                raise ValueError("Certificate 扩展内容截断")
    if not chain:
        raise ValueError("服务器 Certificate 列表为空")
    return chain


def _first_cert_from_certificate(body: bytes):
    """兼容旧调用方：从严格解析的列表中返回叶子证书。"""
    return _cert_chain_from_certificate(body)[0]


def _verify_cert_verify(pub, scheme: int, data: bytes, sig: bytes,
                        cert_der: bytes = None) -> bool:
    """用证书公钥验证 CertificateVerify 签名。"""
    from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, ed25519, ed448
    if scheme in (0x0904, 0x0905, 0x0906) and cert_der is not None:
        oid, public, _ = spki_from_der(cert_der)
        expected_oid = {0x0904: "2.16.840.1.101.3.4.3.17",
                        0x0905: "2.16.840.1.101.3.4.3.18",
                        0x0906: "2.16.840.1.101.3.4.3.19"}[scheme]
        if oid != expected_oid:
            raise ValueError("CertificateVerify 方案与证书公钥算法不一致")
        from pqcrypto.sign import ml_dsa_44, ml_dsa_65, ml_dsa_87
        module = {0x0904: ml_dsa_44, 0x0905: ml_dsa_65, 0x0906: ml_dsa_87}[scheme]
        if len(public) != module.PUBLIC_KEY_SIZE or len(sig) != module.SIGNATURE_SIZE:
            raise InvalidSignature("ML-DSA 公钥或签名长度不符")
        if not module.verify(public, data, sig):
            raise InvalidSignature("ML-DSA CertificateVerify 验签失败")
        return True
    expected_type = ({0x0403: ec.EllipticCurvePublicKey, 0x0503: ec.EllipticCurvePublicKey,
                      0x0603: ec.EllipticCurvePublicKey, 0x0804: rsa.RSAPublicKey,
                      0x0805: rsa.RSAPublicKey, 0x0806: rsa.RSAPublicKey,
                      0x0401: rsa.RSAPublicKey, 0x0807: ed25519.Ed25519PublicKey,
                      0x0808: ed448.Ed448PublicKey}).get(scheme)
    if expected_type is None and scheme not in (0x0904, 0x0905, 0x0906):
        raise UnsupportedAlgorithm("暂不支持的签名方案 0x%04X" % scheme)
    if pub is None and cert_der is not None:
        from cryptography import x509
        pub = x509.load_der_x509_certificate(cert_der).public_key()
    if expected_type is not None and not isinstance(pub, expected_type):
        raise ValueError("CertificateVerify 方案与证书公钥类型不一致")
    if scheme in (0x0403, 0x0503, 0x0603):
        h = {0x0403: hashes.SHA256(), 0x0503: hashes.SHA384(),
             0x0603: hashes.SHA512()}[scheme]
        pub.verify(sig, data, ec.ECDSA(h))
    elif scheme in (0x0804, 0x0805, 0x0806):
        h = {0x0804: hashes.SHA256(), 0x0805: hashes.SHA384(),
             0x0806: hashes.SHA512()}[scheme]
        pub.verify(sig, data, padding.PSS(mgf=padding.MGF1(h),
                                          salt_length=h.digest_size), h)
    elif scheme == 0x0401:
        pub.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())
    elif scheme in (0x0807, 0x0808):          # Ed25519 / Ed448
        pub.verify(sig, data)
    elif scheme in (0x0904, 0x0905, 0x0906):  # ML-DSA-44/65/87（FIPS 204）
        pub.verify(sig, data)
    else:
        raise UnsupportedAlgorithm("暂不支持的签名方案 0x%04X" % scheme)
    return True


def deep_verify(host: str, port: int = 443, timeout: float = 12.0,
                groups=None, log=None) -> dict:
    """验证服务器侧 TLS 1.3 握手飞行，不发送客户端 Finished。

    与 probe_tls 的区别：这里解密并验证服务器握手飞行 —— 用自己的 ML-KEM 私钥解封装、
    ECDH 算出共享密钥，按 RFC 8446 派生握手密钥，解密服务器的加密飞行，
    并校验 Finished（HMAC）与 CertificateVerify（用证书公钥验签）。
    结论从"服务器声明"升级为"密码学确认"。
    """
    import hashlib
    import hmac as _hmac

    def _log(msg):
        if log:
            try:
                log(msg)
            except Exception:
                pass

    groups = list(groups if groups is not None else DEFAULT_GROUPS)
    res = {
        "host": host, "port": port, "ok": False, "verified": False, "error": "",
        "group_id": 0, "group_name": "", "is_pqc": False,
        "cipher_code": 0, "cipher_suite": "", "key_share_body": 0,
        "expect_body": 0, "size_ok": None, "hrr": False, "alert": "",
        "finished_verified": False, "cert_verify": {}, "cert_der": None,
        "cert_chain_der": [], "verification_status": "unverified",
        "verification_error_kind": "",
        "cert_subject": "", "cert_issuer": "", "cert_sig_algorithm": "",
        "server_messages": [], "handshake_bytes_sent": 0, "handshake_bytes_recv": 0,
        "offered": ["%s (0x%04X)" % (lookup_group(g)[0], g) for g in groups],
        "client_hello": None, "server_hello": None,
        "replay_bundle": {"session": {}, "certificates": [], "encrypted_records": []},
        "timings": {"connect_ms": 0.0, "server_hello_ms": 0.0, "verify_ms": 0.0},
    }
    t0 = time.perf_counter()
    hello, keys = build_client_hello(host, groups, return_keys=True)
    res["client_hello"] = describe_client_hello(host, groups, groups, len(hello))
    res["handshake_bytes_sent"] = len(hello)
    trace = [{"dir": "→", "kind": "handshake（ClientHello）", "raw": hello}]

    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        res["timings"]["connect_ms"] = (time.perf_counter() - t0) * 1000
        sock.settimeout(timeout)
        sock.sendall(hello)
        t_sent = time.perf_counter()

        conn_data = b""
        consumed = 0
        pending = []          # 已解析但还没处理的记录 [(type, payload, header)]
        idx = 0
        closed = {"v": False}

        def _pump():
            nonlocal conn_data
            try:
                chunk = sock.recv(16384)
            except socket.timeout:
                closed["v"] = True
                return False
            if not chunk:
                closed["v"] = True
                return False
            conn_data += chunk
            return True

        def _new_records():
            nonlocal consumed
            while consumed + 5 <= len(conn_data):
                rtype = conn_data[consumed]
                rlen = int.from_bytes(conn_data[consumed + 3:consumed + 5], "big")
                if consumed + 5 + rlen > len(conn_data):
                    break
                payload = conn_data[consumed + 5:consumed + 5 + rlen]
                header = conn_data[consumed:consumed + 5]
                consumed += 5 + rlen
                yield rtype, payload, header

        def _fetch_more():
            """读更多数据；返回 False 表示连接结束或超时。"""
            if not _pump():
                return False
            for rec in _new_records():
                pending.append(rec)
            return True

        # ---- 阶段 1：读明文记录，拿到完整 ServerHello ----
        hs_buf, sh_body, sh_msg = b"", None, None
        while sh_msg is None:
            if idx < len(pending):
                rtype, payload, _h = pending[idx]
                idx += 1
                trace.append({"dir": "←", "kind": _record_label(rtype, payload),
                              "raw": _h + payload})
                if rtype == 21 and len(payload) >= 2:
                    res["alert"] = "level=%d description=%d" % (payload[0], payload[1])
                    raise RuntimeError("服务器返回告警（alert %d）" % payload[1])
                if rtype == 22:
                    hs_buf += payload
                # ServerHello 到齐就立刻停下，后面的 CCS / 加密记录留给阶段 2 按序解密
                if len(hs_buf) >= 4 and hs_buf[0] == 2:
                    ln = int.from_bytes(hs_buf[1:4], "big")
                    if len(hs_buf) >= 4 + ln:
                        sh_msg, sh_body = hs_buf[:4 + ln], hs_buf[4:4 + ln]
                        hs_buf = hs_buf[4 + ln:]
                        break
                continue
            if not _fetch_more():
                raise RuntimeError("未收到完整 ServerHello（连接已结束或超时）")

        res["timings"]["server_hello_ms"] = (time.perf_counter() - t_sent) * 1000
        sh = _parse_server_hello(sh_body)
        res["server_hello"] = describe_server_hello(sh, len(sh_body))
        res["hrr"] = (sh["random"] == HRR_RANDOM)
        if res["hrr"]:
            raise RuntimeError("服务器要求 HelloRetryRequest，深度验证未完成")
        res["cipher_code"] = sh["cipher_code"]
        res["cipher_suite"] = _cipher_name(sh["cipher_code"])
        if sh["cipher_code"] not in _TLS13_SUITES:
            raise RuntimeError("服务器未协商 TLS 1.3 套件（%s）" % res["cipher_suite"])

        server_share = b""
        for etype, ev in sh["exts"]:
            if etype == 51 and len(ev) >= 4:
                gid = struct.unpack(">H", ev[0:2])[0]
                klen = struct.unpack(">H", ev[2:4])[0]
                server_share = ev[4:4 + klen]
                res["group_id"] = gid
                res["group_name"], res["is_pqc"] = lookup_group(gid)
                res["key_share_body"] = len(ev)
                res["expect_body"] = KEY_SHARE_BODY_SIZES.get(gid, 0)
                if res["expect_body"]:
                    res["size_ok"] = (len(ev) == res["expect_body"])
        if not server_share:
            raise RuntimeError("ServerHello 中没有 key_share 扩展")
        key_handle = keys.get(res["group_id"])
        if key_handle is None:
            raise RuntimeError("该组的客户端 share 为随机填充，无法完成握手")

        # ---- 阶段 2：派生握手密钥并解密服务器飞行 ----
        _log("深度验证：用 %s 私钥与服务器 key_share 计算共享密钥…" % res["group_name"])
        shared = _derive_shared(res["group_id"], server_share, key_handle)
        transcript = hello[5:] + sh_msg
        k = _tls13_handshake_keys(shared, sh["cipher_code"], transcript)
        res["shared_secret_len"] = len(shared)
        algorithms = {0x001D: "X25519", 0x0017: "P-256", 0x0018: "P-384",
                      0x0200: "ML-KEM-512", 0x0201: "ML-KEM-768",
                      0x0202: "ML-KEM-1024", 0x11EB: "SecP256r1MLKEM768",
                      0x11EC: "X25519MLKEM768", 0x11ED: "SecP384r1MLKEM1024",
                      0x11EE: "X25519MLKEM1024"}
        res["replay_bundle"].update({
            "session": {"source": "deep-detection", "host": host, "port": port,
                        "same_handshake": True, "protocol": "TLS 1.3",
                        "cipher_suite": res["cipher_suite"]},
            "key_exchange": {
                "algorithm": algorithms.get(res["group_id"], res["group_name"]),
                "server_public_key": base64.b64encode(server_share).decode("ascii"),
                "private_key": _replay_private_material(key_handle),
                "expected_shared_secret": base64.b64encode(shared).decode("ascii")}})

        seq, finished, cv_body, cert_der = 0, None, None, None
        transcript_after_cert = None
        while finished is None:
            if idx >= len(pending):
                if not _fetch_more():
                    raise RuntimeError("未收到服务器 Finished（连接中断或超时）")
                continue
            rtype, payload, header = pending[idx]
            idx += 1
            if rtype == 20:                 # ChangeCipherSpec（兼容性用）
                trace.append({"dir": "←", "kind": _record_label(rtype, payload),
                              "raw": header + payload})
                continue
            if rtype == 21 and len(payload) >= 2:
                trace.append({"dir": "←", "kind": _record_label(rtype, payload),
                              "raw": header + payload})
                raise RuntimeError("握手过程中收到告警 %d" % payload[1])
            if rtype != 23:
                trace.append({"dir": "←", "kind": _record_label(rtype, payload),
                              "raw": header + payload})
                continue
            pt = _aead_decrypt(k["aead"], k["server_key"],
                               _nonce(k["server_iv"], seq), header, payload)
            seq += 1
            record_algorithm = ("ChaCha20-Poly1305" if k["aead"] != "aes"
                                else "AES-128-GCM" if len(k["server_key"]) == 16
                                else "AES-256-GCM")
            res["replay_bundle"]["encrypted_records"].append({
                "algorithm": record_algorithm,
                "key": base64.b64encode(k["server_key"]).decode("ascii"),
                "nonce": base64.b64encode(_nonce(k["server_iv"], seq - 1)).decode("ascii"),
                "aad": base64.b64encode(header).decode("ascii"),
                "ciphertext": base64.b64encode(payload).decode("ascii"),
                "expected_plaintext": base64.b64encode(pt).decode("ascii")})
            # TLSInnerPlaintext = content ‖ content_type(1) ‖ 零填充
            pt = pt.rstrip(b"\x00")
            if not pt:
                continue
            content_type, content = pt[-1], pt[:-1]
            trace.append({"dir": "←", "kind": _record_label(rtype, payload),
                          "raw": header + payload, "plain": pt,
                          "content_type": content_type})
            if content_type != 22:           # 只拼接握手内容
                continue
            hs_buf += content
            while len(hs_buf) >= 4:
                mt = hs_buf[0]
                ln = int.from_bytes(hs_buf[1:4], "big")
                if len(hs_buf) < 4 + ln:
                    break
                body = hs_buf[4:4 + ln]
                msg = hs_buf[:4 + ln]
                hs_buf = hs_buf[4 + ln:]
                if mt != 20:                     # Finished 本身不计入转录
                    transcript += msg
                res["server_messages"].append({
                    "type": mt, "name": HANDSHAKE_NAMES.get(mt, "0x%02X" % mt),
                    "len": ln})
                if mt == 11:
                    chain = _cert_chain_from_certificate(body)
                    cert_der = chain[0]
                    res["cert_der"] = cert_der
                    res["cert_chain_der"] = chain
                    res["replay_bundle"]["certificates"] = [
                        base64.b64encode(item).decode("ascii") for item in chain]
                    transcript_after_cert = transcript
                elif mt == 15:
                    cv_body = body
                elif mt == 20:
                    finished = body
                    break

        # ---- 阶段 3：校验 Finished ----
        th = hashlib.new(k["hash_name"], transcript).digest()
        expect = _hmac.new(k["server_finished_key"], th, k["hash_name"]).digest()
        res["finished_verified"] = (finished == expect)
        res["finished_len"] = len(finished)
        if not res["finished_verified"]:
            res["verification_status"] = "failed"
            res["verification_error_kind"] = "invalid"
            res["error"] = "Finished HMAC 校验失败"

        # ---- 阶段 4：校验 CertificateVerify（用证书公钥验签） ----
        if cv_body and cert_der:
            from cryptography import x509
            from cryptography.exceptions import UnsupportedAlgorithm
            if len(cv_body) < 4:
                raise ValueError("CertificateVerify 头截断")
            scheme = struct.unpack(">H", cv_body[0:2])[0]
            slen = struct.unpack(">H", cv_body[2:4])[0]
            if slen != len(cv_body) - 4:
                raise ValueError("CertificateVerify 签名长度不符")
            sig = cv_body[4:4 + slen]
            th_cert = hashlib.new(k["hash_name"], transcript_after_cert or b"").digest()
            content = (b"\x20" * 64 + b"TLS 1.3, server CertificateVerify" + b"\x00"
                       + th_cert)
            cert = x509.load_der_x509_certificate(cert_der)
            ok = False
            err = ""
            error_kind = ""
            try:
                ok = _verify_cert_verify(None, scheme, content, sig, cert_der=cert_der)
            except (UnsupportedAlgorithm, ImportError) as e:
                error_kind = "unsupported"
                err = "%s: %s" % (type(e).__name__, e)
            except Exception as e:
                error_kind = "invalid"
                err = "%s: %s" % (type(e).__name__, e)
            res["cert_verify"] = {
                "scheme": "0x%04X" % scheme,
                "scheme_name": SIG_ALG_NAMES.get(scheme, "未知方案"),
                "sig_len": len(sig), "verified": ok, "error": err,
                "error_kind": error_kind,
            }
            res["replay_bundle"]["handshake_signature"] = {
                "scheme": "0x%04X" % scheme,
                "signed_content": base64.b64encode(content).decode("ascii"),
                "signature": base64.b64encode(sig).decode("ascii")}
            if not ok and res["verification_error_kind"] != "invalid":
                res["verification_status"] = "unsupported" if error_kind == "unsupported" else "failed"
                res["verification_error_kind"] = error_kind
                res["error"] = err
            try:
                cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                res["cert_subject"] = cn[0].value if cn else cert.subject.rfc4514_string()
            except Exception:
                pass
            try:
                cn = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                res["cert_issuer"] = cn[0].value if cn else cert.issuer.rfc4514_string()
            except Exception:
                pass
            res["cert_der"] = cert_der
            res["cert_sig_algorithm"] = SIG_ALGORITHM_OIDS.get(
                cert.signature_algorithm_oid.dotted_string,
                cert.signature_algorithm_oid.dotted_string)

        res["ok"] = True
        res["verified"] = bool(res["finished_verified"]
                               and (res["cert_verify"].get("verified", False)))
        if res["verified"]:
            res["verification_status"] = "verified"
        res["timings"]["verify_ms"] = (time.perf_counter() - t0) * 1000
    except Exception as e:
        res["error"] = "%s: %s" % (type(e).__name__, e)
        from cryptography.exceptions import InvalidSignature, InvalidTag
        if isinstance(e, (ValueError, InvalidSignature, InvalidTag)):
            res["verification_status"] = "failed"
            res["verification_error_kind"] = "invalid"
    finally:
        try:
            if sock is not None:
                sock.close()
        except Exception:
            pass
    res["timings"]["total_ms"] = (time.perf_counter() - t0) * 1000
    res["trace"] = trace
    return res

def fetch_server_cert(host: str, port: int = 443, timeout: float = 12.0):
    """取回服务器叶子证书 DER 与会话信息。

    先用 Python ssl 握手；若失败（典型情况：服务器用的是 ML-DSA 抗量子证书，
    而本机 Python 的 OpenSSL 3.0 不认这种签名算法，握手会在 CertificateVerify
    阶段失败），自动回退到本机 openssl s_client -showcerts 抓取证书。
    """
    t0 = time.perf_counter()
    try:
        info = _fetch_cert_python(host, port, timeout)
    except Exception as py_err:
        info = _fetch_cert_openssl(host, port, timeout)   # 失败会抛出
        info["fallback_reason"] = "%s: %s" % (type(py_err).__name__, py_err)
    info["fetch_ms"] = (time.perf_counter() - t0) * 1000
    return info


#: 常见 OpenSSL 安装位置（Windows / macOS / Linux）
_OPENSSL_PATHS = (
    "D:/Git/mingw64/bin/openssl.exe",
    "C:/Program Files/Git/mingw64/bin/openssl.exe",
    "C:/msys64/mingw64/bin/openssl.exe",
    "C:/Program Files/OpenSSL/bin/openssl.exe",
    "/usr/local/bin/openssl",
    "/opt/homebrew/bin/openssl",
    "/usr/bin/openssl",
)


@lru_cache(maxsize=1)
def find_openssl() -> str:
    """定位 openssl 可执行文件，找不到返回空串。"""
    found = shutil.which("openssl")
    if found:
        return found
    for path in _OPENSSL_PATHS:
        if os.path.exists(path):
            return path
    return ""


def _fetch_cert_openssl(host: str, port: int = 443, timeout: float = 12.0):
    """回退方案：用本机 openssl s_client -showcerts 抓证书（支持 ML-DSA 等新算法）。"""
    exe = find_openssl()
    if not exe:
        raise RuntimeError("本机未找到 openssl，无法抓取该证书")
    cmd = [exe, "s_client", "-connect", "%s:%d" % (host, port),
           "-servername", host, "-showcerts"]
    proc = subprocess.run(cmd, input=b"", capture_output=True, timeout=max(10.0, timeout + 8))
    out = (proc.stdout or b"").decode("utf-8", "replace") + \
          (proc.stderr or b"").decode("utf-8", "replace")
    pems = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", out, re.S)
    if not pems:
        raise RuntimeError("openssl 未取回证书：%s" % out.strip().splitlines()[-1][:80]
                           if out.strip() else "openssl 无输出")
    chain = [load_cert_bytes(p.encode()) for p in pems]
    info = {"der": chain[0], "chain": chain, "protocol": "", "cipher": "",
            "alpn": "", "via": "openssl"}
    mm = re.search(r"^\s*Protocol\s*:\s*(\S+)", out, re.M)
    if mm:
        info["protocol"] = mm.group(1)
    mc = re.search(r"Cipher is (\S+)", out)
    if mc:
        info["cipher"] = mc.group(1)
    return info


def _fetch_cert_python(host: str, port: int = 443, timeout: float = 12.0):
    """用 Python ssl 完成一次常规握手，取回叶子证书 DER 与会话信息。"""
    from cryptography.hazmat.primitives import serialization
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_alpn_protocols(["h2", "http/1.1"])
    except Exception:
        pass
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as ss:
            der = ss.getpeercert(binary_form=True)
            chain = [der]
            try:
                chain = [c.public_bytes(serialization.Encoding.DER)
                         for c in (ss.get_verified_chain() or [])] or [der]
            except Exception:
                pass
            cipher = ss.cipher() or ("", "", 0)
            return {
                "der": der,
                "chain": chain,
                "protocol": ss.version() or "",
                "cipher": cipher[0],
                "cipher_bits": cipher[2],
                "alpn": ss.selected_alpn_protocol() or "",
                "via": "python-ssl",
            }


def load_cert_bytes(raw: bytes) -> bytes:
    """把 PEM / DER 证书内容统一成 DER 字节（供本地证书文件分析使用）。"""
    if b"-----BEGIN" in raw:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        return x509.load_pem_x509_certificate(raw).public_bytes(
            serialization.Encoding.DER)
    return raw


def _tlv(data: bytes, off: int):
    """极简 DER TLV 读取：返回 (tag, value, next_off)。"""
    if off + 2 > len(data):
        raise ValueError("DER 截断")
    tag = data[off]
    ln = data[off + 1]
    hdr = 2
    if ln & 0x80:
        n = ln & 0x7F
        if n == 0 or off + 2 + n > len(data):
            raise ValueError("DER 长度字段非法")
        ln = int.from_bytes(data[off + 2:off + 2 + n], "big")
        hdr = 2 + n
    end = off + hdr + ln
    if end > len(data):
        raise ValueError("DER 值截断")
    return tag, data[off + hdr:end], end


def _oid_str(raw: bytes) -> str:
    if not raw:
        return ""
    parts = [raw[0] // 40, raw[0] % 40]
    val = 0
    for b in raw[1:]:
        val = (val << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(val)
            val = 0
    return ".".join(str(p) for p in parts)


def spki_from_der(der: bytes):
    """从证书 DER 中取出 (SPKI 算法 OID, 公钥原始字节, 曲线 OID)。"""
    _, cert_body, _ = _tlv(der, 0)
    _, tbs, _ = _tlv(cert_body, 0)
    off = 0
    tag, _val, off = _tlv(tbs, off)
    if tag == 0xA0:                          # version [0] 存在时，后面才是 serialNumber
        _tag, _v, off = _tlv(tbs, off)
    spki = None
    # 依次为 signature, issuer, validity, subject, subjectPublicKeyInfo
    for idx in range(5):
        _tag, val, off = _tlv(tbs, off)
        if idx == 4:
            spki = val
    if spki is None:
        raise ValueError("未找到 SubjectPublicKeyInfo")
    # spki 已经是 SubjectPublicKeyInfo 的内容：AlgorithmIdentifier + BIT STRING
    _t, alg_body, alg_end = _tlv(spki, 0)
    _t, alg_oid_raw, oid_end = _tlv(alg_body, 0)
    alg_oid = _oid_str(alg_oid_raw)
    curve_oid = ""
    try:
        tag2, params, _ = _tlv(alg_body, oid_end)
        if tag2 == 0x06:
            curve_oid = _oid_str(params)
    except Exception:
        curve_oid = ""
    _t3, bitstr, _ = _tlv(spki, alg_end)
    key_bytes = bitstr[1:] if bitstr else b""   # 去掉 unused-bits 字节
    return alg_oid, key_bytes, curve_oid


def analyze_cert_der(der: bytes):
    """证书层分析：算法识别 + FIPS 参数长度交叉校验。"""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    out = OrderedDict()
    cert = x509.load_der_x509_certificate(der)
    out["cert_der_len"] = len(der)

    def _cn(name):
        try:
            attrs = name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            return attrs[0].value if attrs else name.rfc4514_string()
        except Exception:
            return name.rfc4514_string()

    out["subject_cn"] = _cn(cert.subject)
    out["issuer_cn"] = _cn(cert.issuer)
    try:
        out["not_before"] = cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
        out["not_after"] = cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        out["not_before"] = str(cert.not_valid_before)
        out["not_after"] = str(cert.not_valid_after)
    out["serial"] = "%X" % cert.serial_number
    out["fingerprint_sha256"] = cert.fingerprint(hashes.SHA256()).hex().upper()

    # ---- 签名算法 ----
    sig_oid = cert.signature_algorithm_oid.dotted_string
    sig_name = SIG_ALGORITHM_OIDS.get(sig_oid, "")
    if not sig_name:
        try:
            sig_name = cert.signature_algorithm_oid._name or ""
        except Exception:
            sig_name = ""
    sig_bytes = len(cert.signature)
    sig_is_pqc = _is_pqc_oid(sig_oid)
    out["sig_oid"] = sig_oid
    out["sig_algorithm"] = sig_name or ("未知 (%s)" % sig_oid)
    out["sig_is_pqc"] = sig_is_pqc
    out["sig_bytes"] = sig_bytes

    # ---- 公钥算法 ----
    pub_oid, pub_bytes, curve_oid = "", 0, ""
    try:
        pub_oid, pub_raw, curve_oid = spki_from_der(der)
        pub_bytes = len(pub_raw)
    except Exception as e:
        out["spki_error"] = str(e)
    if not pub_oid:
        try:
            pub_oid = cert.public_key_algorithm_oid.dotted_string
        except Exception:
            pub_oid = ""
    pub_name = PUBKEY_ALGORITHM_OIDS.get(pub_oid, "")
    pub_is_pqc = _is_pqc_oid(pub_oid)
    out["pub_oid"] = pub_oid
    out["pub_algorithm"] = pub_name or (("未知 (%s)" % pub_oid) if pub_oid else "未能解析")
    out["pub_is_pqc"] = pub_is_pqc
    out["pub_bytes"] = pub_bytes
    if curve_oid:
        out["pub_curve"] = EC_CURVE_OIDS.get(curve_oid, curve_oid)
    if pub_oid == "1.2.840.113549.1.1.1":
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa
            key = cert.public_key()
            if isinstance(key, rsa.RSAPublicKey):
                out["pub_bits"] = key.key_size
        except Exception:
            pass
    elif pub_oid == "1.2.840.10045.2.1" and pub_bytes:
        out["pub_bits"] = (pub_bytes - 1) // 2 * 8

    # ---- FIPS 参数长度交叉校验 ----
    checks = []
    params = PQC_PARAMS.get(sig_oid)
    if sig_is_pqc and params:
        exp_sig = params[2]
        out["sig_expect_bytes"] = exp_sig
        out["sig_size_ok"] = (sig_bytes == exp_sig)
        checks.append("签名长度 %d 字节 vs 规范 %d 字节 —— %s" % (
            sig_bytes, exp_sig, "一致" if out["sig_size_ok"] else "不一致，标识与数据不符"))
    elif sig_is_pqc:
        out["sig_size_ok"] = None
        checks.append("签名算法属于抗量子族，但不在已知参数表中，无法做长度校验")
    else:
        out["sig_size_ok"] = None

    params_pub = PQC_PARAMS.get(pub_oid)
    if pub_is_pqc and params_pub:
        exp_pub = params_pub[1]
        out["pub_expect_bytes"] = exp_pub
        out["pub_size_ok"] = (pub_bytes == exp_pub)
        checks.append("公钥长度 %d 字节 vs 规范 %d 字节 —— %s" % (
            pub_bytes, exp_pub, "一致" if out["pub_size_ok"] else "不一致，标识与数据不符"))
    elif pub_is_pqc:
        out["pub_size_ok"] = None
        checks.append("公钥算法属于抗量子族，但不在已知参数表中，无法做长度校验")
    else:
        out["pub_size_ok"] = None

    # ---- 证书层结论 ----
    if pub_is_pqc and sig_is_pqc:
        evidence = "签名算法 %s、公钥 %s 均为抗量子算法" % (
            out["sig_algorithm"], out["pub_algorithm"])
    elif pub_is_pqc:
        evidence = "公钥为抗量子算法（%s），但签名算法仍为经典算法（%s）" % (
            out["pub_algorithm"], out["sig_algorithm"])
    elif sig_is_pqc:
        evidence = "签名算法为抗量子算法（%s），但公钥为经典算法（%s）" % (
            out["sig_algorithm"], out["pub_algorithm"])
    else:
        evidence = "签名算法 %s、公钥 %s 均为经典算法 —— 该证书不抗量子" % (
            out["sig_algorithm"], out["pub_algorithm"])
    if checks:
        evidence += "；" + "；".join(checks)
    out["cert_is_pqc"] = bool(sig_is_pqc and pub_is_pqc
                              and out.get("sig_size_ok") is True
                              and out.get("pub_size_ok") is True)
    out["certificate_signature_verified"] = False
    out["cert_evidence"] = evidence
    return out


# ===================================================================
# 本地静态文件检测：证书 / 公钥 / 原始密钥块
# ===================================================================

def _pem_block_der(raw: bytes, marker: str):
    """从 PEM 文本中取出指定类型的第一个块并转成 DER；找不到返回 None。"""
    begin = ("-----BEGIN %s-----" % marker).encode()
    end = ("-----END %s-----" % marker).encode()
    i = raw.find(begin)
    if i < 0:
        return None
    j = raw.find(end, i)
    if j < 0:
        return None
    import base64
    b64 = b"".join(raw[i + len(begin):j].split())
    try:
        return base64.b64decode(b64, validate=True)
    except Exception:
        return None


def analyze_public_key_der(der: bytes) -> dict:
    """分析一个 SPKI（SubjectPublicKeyInfo）DER：算法 OID + 公钥字节长度交叉校验。"""
    out = OrderedDict()
    out["kind"] = "public-key"
    # SPKI ::= SEQUENCE { AlgorithmIdentifier, BIT STRING }
    _t, body, _o = _tlv(der, 0)
    _t, alg, alg_end = _tlv(body, 0)
    _t2, oid_raw, oid_end = _tlv(alg, 0)
    pub_oid = _oid_str(oid_raw)
    curve_oid = ""
    if oid_end < len(alg):
        _t3, params, _e3 = _tlv(alg, oid_end)
        if _t3 == 0x06:
            curve_oid = _oid_str(params)
    _t4, bitstr, _e4 = _tlv(body, alg_end)
    pub_raw = bitstr[1:] if bitstr else b""
    pub_bytes = len(pub_raw)
    out["pub_oid"] = pub_oid
    out["pub_algorithm"] = PUBKEY_ALGORITHM_OIDS.get(
        pub_oid, "未知 (%s)" % pub_oid if pub_oid else "未能解析")
    out["pub_is_pqc"] = _is_pqc_oid(pub_oid)
    out["pub_bytes"] = pub_bytes
    if curve_oid:
        out["pub_curve"] = EC_CURVE_OIDS.get(curve_oid, curve_oid)
    params = PQC_PARAMS.get(pub_oid)
    if out["pub_is_pqc"] and params:
        out["pub_expect_bytes"] = params[1]
        out["pub_size_ok"] = (pub_bytes == params[1])
        out["nist_level"] = params[3]
        out["evidence"] = ("OID %s 判为 %s；公钥长度 %d 字节 vs FIPS 规范 %d 字节 —— %s"
                           % (pub_oid, params[0], pub_bytes, params[1],
                              "一致" if out["pub_size_ok"] else "不一致，标识与数据不符"))
    elif out["pub_is_pqc"]:
        out["evidence"] = "OID 属于抗量子族，但不在已知参数表中，无法做长度校验"
    else:
        out["evidence"] = "公钥算法 %s 属于经典算法族" % out["pub_algorithm"]
    out["is_pqc"] = bool(out["pub_is_pqc"] and out.get("pub_size_ok") is not False)
    return out


def _analyze_pkcs8_der(der: bytes) -> dict:
    """分析 PKCS#8 私钥 DER：只识别算法 OID（不解析私钥内容）。"""
    out = OrderedDict()
    out["kind"] = "private-key"
    try:
        _, body, _ = _tlv(der, 0)                 # PrivateKeyInfo SEQUENCE
        _, _ver, off = _tlv(body, 0)              # version INTEGER
        _t, alg, _off2 = _tlv(body, off)          # AlgorithmIdentifier SEQUENCE
        _t2, oid_raw, _off3 = _tlv(alg, 0)        # 算法 OID
        oid = _oid_str(oid_raw)
        out["pub_oid"] = oid
        out["pub_algorithm"] = PUBKEY_ALGORITHM_OIDS.get(oid, "未知 (%s)" % oid)
        out["pub_is_pqc"] = _is_pqc_oid(oid)
        out["evidence"] = ("PKCS#8 算法 OID %s 判为 %s；出于安全考虑不解析私钥内容，"
                           "仅做算法族识别" % (oid, out["pub_algorithm"]))
        out["is_pqc"] = out["pub_is_pqc"]
    except Exception as e:
        out["error"] = "PKCS#8 解析失败：%s" % e
        out["is_pqc"] = False
    return out


def _analyze_raw_blob(data: bytes) -> dict:
    """无结构标识的原始二进制：按已知 PQC 参数长度 / TLS key_share 长度反查候选。"""
    out = OrderedDict()
    out["kind"] = "raw-blob"
    n = len(data)
    out["size_bytes"] = n
    cands = []
    for oid, (name, pub_len, sig_len, lvl) in PQC_PARAMS.items():
        if n == pub_len:
            cands.append("公钥 %s（OID %s，NIST L%d）" % (name, oid, lvl))
        if n == sig_len:
            cands.append("签名值 %s（OID %s，NIST L%d）" % (name, oid, lvl))
    for gid, sz in CLIENT_SHARE_SIZES.items():
        if n == sz:
            cands.append("TLS key_share 客户端封装密钥 %s (0x%04X)"
                         % (lookup_group(gid)[0], gid))
    for gid, sz in KEY_SHARE_BODY_SIZES.items():
        if n == sz:
            cands.append("TLS key_share 扩展体 %s (0x%04X)" % (lookup_group(gid)[0], gid))
    seen, uniq = set(), []
    for c in cands:
        if c not in seen:
            seen.add(c)
            uniq.append(c)
    out["candidates"] = uniq
    out["is_pqc"] = bool(uniq)
    out["evidence"] = ("文件长度 %d 字节命中 %d 个已知 PQC 参数：%s；"
                       "原始数据无 OID/编号，结论仅为长度猜测，需结合来源确认"
                       % (n, len(uniq), "；".join(uniq) if uniq else "无"))
    return out


def analyze_file(path: str) -> dict:
    """本地静态文件检测入口：识别文件类型并给出 PQC 算法判定。

    支持 PEM/DER 证书（签名 + 公钥双层校验）、PEM/DER 公钥（SPKI）、
    PKCS#8 私钥（仅算法族识别）与原始二进制块（按已知长度反查候选）。
    """
    import hashlib
    with open(path, "rb") as f:
        raw = f.read()
    out = OrderedDict()
    out["file"] = path
    out["file_size"] = len(raw)
    out["sha256"] = hashlib.sha256(raw).hexdigest().upper()

    der = _pem_block_der(raw, "CERTIFICATE")
    if der is not None:
        info = analyze_cert_der(der)
        info["kind"] = "certificate"
        info["format"] = "PEM"
        info["is_pqc"] = bool(info.get("cert_is_pqc"))
        out.update(info)
        return out
    der = _pem_block_der(raw, "PUBLIC KEY")
    if der is not None:
        info = analyze_public_key_der(der)
        info["format"] = "PEM"
        out.update(info)
        return out
    der = _pem_block_der(raw, "PRIVATE KEY")
    if der is not None:
        info = _analyze_pkcs8_der(der)
        info["format"] = "PEM"
        out.update(info)
        return out
    try:
        info = analyze_cert_der(raw)
        info["kind"] = "certificate"
        info["format"] = "DER"
        info["is_pqc"] = bool(info.get("cert_is_pqc"))
        out.update(info)
        return out
    except Exception:
        pass
    try:
        info = analyze_public_key_der(raw)
        info["format"] = "DER"
        out.update(info)
        return out
    except Exception:
        pass
    try:
        _t, _b, _o = _tlv(raw, 0)
        info = _analyze_pkcs8_der(raw)
        info["format"] = "DER"
        if not info.get("error"):
            out.update(info)
            return out
    except Exception:
        pass
    out.update(_analyze_raw_blob(raw))
    return out

# ===================================================================
# 总入口：两层合一
# ===================================================================

def _deep_to_probe(deep: dict) -> dict:
    """把深度验证结果整理成与 probe_tls 同构的传输层字典。"""
    return {
        "host": deep.get("host", ""), "port": deep.get("port", 443),
        "ok": True, "error": "", "alert": deep.get("alert", ""),
        "hrr": bool(deep.get("hrr")), "protocol": "TLS 1.3",
        "cipher_suite": deep.get("cipher_suite", ""),
        "cipher_code": deep.get("cipher_code", 0),
        "group_id": deep.get("group_id", 0), "group_name": deep.get("group_name", ""),
        "is_pqc": bool(deep.get("is_pqc")),
        "key_share_body": deep.get("key_share_body", 0),
        "expect_body": deep.get("expect_body", 0),
        "size_ok": deep.get("size_ok"),
        "tls12": False,
        "offered": deep.get("offered", []),
        "elapsed_ms": (deep.get("timings") or {}).get("total_ms", 0.0),
        "bytes_recv": deep.get("handshake_bytes_recv", 0),
        "timings": deep.get("timings"),
        "client_hello": deep.get("client_hello"),
        "server_hello": deep.get("server_hello"),
        "verified": bool(deep.get("verified")),
        "finished_verified": deep.get("finished_verified"),
        "cert_verify": deep.get("cert_verify"),
        "deep": True,
        "shared_secret_len": deep.get("shared_secret_len", 0),
        "server_messages": deep.get("server_messages", []),
        "trace": deep.get("trace", []),
    }


def detect(host: str, port: int = 443, timeout: float = 12.0,
           check_cert: bool = True, log=None, mode: str = "deep",
           cancel_event=None, groups=None) -> dict:
    """对单个目标做完整的抗量子检测，返回报告字典。

    mode="deep"（默认）：**深度验证** —— 验证服务器侧 TLS 1.3 握手（ML-KEM 解封装 +
    ECDH → 派生握手密钥 → 解密服务器飞行 → 校验 Finished 与 CertificateVerify），
    结论是密码学确认的；握手未走完时自动退回快速证据判定并明确标注"未验证"。
    mode="fast"：只读 ServerHello 的 key_share 做证据判定（不完成握手）。
    """
    def _log(msg):
        if log:
            try:
                log(msg)
            except Exception:
                pass

    report = {
        "host": host, "port": port, "error": "",
        "transport": None, "cert": None, "overall": "", "overall_state": "unknown",
        "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "verification_status": "unverified",
        "verification_scope": "算法及参数识别；深度模式另验服务器 Finished 和 CertificateVerify。"
                              "证书链范围仅为服务器提供的证书；未验证证书签名链、CA 信任、域名及有效期。",
        "ca_trust_verified": False, "certificate_chain_signatures_verified": False,
        "certificate_chain_scope": "server_presented",
    }
    if not host:
        report["error"] = "目标为空"
        return report

    def _cancelled():
        if cancel_event is None or not cancel_event.is_set():
            return False
        report["error"] = "用户已取消主动复测"
        report["overall"] = "主动复测已取消"
        report["overall_state"] = "unknown"
        return True

    if _cancelled():
        return report

    # ---- 传输层 ----
    probe = None
    if mode == "deep":
        _log("深度验证：向 %s:%d 发起 TLS 1.3 握手并验证服务器飞行（ML-KEM 解封装 + ECDH → 派生密钥）…"
             % (host, port))
        deep = deep_verify(host, port, timeout, log=log, **({"groups": groups} if groups is not None else {}))
        report["deep"] = deep
        if deep.get("ok"):
            _log("深度验证：收到 %s" % "、".join(
                m["name"] for m in deep.get("server_messages", [])))
            _log("深度验证：共享密钥 %d 字节，握手密钥派生成功" % deep.get("shared_secret_len", 0))
            cv = deep.get("cert_verify") or {}
            _log("深度验证：Finished 校验%s；CertificateVerify 校验%s（%s，签名 %d 字节）" % (
                "通过" if deep.get("finished_verified") else "未通过",
                "通过" if cv.get("verified") else "未通过",
                cv.get("scheme_name", "—"), cv.get("sig_len", 0)))
            probe = _deep_to_probe(deep)
        else:
            _log("深度验证未完成：%s → 退回快速证据判定（结论将标注「未验证」）"
                 % (deep.get("error") or "未知原因"))
    if _cancelled():
        return report
    if probe is None:
        _log("传输层：向 %s:%d 发送含抗量子组的 ClientHello（快速证据判定）…" % (host, port))
        probe = probe_tls(host, port, timeout, **({"groups": groups} if groups is not None else {}))
    if mode != "deep":
        probe["verified"] = False
    if _cancelled():
        return report
    if probe["ok"]:
        _log("传输层：服务器选择 %s (0x%04X)%s" % (
            probe["group_name"], probe["group_id"],
            "" if probe["size_ok"] is None else
            "，key_share 体 %d 字节，长度校验%s" % (
                probe["key_share_body"], "一致" if probe["size_ok"] else "不一致")))
    elif probe.get("tls12"):
        _log("传输层：%s" % probe["error"])
    else:
        _log("传输层：%s" % (probe["error"] or "未取得有效应答"))
    report["transport"] = probe

    # 含 PQC 的 ClientHello 被拒时，用纯经典组复测，区分"不支持"与"直接拒绝"
    if not probe["ok"] and not probe.get("tls12"):
        _log("传输层：改用纯经典组复测…")
        fallback = probe_tls(host, port, timeout, groups=CLASSICAL_ONLY_GROUPS)
        if _cancelled():
            return report
        report["transport_fallback"] = fallback
        if fallback["ok"]:
            _log("传输层：纯经典组握手成功（协商 %s），说明服务器不接受含抗量子组的 ClientHello"
                 % fallback["group_name"])
        else:
            _log("传输层：纯经典组同样失败（%s）"
                 % (fallback["error"] or "未取得应答"))
            report["error"] = probe["error"] or fallback["error"]

    # ---- 多轮分组探测：输出服务器 PQC 支持矩阵（附加证据，不影响总体结论）----
    if probe.get("ok"):
        _log("支持矩阵：逐个试探其余候选抗量子组…")
        try:
            report["group_matrix"] = probe_group_matrix(
                host, port, min(timeout, 8.0), log=log,
                skip_groups=[probe.get("group_id")], cancel_event=cancel_event)
        except Exception as e:
            report["group_matrix_error"] = "%s: %s" % (type(e).__name__, e)
            _log("支持矩阵探测失败：%s" % report["group_matrix_error"])

    if _cancelled():
        return report
    # ---- 证书层 ----
    if check_cert:
        _log("证书层：抓取 %s:%d 的服务器证书…" % (host, port))
        try:
            same_handshake = (report.get("deep") or {}).get("cert_chain_der")
            if same_handshake:
                info = {"der": same_handshake[0], "chain": same_handshake,
                        "protocol": "TLS 1.3", "cipher": probe.get("cipher_suite", ""),
                        "via": "deep-handshake"}
                report["certificate_same_connection"] = True
            else:
                info = fetch_server_cert(host, port, timeout)
                report["certificate_same_connection"] = False
            der = info.get("der")
            if not der:
                raise ValueError("未取回证书")
            cert = analyze_cert_der(der)
            cert["session_protocol"] = info.get("protocol", "")
            cert["session_cipher"] = info.get("cipher", "")
            cert["session_alpn"] = info.get("alpn", "")
            cert["fetched_via"] = info.get("via", "")
            cert["fetch_ms"] = info.get("fetch_ms", 0.0)
            if info.get("fallback_reason"):
                cert["fetch_note"] = info["fallback_reason"]
                _log("证书层：Python ssl 未能完成握手（%s），已回退用本机 openssl 抓取证书"
                     % info["fallback_reason"][:80])
            report["cert"] = cert
            _log("证书层：签名 %s / 公钥 %s（%s）" % (
                cert["sig_algorithm"], cert["pub_algorithm"],
                "抗量子" if cert["cert_is_pqc"] else "经典算法"))
            # 只分析服务器提供的证书；此处不建立或验证 CA 信任路径。
            chain_ders = info.get("chain") or [der]
            chain_info = []
            for i, cder in enumerate(chain_ders):
                try:
                    ci = analyze_cert_der(cder)
                    ci["position"] = "叶子" if i == 0 else ("中间 CA %d" % i)
                    chain_info.append(ci)
                except Exception as e:
                    chain_info.append({"position": ("叶子" if i == 0 else "中间 CA %d" % i),
                                       "error": "%s: %s" % (type(e).__name__, e)})
            report["cert_chain"] = chain_info
            ok_links = [c for c in chain_info if not c.get("error")]
            report["chain_fully_pqc"] = bool(ok_links) and all(
                c.get("cert_is_pqc") for c in ok_links) and len(ok_links) == len(chain_info)
            _log("服务器提供的证书链：%d 张证书，算法%s（未验证 CA 信任）" % (
                len(chain_info), "抗量子" if report["chain_fully_pqc"] else "未完全抗量子"))
        except Exception as e:
            report["cert"] = {"error": "%s: %s" % (type(e).__name__, e)}
            _log("证书层：获取失败 —— %s" % report["cert"]["error"])

    if _cancelled():
        return report
    # ---- 综合结论 ----
    t_ok = bool(probe["ok"] and probe["is_pqc"] and probe.get("size_ok") is True)
    t_known = bool(probe["ok"] or probe.get("tls12"))
    cert_obj = report["cert"] or {}
    c_ok = bool(cert_obj.get("cert_is_pqc") and report.get("chain_fully_pqc"))
    c_known = "cert_is_pqc" in cert_obj
    deep = report.get("deep") or {}
    cv = deep.get("cert_verify") or {}
    unsupported = (deep.get("verification_error_kind") == "unsupported"
                   or cv.get("error_kind") == "unsupported")
    chain_invalid = any(c.get("sig_size_ok") is False or c.get("pub_size_ok") is False
                        for c in report.get("cert_chain", []))
    validation_failed = (probe.get("size_ok") is False or chain_invalid
                         or deep.get("verification_error_kind") == "invalid"
                         or (deep.get("ok") and deep.get("finished_verified") is False)
                         or (cv.get("verified") is False and not unsupported))
    handshake_verified = bool(deep.get("verified") and deep.get("finished_verified")
                              and cv.get("verified") and not validation_failed)
    report["verification_status"] = ("failed" if validation_failed else
                                     "verified" if handshake_verified else
                                     "unsupported" if unsupported else "unverified")
    if validation_failed:
        probe["verified"] = False
        report["overall"] = "验证失败：握手验签或算法参数不一致，不能确认抗量子安全性"
        report["overall_state"] = "unknown"
    elif t_ok and c_ok and handshake_verified and report.get("certificate_same_connection"):
        report["overall"] = "双层抗量子算法与服务器握手已验证；所提供证书链均为抗量子算法（CA 信任未验证）"
        report["overall_state"] = "pqc"
    elif t_ok and c_ok:
        report["overall"] = "观察到双层抗量子算法证据；服务器握手未验证，CA 信任未验证"
        report["overall_state"] = "partial"
    elif t_ok and c_known and not c_ok:
        report["overall"] = "部分抗量子：密钥交换采用抗量子组，证书或所提供证书链未完全采用抗量子算法"
        report["overall_state"] = "partial"
    elif c_ok and t_known and not t_ok:
        report["overall"] = "部分抗量子：证书已抗量子，密钥交换仍为经典算法"
        report["overall_state"] = "partial"
    elif t_known and c_known:
        report["overall"] = "本次连接未观察到抗量子密钥交换与认证：密钥交换和证书均为经典算法"
        report["overall_state"] = "classic"
    elif t_known and not c_known:
        report["overall"] = "仅传输层结论：%s（证书层未检测）" % (
            "已协商抗量子密钥交换" if t_ok else "本次未协商抗量子密钥交换")
        report["overall_state"] = "partial" if t_ok else "classic"
    elif c_known and not t_known:
        report["overall"] = "仅证书层结论：%s（传输层未能判定）" % (
            "证书使用抗量子算法" if c_ok else "证书使用经典算法")
        report["overall_state"] = "partial" if c_ok else "classic"
    else:
        report["overall"] = "未能给出完整结论：%s" % (
            probe["error"] or report.get("error") or "证据不足")
        report["overall_state"] = "unknown"
    if report["verification_status"] in ("unverified", "unsupported") and "未验证" not in report["overall"]:
        report["overall"] += "（服务器握手未验证%s）" % (
            "：当前运行库不支持验签方案" if unsupported else "")
    _log("综合结论：%s" % report["overall"])
    return report


# ===================================================================
# 结果整理（界面表格 / JSON 导出）
# ===================================================================

def _transport_evidence(t: dict) -> str:
    if t.get("verified"):
        cv = t.get("cert_verify") or {}
        tail = ("已验证服务器侧 TLS 1.3 握手：共享密钥派生成功，服务器 Finished 校验%s，"
                "CertificateVerify 用证书公钥验签%s（%s，签名 %d 字节）"
                % ("通过" if t.get("finished_verified") else "未通过",
                   "通过" if cv.get("verified") else "未通过",
                   cv.get("scheme_name") or "—", cv.get("sig_len", 0)))
        if t.get("is_pqc"):
            return ("【密码学验证】服务器 ServerHello 选择 0x%04X（%s，key_share 体 %d 字节），%s"
                    " —— 抗量子密钥交换已被密码学确认"
                    % (t.get("group_id", 0), t.get("group_name", ""),
                       t.get("key_share_body", 0), tail))
        return ("【密码学验证】服务器选择的是 0x%04X（%s），%s —— 本次连接未协商抗量子密钥交换"
                % (t.get("group_id", 0), t.get("group_name", ""), tail))
    if t.get("tls12") and not t.get("ok"):
        return ("【仅证据·未验证】客户端已在 ClientHello 中提供 X25519MLKEM768 等抗量子组，"
                "但服务器以 %s 应答（ServerHello 无 key_share 扩展）—— "
                "本次连接未使用 TLS 1.3 抗量子混合组"
                % (t.get("protocol") or "旧版本"))
    if not t.get("ok"):
        return "【未验证】" + (t.get("error") or "未取得 ServerHello 的 key_share 证据")
    gid = t.get("group_id", 0)
    if t.get("is_pqc"):
        return ("【仅证据·未验证】客户端已在 ClientHello 中提供抗量子组，服务器 ServerHello 主动选择 "
                "0x%04X（%s，key_share 体 %d 字节）—— 直接证据"
                % (gid, t.get("group_name", ""), t.get("key_share_body", 0)))
    return ("【仅证据·未验证】客户端已提供抗量子组（X25519MLKEM768 等），但 ServerHello 选择的是 "
            "0x%04X（%s）—— 本次连接未协商抗量子密钥交换"
            % (gid, t.get("group_name", "")))


def transport_evidence(transport: dict) -> str:
    """对外暴露的直接证据描述（供界面卡片显示）。"""
    return _transport_evidence(transport or {})


def report_rows(report: dict) -> OrderedDict:
    """把报告整理成 (属性, 值) 有序字典，供界面表格展示。"""
    rows = OrderedDict()
    if not report:
        return rows
    _port = report.get("port")
    rows["目标"] = ("%s:%s" % (report.get("host", ""), _port)) if _port \
        else str(report.get("host", ""))
    rows["检测时间"] = report.get("started_at", "")
    rows["综合结论"] = report.get("overall", "")
    if report.get("verification_scope"):
        rows["验证范围"] = report["verification_scope"]
        rows["验证状态"] = report.get("verification_status", "unverified")
    if report.get("error"):
        rows["错误信息"] = report["error"]

    t = report.get("transport") or {}
    if t:
        rows["— 传输层（密钥交换）—"] = ""
        rows["服务器选中组"] = "%s (0x%04X)" % (t.get("group_name", ""), t.get("group_id", 0))
        if t.get("ok"):
            rows["是否抗量子"] = "是" if t.get("is_pqc") else "否"
        elif t.get("tls12"):
            rows["是否抗量子"] = "否（服务器仅 %s 应答）" % (t.get("protocol") or "旧版本")
        else:
            rows["是否抗量子"] = "未能判定"
        if t.get("ok"):
            rows["key_share 体长度"] = "%d 字节%s" % (
                t.get("key_share_body", 0),
                "" if not t.get("expect_body") else
                "（规范 %d 字节，%s）" % (t["expect_body"],
                                        "一致" if t.get("size_ok") else "不一致"))
        rows["协商版本"] = t.get("protocol", "") or "—"
        rows["协商密码套件"] = t.get("cipher_suite", "") or "—"
        rows["HelloRetryRequest"] = "是（服务器要求重试）" if t.get("hrr") else "否"
        if t.get("verified"):
            cv = t.get("cert_verify") or {}
            rows["验证强度"] = "已验证服务器握手：Finished + CertificateVerify 密码学校验"
            rows["服务器消息"] = "、".join(m.get("name", "") for m in t.get("server_messages", []))
            rows["共享密钥长度"] = "%d 字节（握手密钥派生成功）" % t.get("shared_secret_len", 0)
            rows["Finished 校验"] = "通过" if t.get("finished_verified") else "未通过"
            rows["CertificateVerify"] = "%s，签名 %d 字节，%s" % (
                cv.get("scheme_name") or "—", cv.get("sig_len", 0),
                "验签通过" if cv.get("verified") else "验签未通过")
        else:
            rows["验证强度"] = "仅 ServerHello 证据（服务器握手未验证）"
            d = report.get("deep") or {}
            if d.get("error"):
                rows["深度验证失败原因"] = d["error"]
        rows["客户端提供组"] = " | ".join(t.get("offered", [])) or "—"
        rows["握手耗时"] = "%.1f ms" % t.get("elapsed_ms", 0.0)
        rows["直接证据"] = _transport_evidence(t)
        fb = report.get("transport_fallback")
        if fb:
            rows["经典组复测"] = ("成功，协商 %s" % fb.get("group_name")) if fb.get("ok") \
                else ("失败：%s" % (fb.get("error") or "无应答"))
        gm = report.get("group_matrix")
        if gm:
            rows["— PQC 支持矩阵（多轮探测）—"] = ""
            for g in gm:
                rows["%s (%s)" % (g.get("group_name"), g.get("group_id"))] = "%s%s" % (
                    "支持" if g.get("supported") else "不支持",
                    ("，key_share 长度%s" % ("一致" if g.get("size_ok") else "不一致"))
                    if g.get("size_ok") is not None else "")
            rows["支持组数"] = "%d / %d" % (sum(1 for g in gm if g.get("supported")), len(gm))

    c = report.get("cert") or {}
    if c:
        rows["— 证书层（身份认证）—"] = ""
        if c.get("error"):
            rows["证书获取"] = "失败：%s" % c["error"]
        else:
            rows["证书主体"] = c.get("subject_cn", "")
            rows["证书签发者"] = c.get("issuer_cn", "")
            rows["有效期"] = "%s ~ %s" % (c.get("not_before", ""), c.get("not_after", ""))
            rows["签名算法"] = "%s（OID %s）" % (c.get("sig_algorithm", ""), c.get("sig_oid", ""))
            rows["签名值长度"] = "%d 字节%s" % (
                c.get("sig_bytes", 0),
                "" if c.get("sig_expect_bytes") is None else
                "（规范 %d 字节，%s）" % (c["sig_expect_bytes"],
                                        "一致" if c.get("sig_size_ok") else "不一致"))
            rows["公钥算法"] = "%s（OID %s）" % (c.get("pub_algorithm", ""), c.get("pub_oid", ""))
            rows["公钥长度"] = "%d 字节%s%s" % (
                c.get("pub_bytes", 0),
                "" if c.get("pub_expect_bytes") is None else
                "（规范 %d 字节，%s）" % (c["pub_expect_bytes"],
                                        "一致" if c.get("pub_size_ok") else "不一致"),
                ("，%d 位" % c["pub_bits"]) if c.get("pub_bits") else "")
            if c.get("pub_curve"):
                rows["公钥曲线"] = c["pub_curve"]
            rows["证书指纹 SHA256"] = c.get("fingerprint_sha256", "")
            rows["序列号"] = c.get("serial", "")
            if c.get("session_protocol"):
                rows["常规握手版本/套件"] = "%s / %s%s" % (
                    c.get("session_protocol"), c.get("session_cipher"),
                    ("，ALPN %s" % c["session_alpn"]) if c.get("session_alpn") else "")
            if c.get("fetched_via") == "openssl":
                rows["证书获取方式"] = "openssl s_client（Python ssl 不支持该证书签名算法时自动回退）"
            elif c.get("fetched_via") == "deep-handshake":
                rows["证书获取方式"] = "同一次深度 TLS 握手解密得到的 Certificate 消息"
            rows["证书层结论"] = c.get("cert_evidence", "")
        chain = report.get("cert_chain")
        if chain:
            rows["— 证书链（服务器提供的证书）—"] = ""
            for i, link in enumerate(chain):
                if link.get("error"):
                    rows["链节点 %d" % i] = "解析失败：%s" % link["error"]
                else:
                    rows["链节点 %d（%s）" % (i, link.get("position", ""))] = \
                        "签名 %s / 公钥 %s（%s）" % (
                            link.get("sig_algorithm"), link.get("pub_algorithm"),
                            "抗量子" if link.get("cert_is_pqc") else "未确认抗量子")
            rows["整链结论"] = "所提供链均采用抗量子算法（CA 信任未验证）" if report.get("chain_fully_pqc") \
                else "所提供链未完全采用抗量子算法（CA 信任未验证）"
    return rows


def report_to_json(report: dict) -> dict:
    """把报告整理成可 JSON 序列化的结构。"""
    out = {
        "host": report.get("host"), "port": report.get("port"),
        "started_at": report.get("started_at"), "overall": report.get("overall"),
        "overall_state": report.get("overall_state"), "error": report.get("error", ""),
        "verification_status": report.get("verification_status", "unverified"),
        "verification_scope": report.get("verification_scope", ""),
        "ca_trust_verified": bool(report.get("ca_trust_verified")),
        "certificate_chain_signatures_verified": bool(report.get("certificate_chain_signatures_verified")),
        "certificate_chain_scope": report.get("certificate_chain_scope", "server_presented"),
        "certificate_same_connection": bool(report.get("certificate_same_connection")),
    }
    t = report.get("transport") or {}
    out["transport"] = {
        "success": bool(t.get("ok")),
        "pqc_supported": bool(t.get("is_pqc")),
        "group_id": ("0x%04X" % t["group_id"]) if t.get("group_id") else "",
        "group_name": t.get("group_name", ""),
        "key_share_body": t.get("key_share_body", 0),
        "key_share_expected": t.get("expect_body", 0),
        "key_share_size_ok": t.get("size_ok"),
        "protocol": t.get("protocol", ""),
        "cipher_suite": t.get("cipher_suite", ""),
        "hello_retry_request": bool(t.get("hrr")),
        "tls12_response": bool(t.get("tls12")),
        "offered_groups": t.get("offered", []),
        "elapsed_ms": round(t.get("elapsed_ms", 0.0), 1),
        "alert": t.get("alert", ""),
        "error": t.get("error", ""),
    }
    fb = report.get("transport_fallback")
    if fb:
        out["transport_fallback"] = {
            "success": bool(fb.get("ok")), "group_name": fb.get("group_name", ""),
            "error": fb.get("error", ""),
        }
    gm = report.get("group_matrix")
    if gm:
        out["group_matrix"] = gm
    if report.get("group_matrix_error"):
        out["group_matrix_error"] = report["group_matrix_error"]
    deep = report.get("deep")
    if deep:
        out["deep_verification"] = {
            "attempted": True,
            "completed": bool(deep.get("ok")),
            "verified": bool(deep.get("verified")),
            "verification_status": deep.get("verification_status", "unverified"),
            "verification_error_kind": deep.get("verification_error_kind", ""),
            "error": deep.get("error", ""),
            "shared_secret_len": deep.get("shared_secret_len", 0),
            "server_messages": [m.get("name") for m in deep.get("server_messages", [])],
            "finished_verified": deep.get("finished_verified"),
            "certificate_verify": deep.get("cert_verify"),
            "timings": deep.get("timings"),
        }
    c = report.get("cert") or {}
    if c:
        if c.get("error"):
            out["cert"] = {"success": False, "error": c["error"]}
        else:
            out["cert"] = {
                "success": True,
                "subject_cn": c.get("subject_cn"), "issuer_cn": c.get("issuer_cn"),
                "not_before": c.get("not_before"), "not_after": c.get("not_after"),
                "serial": c.get("serial"),
                "fingerprint_sha256": c.get("fingerprint_sha256"),
                "sig_algorithm": c.get("sig_algorithm"), "sig_oid": c.get("sig_oid"),
                "sig_is_pqc": c.get("sig_is_pqc"), "sig_bytes": c.get("sig_bytes"),
                "sig_expected_bytes": c.get("sig_expect_bytes"),
                "sig_size_ok": c.get("sig_size_ok"),
                "pub_algorithm": c.get("pub_algorithm"), "pub_oid": c.get("pub_oid"),
                "pub_is_pqc": c.get("pub_is_pqc"), "pub_bytes": c.get("pub_bytes"),
                "pub_expected_bytes": c.get("pub_expect_bytes"),
                "pub_size_ok": c.get("pub_size_ok"),
                "pub_curve": c.get("pub_curve"), "pub_bits": c.get("pub_bits"),
                "cert_is_pqc": c.get("cert_is_pqc"), "evidence": c.get("cert_evidence"),
                "session_protocol": c.get("session_protocol"),
                "session_cipher": c.get("session_cipher"),
            }
    chain = report.get("cert_chain")
    if chain:
        out["cert_chain"] = [{
            "position": l.get("position"),
            "subject_cn": l.get("subject_cn"), "issuer_cn": l.get("issuer_cn"),
            "sig_algorithm": l.get("sig_algorithm"),
            "pub_algorithm": l.get("pub_algorithm"),
            "cert_is_pqc": l.get("cert_is_pqc"),
            "error": l.get("error"),
        } for l in chain]
        out["chain_fully_pqc"] = bool(report.get("chain_fully_pqc"))
    out["rows"] = OrderedDict(report_rows(report))
    out["interaction_raw"] = interaction_text(report)
    out["interaction_verbose"] = interaction_text_verbose(report)
    return out


# ===================================================================
# 交互细节（逐字段展示我们发了什么、服务器回了什么）
# ===================================================================

def interaction_text_verbose(report: dict) -> str:
    """逐字段的“解析说明”版交互过程（保留给 JSON 报告/人工阅读使用）。"""
    if not report:
        return ""
    t = report.get("transport") or {}
    c = report.get("cert") or {}
    host, port = report.get("host", ""), report.get("port", 443)
    out = []
    add = out.append

    add("目标    : %s:%s" % (host, port))
    add("检测时间: %s" % report.get("started_at", ""))
    add("")

    # ---------- 时间线 ----------
    add("=" * 76)
    add("① 交互时间线")
    add("=" * 76)
    if t:
        tm = t.get("timings") or {}
        ch = t.get("client_hello") or {}
        add("  TCP 建连完成                         %.1f ms" % tm.get("connect_ms", 0.0))
        add("  → 发送 ClientHello                   %d 字节（含 %s 的抗量子组）"
            % (ch.get("record_len", 0), "、".join(
                g["name"] for g in (ch.get("groups") or []) if g.get("pqc")) or "—"))
        if tm.get("server_hello_ms") is not None:
            add("  ← 收到服务器首个响应                  %.1f ms 后（本次读取 %d 字节）"
                % (tm["server_hello_ms"], t.get("bytes_recv", 0)))
        if t.get("alert"):
            add("  ← 服务器告警                         %s（握手未完成）" % t["alert"])
        if report.get("transport_fallback"):
            fb = report["transport_fallback"]
            add("  → 回退复测（纯经典组）               %s"
                % ("成功，协商 %s" % fb.get("group_name") if fb.get("ok")
                   else "失败：%s" % (fb.get("error") or "无应答")))
        add("  传输层探测总耗时                     %.1f ms" % tm.get("total_ms", t.get("elapsed_ms", 0.0)))
    else:
        add("  （本次未做传输层探测）")
    if c:
        if c.get("error"):
            add("  证书抓取                             失败：%s" % c["error"])
        else:
            add("  ← 取回服务器证书                     %.1f ms（方式：%s）" % (
                c.get("fetch_ms", 0.0),
                "openssl s_client（Python ssl 不支持该证书算法时回退）"
                if c.get("fetched_via") == "openssl" else "Python ssl"))
            if c.get("fallback_reason"):
                add("     回退原因                          %s" % c["fallback_reason"][:96])
    add("")

    # ---------- ClientHello ----------
    add("=" * 76)
    add("② 我们发出的 ClientHello（客户端 → 服务器）")
    add("=" * 76)
    if t and t.get("client_hello"):
        ch = t["client_hello"]
        add("  TLS 记录           type=handshake(22)  legacy_version=0x0301  length=%d" % ch["record_len"])
        add("  握手消息           type=ClientHello(1)  length=%d" % ch["handshake_len"])
        add("  legacy_version     0x0303（TLS 1.3 固定写法，真实版本在 supported_versions）")
        add("  random             32 字节随机数")
        add("  session_id         32 字节（TLS 1.3 中间盒兼容）")
        add("  压缩方式           null")
        add("  扩展 SNI           %s" % ch["sni"])
        add("  扩展 supported_versions  %s" % ch["versions"])
        add("  扩展 supported_groups    （顺序即优先级，服务器应优先选靠前的组）")
        for i, g in enumerate(ch["groups"]):
            mark = "★抗量子" if g["pqc"] else "  经典  "
            add("      %d) 0x%04X  %-26s %s" % (i + 1, g["id"], g["name"], mark))
        add("  扩展 signature_algorithms  共 %d 个，抗量子签名在前："
            % len(ch["sig_algs"]))
        add("      " + "、".join(ch["sig_algs"][:6]) + " …")
        add("  扩展 key_share     每组附带的客户端密钥材料（key_exchange）长度：")
        for g in ch["groups"]:
            if not g.get("share_sent"):
                add("      0x%04X  %-26s 未附带 share（仅声明）" % (g["id"], g["name"]))
                continue
            detail = ""
            if g["id"] == 0x11EC:
                detail = "（ML-KEM-768 封装密钥 1184 + X25519 公钥 32）"
            elif g["id"] == 0x11EB:
                detail = "（ML-KEM-768 封装密钥 1184 + P-256 公钥 65）"
            elif g["id"] == 0x11ED:
                detail = "（ML-KEM-1024 封装密钥 1568 + P-384 公钥 97）"
            add("      0x%04X  %-26s %4d 字节 %s" % (g["id"], g["name"], g["share_len"], detail))
        add("  说明               %s" % ch["key_share_note"])
    else:
        add("  （本次未发送 ClientHello）")
    add("")

    # ---------- ServerHello ----------
    add("=" * 76)
    add("③ 服务器回的 ServerHello（服务器 → 客户端）")
    add("=" * 76)
    sh = t.get("server_hello") if t else None
    if sh:
        add("  消息长度           %d 字节" % sh["body_len"])
        add("  legacy_version     %s" % sh["legacy_version"])
        add("  random             %s%s" % (sh["random_hex"][:32] + "…",
                                          "   ← HelloRetryRequest 特殊值" if sh["is_hrr"] else ""))
        add("  selected_cipher    0x%04X %s" % (sh["cipher_code"], sh["cipher_name"]))
        add("  扩展列表：")
        for e in sh["extensions"]:
            add("      type=0x%04X (%-22s) 长度 %4d  %s"
                % (e["id"], e["name"], e["len"], e["summary"]))
        if sh.get("alert"):
            add("  告警               %s" % sh["alert"])
    else:
        add("  未收到可解析的 ServerHello")
        if t and t.get("alert"):
            add("  服务器告警         %s" % t["alert"])
        if t and t.get("error"):
            add("  说明               %s" % t["error"])
    add("")

    # ---------- 深度验证 ----------
    deep = report.get("deep") or {}
    add("=" * 76)
    add("④ 深度验证（服务器 TLS 1.3 握手密码学校验）")
    add("=" * 76)
    if deep:
        if not deep.get("ok"):
            add("  结果               未完成：%s" % (deep.get("error") or "未知原因"))
            add("  说明               已自动退回「仅 ServerHello 证据」判定，结论标注为未验证")
        else:
            add("  共享密钥           %d 字节（我们的 ML-KEM 私钥解封装 + ECDH 得到）"
                % deep.get("shared_secret_len", 0))
            add("  密钥派生           HKDF-Extract/Expand-Label 按 RFC 8446 派生握手流量密钥")
            add("  服务器加密飞行     %s" % "、".join(
                "%s(%d)" % (m["name"], m["len"]) for m in deep.get("server_messages", [])))
            add("  Finished 校验      %s（verify_data %d 字节，HMAC 对握手转录哈希）"
                % ("通过" if deep.get("finished_verified") else "未通过",
                   deep.get("finished_len", 0)))
            cv = deep.get("cert_verify") or {}
            add("  CertificateVerify  %s：%s，签名 %d 字节 → 用证书公钥验签 %s%s" % (
                cv.get("scheme", "—"), cv.get("scheme_name", "—"), cv.get("sig_len", 0),
                "通过" if cv.get("verified") else "未通过",
                ("（%s）" % cv["error"][:50]) if cv.get("error") else ""))
            add("  验证结论           %s" % (
                "密码学确认：本次握手确实使用了上述算法，且对方持有证书私钥"
                if deep.get("verified") else "握手完成但校验未全部通过，请查看上面各项"))
    else:
        add("  （本次为快速检测模式，未完成握手）")
    add("")

    # ---------- 证书层 ----------
    add("=" * 76)
    add("⑤ 证书层解析（服务器证书真实字节）")
    add("=" * 76)
    if c and not c.get("error"):
        add("  证书主体           %s" % c.get("subject_cn", ""))
        add("  证书签发者         %s" % c.get("issuer_cn", ""))
        add("  有效期             %s ~ %s" % (c.get("not_before", ""), c.get("not_after", "")))
        add("  签名算法           %s（OID %s）" % (c.get("sig_algorithm", ""), c.get("sig_oid", "")))
        add("  签名实际长度       %d 字节%s" % (
            c.get("sig_bytes", 0),
            "" if c.get("sig_expect_bytes") is None else
            "（FIPS 规范 %d 字节 → %s）" % (
                c["sig_expect_bytes"], "一致" if c.get("sig_size_ok") else "不一致")))
        add("  公钥算法           %s（OID %s）" % (c.get("pub_algorithm", ""), c.get("pub_oid", "")))
        add("  公钥实际长度       %d 字节%s%s" % (
            c.get("pub_bytes", 0),
            "" if c.get("pub_expect_bytes") is None else
            "（FIPS 规范 %d 字节 → %s）" % (
                c["pub_expect_bytes"], "一致" if c.get("pub_size_ok") else "不一致"),
            ("，%d 位" % c["pub_bits"]) if c.get("pub_bits") else ""))
        if c.get("pub_curve"):
            add("  公钥曲线           %s" % c["pub_curve"])
        add("  证书指纹 SHA256    %s" % c.get("fingerprint_sha256", ""))
    elif c:
        add("  证书获取失败：%s" % c.get("error"))
    else:
        add("  （本次未做证书层检测）")
    add("")

    # ---------- 判定 ----------
    add("=" * 76)
    add("⑥ 判定与证据")
    add("=" * 76)
    add("  [传输层] %s" % (transport_evidence(t) if t else "—"))
    if c and not c.get("error"):
        add("  [证书层] %s" % c.get("cert_evidence", ""))
    elif c:
        add("  [证书层] 获取失败：%s" % c.get("error"))
    add("  [综合]   %s" % report.get("overall", ""))
    return "\n".join(out)


def interaction_text(report: dict) -> str:
    """交互细节（最底层）：逐条 TLS 记录的原始字节 hex dump。

    只保留必要的帧信息（方向、记录类型与长度）；加密记录在其密文之后附上
    **解密后的明文**（含 TLSInnerPlaintext 的内容类型字节），不做字段解释。
    """
    if not report:
        return ""
    deep = report.get("deep") or {}
    t = report.get("transport") or {}
    if not deep:
        mode = "快速检测"
    elif deep.get("ok"):
        mode = "深度验证"
    else:
        mode = "深度验证（未完成 → 已退回证据判定）"
    out = []
    add = out.append
    add("目标 %s:%s    %s    模式 %s" % (
        report.get("host", ""), report.get("port", ""),
        report.get("started_at", ""), mode))
    add("")

    def _dump(trace, title):
        if not trace:
            return
        add("===== %s =====" % title)
        for i, item in enumerate(trace, 1):
            raw = item.get("raw") or b""
            add("#%02d %s %-40s %6d 字节" % (
                i, item.get("dir", ""), item.get("kind", ""), len(raw)))
            add(hexdump(raw))
            plain = item.get("plain")
            if plain is not None:
                add("     解密后明文 content_type=%s  %d 字节" % (
                    item.get("content_type", "?"), len(plain)))
                add(hexdump(plain))
            add("")

    _dump(t.get("trace") or deep.get("trace") or [], "TLS 记录收发（原始字节）")
    fb = report.get("transport_fallback")
    if fb:
        _dump(fb.get("trace"), "回退复测（纯经典组）")
    return "\n".join(out)


def _handshake_names_in(content: bytes) -> str:
    """列出给定握手字节流包含的消息名（仅做帧标注）。"""
    names, off = [], 0
    while off + 4 <= len(content):
        mt = content[off]
        ln = int.from_bytes(content[off + 1:off + 4], "big")
        if off + 4 + ln > len(content):
            names.append("(不完整 %s)" % HANDSHAKE_NAMES.get(mt, "0x%02X" % mt))
            break
        names.append(HANDSHAKE_NAMES.get(mt, "0x%02X" % mt))
        off += 4 + ln
    return "、".join(names) if names else "—"


def _pad(text: str, width: int) -> str:
    """按显示宽度补空格（中文按 2 列算），让等宽字体下的表格对齐。"""
    w = sum(2 if ord(c) > 0x2E80 else 1 for c in text)
    return text + " " * max(0, width - w)


def interaction_outline(report: dict) -> str:
    """交互框架（界面显示用）：逐条记录的方向 / 类型 / 长度，
    加密记录再给"解密后长度 + 所含握手消息名"，并补一列关键内容（不铺字节）。"""
    if not report:
        return ""
    deep = report.get("deep") or {}
    t = report.get("transport") or {}
    c = report.get("cert") or {}
    ch = t.get("client_hello") or {}
    cv = t.get("cert_verify") or {}
    offered_pqc = [g["name"] for g in (ch.get("groups") or []) if g.get("pqc")]
    if not deep:
        mode = "快速检测"
    elif deep.get("ok"):
        mode = "深度验证"
    else:
        mode = "深度验证（未完成 → 已退回证据判定）"
    out = []
    add = out.append
    add("目标 %s:%s     %s     模式 %s" % (
        report.get("host", ""), report.get("port", ""),
        report.get("started_at", ""), mode))
    add("-" * 78)
    add("  %s %s %s %8s  %s" % (_pad("#", 3), _pad("方向", 4),
                                _pad("记录", 28), "长度", "关键内容"))
    trace = t.get("trace") or deep.get("trace") or []
    for i, item in enumerate(trace, 1):
        raw = item.get("raw") or b""
        plain = item.get("plain")
        key = ""
        if item.get("dir") == "→":
            key = "SNI=%s；提供 %d 个组（抗量子 %d 个）" % (
                ch.get("sni", report.get("host", "")), len(ch.get("groups") or []),
                len(offered_pqc))
        elif t.get("ok") and item.get("dir") == "←" and len(raw) >= 6 and raw[5] == 2:
            key = "选中 0x%04X %s；%s" % (
                t.get("group_id", 0), t.get("group_name", ""),
                ("key_share %d 字节（规范%s）" % (
                    t.get("key_share_body", 0),
                    "一致" if t.get("size_ok") else "不一致"))
                if t.get("expect_body") else "无 key_share")
        if plain is None:
            extra = key or "—"
        else:
            names = _handshake_names_in(plain[:-1])
            extra = "%d B  %s" % (max(0, len(plain) - 1), names)
            if names == "Certificate" and c.get("subject_cn"):
                extra += "（%s ← %s）" % (c.get("subject_cn"), c.get("issuer_cn", ""))
            elif names == "CertificateVerify" and cv:
                extra += "（%s，签名 %d 字节，验签%s）" % (
                    cv.get("scheme_name") or "—", cv.get("sig_len", 0),
                    "通过" if cv.get("verified") else "未通过")
            elif names == "Finished":
                extra += "（校验%s）" % ("通过" if deep.get("finished_verified") else "未通过")
            elif names == "EncryptedExtensions":
                extra += "（服务器扩展）"
        add("  %s %s %s %6d B  %s" % (
            _pad(str(i), 3), _pad(item.get("dir", ""), 4),
            _pad(item.get("kind", ""), 28), len(raw), extra))
    fb = report.get("transport_fallback")
    if fb and fb.get("trace"):
        add("  ——— 回退复测（纯经典组）———")
        for i, item in enumerate(fb["trace"], 1):
            raw = item.get("raw") or b""
            add("  %s %s %s %6d B  %s" % (
                _pad(str(i), 3), _pad(item.get("dir", ""), 4),
                _pad(item.get("kind", ""), 28), len(raw), "—"))
    add("-" * 78)
    # 关键字段摘要
    rows = []
    if t:
        rows.append(("SNI", ch.get("sni") or report.get("host", "")))
        if ch.get("groups"):
            rows.append(("客户端提供组", " > ".join(
                "0x%04X %s%s" % (g["id"], g["name"], "（抗量子）" if g["pqc"] else "")
                for g in ch["groups"])))
        if t.get("ok"):
            rows.append(("服务器选中组", "0x%04X %s" % (
                t.get("group_id", 0), t.get("group_name", ""))))
            if t.get("expect_body"):
                rows.append(("key_share 体", "%d 字节（规范 %d 字节 → %s）" % (
                    t.get("key_share_body", 0), t["expect_body"],
                    "一致" if t.get("size_ok") else "不一致")))
            rows.append(("协商版本/套件", "%s / %s" % (
                t.get("protocol") or "TLS 1.3", t.get("cipher_suite") or "—")))
        rows.append(("验证强度", "已验证服务器握手：Finished + CertificateVerify 校验通过"
                     if t.get("verified") else "仅 ServerHello 证据（服务器握手未验证）"))
        if t.get("verified"):
            rows.append(("共享密钥", "%d 字节（ML-KEM 解封装 + ECDH）"
                         % t.get("shared_secret_len", 0)))
            rows.append(("Finished", "verify_data %d 字节，HMAC 校验%s" % (
                deep.get("finished_len", 0),
                "通过" if t.get("finished_verified") else "未通过")))
            rows.append(("证书验签", "%s，签名 %d 字节，验签%s" % (
                cv.get("scheme_name") or "—", cv.get("sig_len", 0),
                "通过" if cv.get("verified") else "未通过")))
    if c and not c.get("error"):
        rows.append(("服务器证书", "%s ← %s（%s ~ %s）" % (
            c.get("subject_cn", ""), c.get("issuer_cn", ""),
            (c.get("not_before") or "")[:10], (c.get("not_after") or "")[:10])))
        rows.append(("证书算法", "签名 %s / 公钥 %s（%s）" % (
            c.get("sig_algorithm", ""), c.get("pub_algorithm", ""),
            "抗量子" if c.get("cert_is_pqc") else "经典算法")))
        rows.append(("证书指纹", (c.get("fingerprint_sha256") or "")[:32] + "…"))
    if not deep.get("ok") and deep.get("error"):
        rows.append(("深度验证", "未完成：%s" % deep["error"][:60]))
    rows.append(("综合结论", report.get("overall", "")))
    for k, v in rows:
        add("%s %s" % (_pad(k, 14), v))
    if report.get("detail_file"):
        add("")
        add("详细报文（原始 hex + 逐字段说明）已保存：%s" % report["detail_file"])
    return "\n".join(out)


def interaction_full_text(report: dict) -> str:
    """写文件用的完整详情：交互框架 + 原始报文 hex + 逐字段说明。"""
    sep = "=" * 78
    return "\n".join([
        "抗量子（PQC）检测详细记录",
        sep,
        interaction_outline(report),
        "",
        sep,
        "附一：原始报文（逐条 TLS 记录 hex dump；加密记录附解密后明文）",
        sep,
        interaction_text(report),
        "",
        sep,
        "附二：逐字段说明",
        sep,
        interaction_text_verbose(report),
        "",
    ])


if __name__ == "__main__":                     # python -m modules.pqc_detect <file>
    import sys as _sys
    if len(_sys.argv) != 2:
        print("用法：python -m modules.pqc_detect <证书/公钥/私钥/原始文件>")
        _sys.exit(2)
    _info = analyze_file(_sys.argv[1])
    print("本地静态 PQC 检测")
    print("=" * 62)
    print("文件       %s" % _info.get("file", ""))
    print("大小       %d 字节" % _info.get("file_size", 0))
    print("SHA-256    %s" % _info.get("sha256", ""))
    print("类型       %s（%s）" % (_info.get("kind", ""), _info.get("format", "")))
    if _info.get("kind") == "certificate":
        print("签名算法   %s（OID %s）%s" % (
            _info.get("sig_algorithm"), _info.get("sig_oid"),
            "，长度%s" % ("一致" if _info.get("sig_size_ok") else "不一致")
            if _info.get("sig_size_ok") is not None else ""))
        print("公钥算法   %s（OID %s）%s" % (
            _info.get("pub_algorithm"), _info.get("pub_oid"),
            "，长度%s" % ("一致" if _info.get("pub_size_ok") else "不一致")
            if _info.get("pub_size_ok") is not None else ""))
    elif _info.get("kind") in ("public-key", "private-key"):
        print("算法       %s（OID %s）" % (
            _info.get("pub_algorithm"), _info.get("pub_oid")))
        if _info.get("nist_level"):
            print("NIST 等级  L%d" % _info["nist_level"])
    elif _info.get("kind") == "raw-blob":
        for _c in _info.get("candidates", []):
            print("候选       %s" % _c)
    print("-" * 62)
    print("结论       %s" % ("抗量子" if _info.get("is_pqc") else "非抗量子 / 未确认"))
    print("证据       %s" % _info.get("evidence", _info.get("cert_evidence", "")))
