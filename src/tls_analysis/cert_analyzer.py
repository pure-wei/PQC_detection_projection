"""X.509 证书深度分析：识别签名算法/公钥类型，判断是否抗量子。

用法:
    result = analyze_certificate(der_bytes)
    print(f"Signature: {result.sig_algorithm_name}")
    print(f"Quantum-safe: {result.is_quantum_safe}")
"""

import hashlib
from dataclasses import dataclass, field

from ..utils.logger import get_logger

log = get_logger(__name__)

# ── OID → 算法名映射表 ─────────────────────────────────────────────────────

SIG_ALGORITHM_OIDS = {
    # RSA
    "1.2.840.113549.1.1.5":  "RSA-SHA1",
    "1.2.840.113549.1.1.11": "RSA-SHA256",
    "1.2.840.113549.1.1.12": "RSA-SHA384",
    "1.2.840.113549.1.1.13": "RSA-SHA512",
    "1.2.840.113549.1.1.14": "RSA-SHA224",
    # ECDSA
    "1.2.840.10045.4.1":    "ECDSA-SHA1",
    "1.2.840.10045.4.3.1":  "ECDSA-SHA224",
    "1.2.840.10045.4.3.2":  "ECDSA-SHA256",
    "1.2.840.10045.4.3.3":  "ECDSA-SHA384",
    "1.2.840.10045.4.3.4":  "ECDSA-SHA512",
    # DSA / EdDSA / RSASSA-PSS
    "1.2.840.10040.4.3":    "DSA-SHA1",
    "1.3.101.112":          "Ed25519",
    "1.3.101.113":          "Ed448",
    "1.2.840.113549.1.1.10": "RSA-PSS",
    # 国密
    "1.2.156.10197.1.301":   "SM2-with-SM3",
    "1.2.156.10197.1.501":   "SM2-SM3 (variant)",
    "1.2.156.10197.1.504":   "SM2-SHA256",
    # NIST PQC (ML-DSA / Dilithium)
    "1.3.6.1.4.1.2.267.7.4.4":  "ML-DSA-44 (Dilithium2)",
    "1.3.6.1.4.1.2.267.7.6.5":  "ML-DSA-65 (Dilithium3)",
    "1.3.6.1.4.1.2.267.7.8.7":  "ML-DSA-87 (Dilithium5)",
    # Falcon / SPHINCS+
    "1.3.9999.3.1":           "Falcon-512",
    "1.3.9999.3.4":           "Falcon-1024",
    "1.3.9999.6.4.1":         "SPHINCS+-SHA2-128s",
    "1.3.9999.6.4.3":         "SPHINCS+-SHA2-128f",
    "1.3.9999.6.5.3":         "SPHINCS+-SHA2-192s",
    "1.3.9999.6.6.3":         "SPHINCS+-SHA2-256s",
}

PUBKEY_ALGORITHM_OIDS = {
    # 经典
    "1.2.840.113549.1.1.1":   "RSA",
    "1.2.840.10045.2.1":      "EC (ECDSA)",
    "1.2.840.10040.4.1":      "DSA",
    "1.3.101.112":            "Ed25519",
    "1.3.101.113":            "Ed448",
    # 国密
    "1.2.156.10197.1.301":    "SM2",
    # PQC KEM
    "1.3.6.1.4.1.2.267.5.1.1":  "ML-KEM-512 (Kyber512)",
    "1.3.6.1.4.1.2.267.5.2.2":  "ML-KEM-768 (Kyber768)",
    "1.3.6.1.4.1.2.267.5.3.3":  "ML-KEM-1024 (Kyber1024)",
    # PQC 签名
    "1.3.6.1.4.1.2.267.7.4.4":  "ML-DSA-44 (Dilithium2)",
    "1.3.6.1.4.1.2.267.7.6.5":  "ML-DSA-65 (Dilithium3)",
    "1.3.6.1.4.1.2.267.7.8.7":  "ML-DSA-87 (Dilithium5)",
    "1.3.9999.3.1":           "Falcon-512",
    "1.3.9999.3.4":           "Falcon-1024",
}

EC_CURVE_OIDS = {
    "1.2.840.10045.3.1.7":    "secp256r1 (P-256)",
    "1.3.132.0.34":           "secp384r1 (P-384)",
    "1.3.132.0.35":           "secp521r1 (P-521)",
    "1.3.132.0.10":           "secp256k1",
    "1.3.132.0.1":            "sect163k1",
    "1.2.840.10045.3.1.1":    "secp192r1 (P-192)",
    "1.3.101.110":            "X25519",
    "1.3.101.111":            "X448",
    "1.2.156.10197.1.301":    "SM2 (curveSM2)",
}

# OID 前缀落在这几个范围即视为 PQC 算法
PQC_OID_PREFIXES = [
    "1.3.6.1.4.1.2.267",    # NIST / ML-DSA / ML-KEM
    "1.3.9999",              # Falcon / SPHINCS+
    "2.16.840.1.114027",    # Composite signatures
    "1.3.6.1.4.1.22554",    # BSI / German PQC
]

# NIST PQC 参数表：OID -> (名称, 公钥字节数, 签名字节数, NIST 安全级别)
# OID 只是标签；公钥/签名的实际字节数必须与规范一致，否则视为
# 标识与数据不符（错标或伪造）。参考 FIPS 203/204/205 与 Falcon Round 4。
PQC_PARAMS = {
    # ML-KEM (FIPS 203)
    "1.3.6.1.4.1.2.267.5.1.1": ("ML-KEM-512",  800,   768, 1),
    "1.3.6.1.4.1.2.267.5.2.2": ("ML-KEM-768",  1184, 1088, 3),
    "1.3.6.1.4.1.2.267.5.3.3": ("ML-KEM-1024", 1568, 1568, 5),
    # ML-DSA (FIPS 204)
    "1.3.6.1.4.1.2.267.7.4.4": ("ML-DSA-44",   1312, 2420, 2),
    "1.3.6.1.4.1.2.267.7.6.5": ("ML-DSA-65",   1952, 3309, 3),
    "1.3.6.1.4.1.2.267.7.8.7": ("ML-DSA-87",   2592, 4627, 5),
    # SLH-DSA / SPHINCS+ (FIPS 205)
    "1.3.9999.6.4.1": ("SPHINCS+-SHA2-128s", 32, 7856, 1),
    "1.3.9999.6.4.3": ("SPHINCS+-SHA2-128f", 32, 17088, 1),
    "1.3.9999.6.5.3": ("SPHINCS+-SHA2-192s", 48, 16224, 3),
    "1.3.9999.6.6.3": ("SPHINCS+-SHA2-256s", 64, 29792, 5),
    # Falcon (Round 4 决选)
    "1.3.9999.3.1": ("Falcon-512",  897,  666, 1),
    "1.3.9999.3.4": ("Falcon-1024", 1793, 1280, 5),
}


@dataclass
class CertAnalysis:
    """X.509 证书分析结果。"""

    # 基本信息
    subject_cn: str = ""
    issuer_cn: str = ""
    issuer_org: str = ""
    not_before: str = ""
    not_after: str = ""
    serial_number: str = ""
    fingerprint_sha256: str = ""

    # 签名
    sig_algorithm_oid: str = ""
    sig_algorithm_name: str = ""
    sig_is_pqc: bool = False
    sig_is_sm: bool = False
    sig_actual_bytes: int = 0        # 实际签名字节数（用于 NIST 校验）

    # 公钥
    pubkey_algorithm_oid: str = ""
    pubkey_type: str = ""
    pubkey_size_bits: int = 0
    pubkey_curve: str = ""
    pubkey_is_pqc: bool = False
    pubkey_raw_bytes: int = 0
    pubkey_key_bytes: int = 0        # SPKI BIT STRING 原始密钥字节数

    # 原始密码学材料（供 verification 验签）
    signature_bytes: bytes = b""
    tbs_certificate_bytes: bytes = b""
    pubkey_der_bytes: bytes = b""

    # 安全评估
    is_quantum_safe: bool = False
    nist_security_level: int = 0
    security_notes: list = field(default_factory=list)
    nist_checks: list = field(default_factory=list)

    # 元信息
    raw_der_size: int = 0
    parse_error: str = ""


def _is_pqc_oid(oid_str: str) -> bool:
    return any(oid_str.startswith(prefix) for prefix in PQC_OID_PREFIXES)


def _is_sm_oid(oid_str: str) -> bool:
    return oid_str.startswith("1.2.156.10197")


def _estimate_nist_level(sig_oid: str, pubkey_size: int) -> int:
    """PQC 算法直接查参数表；经典算法按位强度粗估（仅对经典计算机有效）。"""
    if sig_oid in PQC_PARAMS:
        return PQC_PARAMS[sig_oid][3]

    if pubkey_size >= 15360:
        return 3
    if pubkey_size >= 7680:
        return 2
    if pubkey_size >= 3072:
        return 2
    if pubkey_size >= 256:
        return 1

    return 0


def _validate_nist_params(result, sig_oid: str, pubkey_oid: str):
    """OID 声明的 PQC 算法，其签名/公钥实际字节数必须等于规范值。

    不符即在 nist_checks 中标记"标识与数据不符,可能伪造"。
    """
    if sig_oid in PQC_PARAMS:
        name, _pk, sig_bytes, _lvl = PQC_PARAMS[sig_oid]
        actual = result.sig_actual_bytes
        if actual == sig_bytes:
            result.nist_checks.append(f"✅ 签名 {actual}B 符合 {name} (规范 {sig_bytes}B)")
        else:
            result.nist_checks.append(
                f"⚠️ OID 声明 {name} 但实际签名 {actual}B (规范 {sig_bytes}B) — 标识与数据不符,可能伪造"
            )

    if pubkey_oid in PQC_PARAMS:
        name, pk_bytes, _sig, _lvl = PQC_PARAMS[pubkey_oid]
        actual = result.pubkey_key_bytes
        if actual == pk_bytes:
            result.nist_checks.append(f"✅ 公钥 {actual}B 符合 {name} (规范 {pk_bytes}B)")
        else:
            result.nist_checks.append(
                f"⚠️ OID 声明 {name} 但实际公钥 {actual}B (规范 {pk_bytes}B) — 标识与数据不符,可能伪造"
            )


def _get_cn(name) -> str:
    try:
        for attr in name:
            oid_str = attr.oid.dotted_string if hasattr(attr.oid, 'dotted_string') else str(attr.oid)
            if "2.5.4.3" in oid_str:
                return str(attr.value)
    except Exception:
        pass
    return ""


def _get_org(name) -> str:
    try:
        for attr in name:
            oid_str = attr.oid.dotted_string if hasattr(attr.oid, 'dotted_string') else str(attr.oid)
            if "2.5.4.10" in oid_str:
                return str(attr.value)
    except Exception:
        pass
    return ""


def _get_ec_curve_oid(pubkey) -> str:
    try:
        curve = pubkey.curve
        return curve.oid.dotted_string if hasattr(curve.oid, 'dotted_string') else str(curve.oid)
    except Exception:
        return ""


def _get_pubkey_der_size(pubkey) -> int:
    try:
        from cryptography.hazmat.primitives import serialization
        der = pubkey.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return len(der)
    except Exception:
        return 0


def analyze_certificate(der_bytes: bytes) -> CertAnalysis:
    """解析 X.509 DER 证书，识别算法并做 PQC 判定与 NIST 校验。"""
    result = CertAnalysis(raw_der_size=len(der_bytes))
    result.fingerprint_sha256 = hashlib.sha256(der_bytes).hexdigest()

    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448

        cert = x509.load_der_x509_certificate(der_bytes)

        # 保留原始密码学材料，供 verification 模块真实验签
        result.signature_bytes = cert.signature
        result.tbs_certificate_bytes = cert.tbs_certificate_bytes
        result.sig_actual_bytes = len(cert.signature)
        try:
            result.pubkey_der_bytes = cert.public_key().public_bytes_raw()
        except Exception:
            pass

        # 基本信息
        result.subject_cn = _get_cn(cert.subject)
        result.issuer_cn = _get_cn(cert.issuer)
        result.issuer_org = _get_org(cert.issuer)
        result.not_before = str(cert.not_valid_before_utc) if cert.not_valid_before_utc else ""
        result.not_after = str(cert.not_valid_after_utc) if cert.not_valid_after_utc else ""
        result.serial_number = str(cert.serial_number)

        # 签名算法
        sig_oid = cert.signature_algorithm_oid.dotted_string
        result.sig_algorithm_oid = sig_oid
        result.sig_algorithm_name = SIG_ALGORITHM_OIDS.get(sig_oid, f"Unknown ({sig_oid})")
        result.sig_is_pqc = _is_pqc_oid(sig_oid)
        result.sig_is_sm = _is_sm_oid(sig_oid)

        # 公钥类型（cryptography 能识别的经典类型）
        try:
            pubkey = cert.public_key()
        except Exception:
            pubkey = None
        pubkey_oid_str = ""

        if isinstance(pubkey, rsa.RSAPublicKey):
            result.pubkey_type = "RSA"
            result.pubkey_size_bits = pubkey.key_size
            pubkey_oid_str = "1.2.840.113549.1.1.1"
            result.pubkey_raw_bytes = _get_pubkey_der_size(pubkey)

        elif isinstance(pubkey, ec.EllipticCurvePublicKey):
            result.pubkey_type = "EC"
            result.pubkey_size_bits = pubkey.key_size
            pubkey_oid_str = "1.2.840.10045.2.1"
            curve_oid = _get_ec_curve_oid(pubkey)
            result.pubkey_curve = EC_CURVE_OIDS.get(curve_oid, curve_oid)
            result.pubkey_raw_bytes = _get_pubkey_der_size(pubkey)
            if "sm2" in result.pubkey_curve.lower() or "1.2.156.10197" in curve_oid:
                pubkey_oid_str = "1.2.156.10197.1.301"
                result.pubkey_is_pqc = False
                result.pubkey_type = "SM2"

        elif isinstance(pubkey, ed25519.Ed25519PublicKey):
            result.pubkey_type = "Ed25519"
            result.pubkey_size_bits = 256
            result.pubkey_raw_bytes = 32 + 12

        elif isinstance(pubkey, ed448.Ed448PublicKey):
            result.pubkey_type = "Ed448"
            result.pubkey_size_bits = 456
            result.pubkey_raw_bytes = 57 + 12

        else:
            result.pubkey_type = "Unknown"
            result.pubkey_raw_bytes = _get_pubkey_der_size(pubkey) if pubkey is not None else 0

        # 从 SPKI 提取原始密钥字节数——cryptography 无法解析的 PQC 公钥
        # 也能拿到长度，使 NIST 校验基于真实数据而非仅 OID
        spki_oid, spki_key_bytes = _parse_spki(_extract_spki_from_cert_der(der_bytes))
        if spki_key_bytes:
            result.pubkey_key_bytes = spki_key_bytes
        if not pubkey_oid_str and spki_oid:
            pubkey_oid_str = spki_oid

        result.pubkey_algorithm_oid = pubkey_oid_str
        result.pubkey_is_pqc = _is_pqc_oid(pubkey_oid_str)

        # 安全评估 + 数据驱动校验
        result.is_quantum_safe = result.sig_is_pqc or result.pubkey_is_pqc
        result.nist_security_level = _estimate_nist_level(sig_oid, result.pubkey_size_bits)
        _validate_nist_params(result, sig_oid, pubkey_oid_str)

        if result.is_quantum_safe:
            result.security_notes.append(
                f"抗量子安全: 使用 PQC 算法，NIST Level {result.nist_security_level}"
            )
        else:
            if result.sig_is_sm:
                result.security_notes.append(
                    f"国密算法 {result.sig_algorithm_name}: 合规但非抗量子"
                )
            else:
                result.security_notes.append(
                    f"经典密码 {result.sig_algorithm_name}: "
                    f"无法抵抗量子计算机攻击"
                )
            if result.nist_security_level > 0:
                result.security_notes.append(
                    f"经典 NIST Level {result.nist_security_level} "
                    f"仅对经典计算机有效，量子计算机下不安全"
                )

    except ImportError:
        result.parse_error = "cryptography library not installed. Install with: pip install cryptography"
    except Exception as e:
        result.parse_error = f"Certificate parsing failed: {e}"

    return result


def cert_analysis_to_dict(result: CertAnalysis) -> dict:
    """转成 JSON 可序列化的 dict。"""
    return {
        "subject_cn": result.subject_cn,
        "issuer_cn": result.issuer_cn,
        "issuer_org": result.issuer_org,
        "not_before": result.not_before,
        "not_after": result.not_after,
        "fingerprint_sha256": result.fingerprint_sha256[:16] + "...",
        "sig_algorithm_oid": result.sig_algorithm_oid,
        "sig_algorithm_name": result.sig_algorithm_name,
        "sig_is_pqc": result.sig_is_pqc,
        "sig_is_sm": result.sig_is_sm,
        "pubkey_type": result.pubkey_type,
        "pubkey_size_bits": result.pubkey_size_bits,
        "pubkey_curve": result.pubkey_curve,
        "pubkey_is_pqc": result.pubkey_is_pqc,
        "pubkey_raw_bytes": result.pubkey_raw_bytes,
        "pubkey_key_bytes": result.pubkey_key_bytes,
        "sig_actual_bytes": result.sig_actual_bytes,
        "is_quantum_safe": result.is_quantum_safe,
        "nist_security_level": result.nist_security_level,
        "security_notes": result.security_notes,
        "nist_checks": result.nist_checks,
        "parse_error": result.parse_error,
    }


# ── DER 底层解析 ───────────────────────────────────────────────────────────
# cryptography 尚无法解析 ML-KEM / ML-DSA / SPHINCS+ 公钥，
# 以下函数按 RFC 5280 结构手工解析 SPKI，拿到算法 OID 与原始密钥长度。

def _decode_oid(oid_bytes: bytes) -> str:
    """DER 编码的 OID 字节 → 点分字符串。"""
    if not oid_bytes:
        return ""
    oid_parts = [str(oid_bytes[0] // 40), str(oid_bytes[0] % 40)]
    val = 0
    for b in oid_bytes[1:]:
        val = (val << 7) | (b & 0x7F)
        if not (b & 0x80):
            oid_parts.append(str(val))
            val = 0
    return ".".join(oid_parts)


def _parse_spki(der_bytes: bytes) -> tuple[str, int]:
    """解析 SubjectPublicKeyInfo DER，返回 (算法 OID, 原始密钥字节数)。

    SubjectPublicKeyInfo ::= SEQUENCE {
        algorithm         AlgorithmIdentifier,  -- SEQUENCE { OID, params }
        subjectPublicKey  BIT STRING }

    不依赖 cryptography 识别密钥类型，任何算法（含 PQC）通用；
    解析失败返回 ("", 0)。
    """
    def _read_len(data: bytes, i: int) -> tuple[int, int]:
        if i >= len(data):
            raise ValueError("truncated")
        first = data[i]
        if first & 0x80:
            n = first & 0x7F
            if n == 0 or n > 4 or i + 1 + n > len(data):
                raise ValueError("bad length")
            return int.from_bytes(data[i + 1:i + 1 + n], "big"), i + 1 + n
        return first, i + 1

    try:
        i = 0
        if der_bytes[i] != 0x30:
            raise ValueError("not a sequence")
        _, i = _read_len(der_bytes, i + 1)

        # AlgorithmIdentifier 的内容区间 [alg_start, alg_end)
        if i >= len(der_bytes) or der_bytes[i] != 0x30:
            raise ValueError("no AlgorithmIdentifier")
        alg_len, alg_start = _read_len(der_bytes, i + 1)
        alg_end = alg_start + alg_len

        # AlgorithmIdentifier 中第一个 OID
        j = alg_start
        while j < alg_end and der_bytes[j] != 0x06:
            _, j = _read_len(der_bytes, j + 1)
        if j >= alg_end or der_bytes[j] != 0x06:
            raise ValueError("no OID")
        oid_len, k = _read_len(der_bytes, j + 1)
        oid_str = _decode_oid(der_bytes[k:k + oid_len])

        # BIT STRING 内容长度减去前置 unused-bits 字节即原始密钥长度
        i = alg_end
        if i >= len(der_bytes) or der_bytes[i] != 0x03:
            raise ValueError("no BIT STRING")
        bs_len, j = _read_len(der_bytes, i + 1)
        return oid_str, bs_len - 1
    except Exception:
        return "", 0


def _extract_spki_from_cert_der(der_bytes: bytes) -> bytes:
    """从证书 DER 中切出完整的 subjectPublicKeyInfo TLV。

    按 Certificate → TBSCertificate 结构遍历，subjectPublicKeyInfo 即
    第一个以 SEQUENCE(AlgorithmIdentifier, 首字段为 OID) 开头的子节点。
    """
    def _read_len(data: bytes, i: int) -> tuple[int, int]:
        if i >= len(data):
            raise ValueError("truncated")
        first = data[i]
        if first & 0x80:
            n = first & 0x7F
            if n == 0 or n > 4 or i + 1 + n > len(data):
                raise ValueError("bad length")
            return int.from_bytes(data[i + 1:i + 1 + n], "big"), i + 1 + n
        return first, i + 1

    def _children(seq_value: bytes):
        off, out = 0, []
        while off < len(seq_value):
            tag = seq_value[off]
            off += 1
            length, off = _read_len(seq_value, off)
            out.append((tag, seq_value[off:off + length]))
            off += length
        return out

    def _encode_len(n: int) -> bytes:
        if n < 0x80:
            return bytes([n])
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return bytes([0x80 | len(b)]) + b

    try:
        if not der_bytes or der_bytes[0] != 0x30:
            return b""
        _, i = _read_len(der_bytes, 1)
        cert = _children(der_bytes[i:])
        if not cert or cert[0][0] != 0x30:
            return b""
        tbs = cert[0][1]

        for tag, value in _children(tbs):
            if tag != 0x30:
                continue
            inner = _children(value)
            if not inner or inner[0][0] != 0x30:
                continue
            alg = _children(inner[0][1])
            if alg and alg[0][0] == 0x06:
                return bytes([0x30]) + _encode_len(len(value)) + value
    except Exception:
        pass
    return b""
