# -*- coding: utf-8 -*-
"""Offline demonstrations of real PQC operations and a compact parameter table.

The hybrid flows are educational demonstrations, not TLS or IETF Composite
ML-DSA implementations. Keys are ephemeral; the ML-KEM calculation trace
intentionally contains random seeds, private intermediates and shared secrets.
Signature demos also expose temporary teaching values; public signing APIs
continue to return public artifacts only.
"""

import base64
import hashlib
import hmac
import importlib
import os

from cryptography.exceptions import InvalidSignature, InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from modules.mlkem_trace import Trace, run_calculation
from modules import classical_signature_trace, falcon_trace, ml_dsa_trace, slh_dsa_trace


_KEM_MODULES = {"ML-KEM-%s" % size: "ml_kem_%s" % size
                for size in (512, 768, 1024)}
KEM_VARIANTS = tuple(_KEM_MODULES)
CLASSICAL_VARIANTS = ("X25519", "P-256", "P-384")

_SIGN_MODULES = {"ML-DSA-%s" % size: "ml_dsa_%s" % size
                 for size in (44, 65, 87)}
_SIGN_MODULES.update({
    "SLH-DSA-%s-%s%s" % (hash_name, size, speed):
        "sphincs_%s_%s%s_simple" % (hash_name.lower(), size, speed)
    for hash_name in ("SHA2", "SHAKE")
    for size in (128, 192, 256)
    for speed in ("s", "f")
})
_SIGN_MODULES.update({"Falcon-512": "falcon_512", "Falcon-1024": "falcon_1024"})
SIGNATURE_VARIANTS = tuple(_SIGN_MODULES)
CLASSICAL_SIGNATURE_VARIANTS = (
    "Ed25519", "ECDSA-P256", "ECDSA-P384", "RSA-PSS-2048", "RSA-PSS-3072",
)
_HYBRID_SIGNATURE_FORMAT = "crypto-analysis-tool-hybrid-signature-v1"


def _pq_module(kind, name):
    try:
        return importlib.import_module("pqcrypto.%s.%s" % (kind, name))
    except ImportError as exc:
        raise RuntimeError("缺少 pqcrypto；请运行 pip install -r requirements.txt") from exc


def _derive_key(classical_secret, pq_secret, salt):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                info=b"crypto-analysis-tool hybrid demo v1").derive(
                    classical_secret + pq_secret)


def run_kem_demo(algorithm: str = "ML-KEM-512") -> dict:
    """Show a standalone ML-KEM encapsulation and decapsulation round trip."""
    if algorithm not in _KEM_MODULES:
        raise ValueError("不支持的密钥封装算法：%s" % algorithm)
    kem = _pq_module("kem", _KEM_MODULES[algorithm])
    calculation = run_calculation(algorithm, kem)
    public, ciphertext = calculation["public_key"], calculation["ciphertext"]
    sender_shared, receiver_shared = calculation["sender_shared"], calculation["receiver_shared"]
    changed_shared = calculation["changed_shared"]

    def fingerprint(value):
        return hashlib.sha256(value).hexdigest()[:16]

    return {
        "algorithm": algorithm,
        "public_key_bytes": len(public),
        "ciphertext_bytes": len(ciphertext),
        "shared_secret_bytes": len(sender_shared),
        "shared_secret_matches": sender_shared == receiver_shared,
        "changed_ciphertext_changes_secret": changed_shared != sender_shared,
        "sender_fingerprint": fingerprint(sender_shared),
        "receiver_fingerprint": fingerprint(receiver_shared),
        "public_key_base64": base64.b64encode(public).decode("ascii"),
        "ciphertext_base64": base64.b64encode(ciphertext).decode("ascii"),
        "calculation_trace": calculation["trace"],
    }


def run_hybrid_demo(message: bytes, kem_algorithm="ML-KEM-768",
                    classical_algorithm="X25519") -> dict:
    """ECDH + ML-KEM -> HKDF-SHA256 -> AES-256-GCM round trip."""
    if not isinstance(message, bytes):
        raise TypeError("message 必须为 bytes")
    if kem_algorithm not in _KEM_MODULES:
        raise ValueError("不支持的密钥封装算法：%s" % kem_algorithm)
    if classical_algorithm not in CLASSICAL_VARIANTS:
        raise ValueError("不支持的经典密钥交换算法：%s" % classical_algorithm)
    kem = _pq_module("kem", _KEM_MODULES[kem_algorithm])

    if classical_algorithm == "X25519":
        receiver_ecdh = x25519.X25519PrivateKey.generate()
        sender_ecdh = x25519.X25519PrivateKey.generate()
        public_format = (serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        sender_classical = sender_ecdh.exchange(receiver_ecdh.public_key())
        receiver_classical = receiver_ecdh.exchange(sender_ecdh.public_key())
    else:
        curve = ec.SECP256R1() if classical_algorithm == "P-256" else ec.SECP384R1()
        receiver_ecdh = ec.generate_private_key(curve)
        sender_ecdh = ec.generate_private_key(curve)
        public_format = (serialization.Encoding.X962,
                         serialization.PublicFormat.UncompressedPoint)
        sender_classical = sender_ecdh.exchange(ec.ECDH(), receiver_ecdh.public_key())
        receiver_classical = receiver_ecdh.exchange(ec.ECDH(), sender_ecdh.public_key())
    receiver_pub = receiver_ecdh.public_key().public_bytes(*public_format)
    sender_pub = sender_ecdh.public_key().public_bytes(*public_format)

    calculation = run_calculation(kem_algorithm, kem)
    kem_public, kem_ciphertext = calculation["public_key"], calculation["ciphertext"]
    sender_pq, receiver_pq = calculation["sender_shared"], calculation["receiver_shared"]
    salt, nonce = os.urandom(16), os.urandom(12)
    aad = b"pqc-hybrid-demo-v1"
    sender_key = _derive_key(sender_classical, sender_pq, salt)
    receiver_key = _derive_key(receiver_classical, receiver_pq, salt)
    ciphertext = AESGCM(sender_key).encrypt(nonce, message, aad)
    recovered = AESGCM(receiver_key).decrypt(nonce, ciphertext, aad)
    altered = bytearray(ciphertext)
    altered[-1] ^= 1
    try:
        AESGCM(receiver_key).decrypt(nonce, bytes(altered), aad)
    except InvalidTag:
        tamper_rejected = True
    else:
        tamper_rejected = False

    trace = Trace(calculation["trace"]["steps"])
    info = b"crypto-analysis-tool hybrid demo v1"
    ikm = sender_classical + sender_pq
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
    if okm != sender_key:
        raise RuntimeError("HKDF 计算展示与实际 AES 密钥不一致")
    trace.add("混合密钥派生：HKDF-SHA256", "IKM=ECDH_secret || K；PRK=HMAC-SHA256(salt,IKM)；T₁=HMAC-SHA256(PRK,info || 0x01)；AES_key=T₁", {
        "classical_algorithm": classical_algorithm, "ecdh_secret": sender_classical,
        "MLKEM_K": sender_pq, "IKM": ikm, "salt": salt, "info": info,
        "PRK": prk, "expand_input": info + b"\x01", "AES_key": sender_key,
    }, "RFC 5869，§2.2–2.3（输出长度 32 字节，只需一个块）")
    trace.add("混合加密：使用派生密钥", "AES-256-GCM(AES_key,nonce,明文,AAD) → 密文 || 16 字节认证标签", {
        "nonce": nonce, "AAD": aad, "plaintext": message,
        "aes_ciphertext": ciphertext, "recovered": recovered,
        "tampered_aes_ciphertext": bytes(altered), "tamper_rejected": tamper_rejected,
    }, "本项目混合加密演示（使用 cryptography AESGCM）")

    return {
        "kem_algorithm": kem_algorithm,
        "classical_algorithm": classical_algorithm,
        "recovered": recovered,
        "kem_shared_secret_matches": sender_pq == receiver_pq,
        "ecdh_shared_secret_matches": sender_classical == receiver_classical,
        "tamper_rejected": tamper_rejected,
        "kem_public_key_bytes": len(kem_public),
        "kem_ciphertext_bytes": len(kem_ciphertext),
        "classical_public_key_bytes": len(receiver_pub),
        **({"x25519_public_key_bytes": len(receiver_pub)}
           if classical_algorithm == "X25519" else {}),
        "sender_public_key_base64": base64.b64encode(sender_pub).decode("ascii"),
        "kem_public_key_base64": base64.b64encode(kem_public).decode("ascii"),
        "kem_ciphertext_base64": base64.b64encode(kem_ciphertext).decode("ascii"),
        "ciphertext_base64": base64.b64encode(ciphertext).decode("ascii"),
        "nonce_base64": base64.b64encode(nonce).decode("ascii"),
        "calculation_trace": calculation["trace"],
    }


def run_signature_demo(message: bytes, algorithm: str) -> dict:
    """Generate, sign and verify with one PQC signature family."""
    if not isinstance(message, bytes):
        raise TypeError("message 必须为 bytes")
    if algorithm not in _SIGN_MODULES:
        raise ValueError("不支持的签名算法：%s" % algorithm)
    module = _pq_module("sign", _SIGN_MODULES[algorithm])
    public, secret = module.generate_keypair()
    signature = module.sign(secret, message)
    calculation_trace = _new_signature_trace(algorithm)
    _append_pq_signature_calculation(algorithm, message, public, signature, secret,
                                     Trace(calculation_trace["steps"]), module)
    verified = bool(module.verify(public, message, signature))
    altered_verified = bool(module.verify(public, message + b"!", signature))
    replay_altered = _signature_family(algorithm).verify(algorithm, message+b"!", public, signature)
    if replay_altered != altered_verified:
        raise RuntimeError("修改消息后的签名重放与原生验签不一致")
    Trace(calculation_trace["steps"]).add("修改消息后重验", "保持公钥和签名，M_tampered=M || 0x21；重新计算消息相关值并验签", {
        "original_message": message, "changed_message": message+b"!",
        "native_verified": altered_verified, "replay_verified": replay_altered}, "本项目独立篡改试验")
    return {
        "algorithm": algorithm,
        "public_key_bytes": len(public),
        "signature_bytes": len(signature),
        "public_key_base64": base64.b64encode(public).decode("ascii"),
        "signature_base64": base64.b64encode(signature).decode("ascii"),
        "verified": verified,
        "altered_verified": altered_verified,
        "calculation_trace": calculation_trace,
    }


def _signature_family(algorithm):
    if algorithm.startswith("ML-DSA-"):
        return ml_dsa_trace
    if algorithm.startswith("SLH-DSA-"):
        return slh_dsa_trace
    if algorithm.startswith("Falcon-"):
        return falcon_trace
    raise ValueError("不支持的后量子签名算法")


def _new_signature_trace(algorithm, classical_algorithm=None):
    family = _signature_family(algorithm)
    parameters = family.parameters(algorithm)
    description = {
        ml_dsa_trace: "n/q：多项式长度与模数；k/l：矩阵维数；η/τ/β：采样与挑战参数；γ₁/γ₂/ω：掩码、分解与提示限制。",
        slh_dsa_trace: "n：哈希输出字节数；h/d/h′：超树总高度、层数与单层高度；a/k：FORS 高度与树数；w：WOTS+ 进制。实际消息编码遵循本项目的 SPHINCS+ simple 后端。",
        falcon_trace: "n/q：NTRU 环维数与模数；nonce 为本次签名的 40 字节随机值；平方范数上界决定短向量是否通过验签。",
    }[family]
    if classical_algorithm is not None:
        parameters = {"post_quantum": parameters,
                      "classical": classical_signature_trace.parameters(classical_algorithm),
                      "hybrid_format": _HYBRID_SIGNATURE_FORMAT, "acceptance_rule": "传统验签 AND 后量子验签"}
        description += "\n传统参数列出实际曲线/模数、摘要、编码、盐与 nonce 规则；混合签名绑定算法、公钥和消息。"
    return dict(algorithm=(classical_algorithm+" + "+algorithm if classical_algorithm else algorithm),
                parameters=parameters, parameter_description=description, source=family.SOURCE,
                parameter_reference="算法参数与实际后端："+family.SOURCE,
                parameter_note="详情包含本轮临时秘密，供教学查看，不自动保存。标明原始数值、确定性重算与代数重建；原生库未返回的随机输入或拒绝尝试不代填。签名生成仍由原生库执行，重放计算不是恒定时间的生产实现。",
                steps=[])


def _append_pq_signature_calculation(algorithm, message, public, signature, secret, trace, native):
    scope = trace.add(algorithm+" 本次签名计算", "以本轮实际密钥、消息和签名进行解码、重建与完整验签", {
        "message": message, "public_key": public, "signature": signature}, "本项目教学重放")
    replay = _signature_family(algorithm).calculate(algorithm, message, public, signature, scope, secret)
    verified = bool(native.verify(public, message, signature))
    scope.add("原生验签与计算重放校验", "原生验签结果 == 教学数学验签结果", {
        "native_verified": verified, "replay_verified": replay}, "本项目交叉校验")
    if not replay or replay != verified:
        raise RuntimeError("签名计算重放与原生验签不一致")


def _classical_signing_key(algorithm):
    if algorithm == "Ed25519":
        private = ed25519.Ed25519PrivateKey.generate()
        encoding, public_format, label = (
            serialization.Encoding.Raw, serialization.PublicFormat.Raw, "Raw")
    elif algorithm.startswith("ECDSA-"):
        curve = ec.SECP256R1() if algorithm == "ECDSA-P256" else ec.SECP384R1()
        private = ec.generate_private_key(curve)
        encoding, public_format, label = (
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint, "X9.62 未压缩点")
    else:
        private = rsa.generate_private_key(public_exponent=65537,
                                           key_size=int(algorithm.rsplit("-", 1)[1]))
        encoding, public_format, label = (
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo, "SPKI DER")
    return private, private.public_key().public_bytes(encoding, public_format), label


def _classical_signature_arguments(algorithm):
    if algorithm == "Ed25519":
        return ()
    if algorithm.startswith("ECDSA-"):
        digest = hashes.SHA256() if algorithm == "ECDSA-P256" else hashes.SHA384()
        return (ec.ECDSA(digest),)
    return (padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256())


def _load_classical_signing_public(algorithm, public):
    if algorithm == "Ed25519":
        return ed25519.Ed25519PublicKey.from_public_bytes(public)
    if algorithm.startswith("ECDSA-"):
        curve = ec.SECP256R1() if algorithm == "ECDSA-P256" else ec.SECP384R1()
        return ec.EllipticCurvePublicKey.from_encoded_point(curve, public)
    key = serialization.load_der_public_key(public)
    if (not isinstance(key, rsa.RSAPublicKey) or
            key.key_size != int(algorithm.rsplit("-", 1)[1]) or
            key.public_numbers().e != 65537):
        raise ValueError("RSA 公钥与所选签名参数不符")
    return key


def _hybrid_signing_data(message, pq_algorithm, classical_algorithm,
                         pq_public, classical_public):
    """Bind both algorithm identifiers and public keys to the same message."""
    fields = (classical_algorithm.encode("ascii"), pq_algorithm.encode("ascii"),
              classical_public, pq_public, message)
    return (_HYBRID_SIGNATURE_FORMAT.encode("ascii") + b"\x00" +
            b"".join(len(field).to_bytes(8, "big") + field for field in fields))


def sign_hybrid_message(message: bytes, pq_algorithm="ML-DSA-65",
                        classical_algorithm="Ed25519") -> dict:
    """Create two bound signatures; return only public data and metadata.

    This application-specific dual-signature format is an offline teaching
    format, not the wire format of the IETF Composite ML-DSA specification.
    ECDSA uses DER signatures; RSA uses SHA-256/MGF1-SHA256 and a 32-byte salt.
    """
    return _sign_hybrid_message(message, pq_algorithm, classical_algorithm)


def _sign_hybrid_message(message, pq_algorithm, classical_algorithm, include_trace=False):
    if not isinstance(message, bytes):
        raise TypeError("message 必须为 bytes")
    if pq_algorithm not in _SIGN_MODULES:
        raise ValueError("不支持的后量子签名算法：%s" % pq_algorithm)
    if classical_algorithm not in CLASSICAL_SIGNATURE_VARIANTS:
        raise ValueError("不支持的传统签名算法：%s" % classical_algorithm)
    module = _pq_module("sign", _SIGN_MODULES[pq_algorithm])
    pq_public, pq_secret = module.generate_keypair()
    private, classical_public, encoding = _classical_signing_key(classical_algorithm)
    data = _hybrid_signing_data(message, pq_algorithm, classical_algorithm,
                                pq_public, classical_public)
    classical_signature = private.sign(
        data, *_classical_signature_arguments(classical_algorithm))
    pq_signature = module.sign(pq_secret, data)
    result = {
        "format": _HYBRID_SIGNATURE_FORMAT,
        "pq_algorithm": pq_algorithm,
        "classical_algorithm": classical_algorithm,
        "classical_public_key_encoding": encoding,
        "classical_signature_encoding": "DER" if classical_algorithm.startswith("ECDSA-") else "Raw",
        "classical_public_key_bytes": len(classical_public),
        "pq_public_key_bytes": len(pq_public),
        "public_key_bytes": len(classical_public) + len(pq_public),
        "classical_signature_bytes": len(classical_signature),
        "pq_signature_bytes": len(pq_signature),
        "signature_bytes": len(classical_signature) + len(pq_signature),
        "classical_public_key_base64": base64.b64encode(classical_public).decode("ascii"),
        "pq_public_key_base64": base64.b64encode(pq_public).decode("ascii"),
        "classical_signature_base64": base64.b64encode(classical_signature).decode("ascii"),
        "pq_signature_base64": base64.b64encode(pq_signature).decode("ascii"),
    }
    if include_trace:
        calculation_trace = _new_signature_trace(pq_algorithm, classical_algorithm)
        trace = Trace(calculation_trace["steps"])
        fields = [("classical_algorithm", classical_algorithm.encode("ascii")),
                  ("pq_algorithm", pq_algorithm.encode("ascii")),
                  ("classical_public_key", classical_public), ("pq_public_key", pq_public),
                  ("message", message)]
        trace.add("混合签名绑定数据", "signed_data=format || 0x00 || Σ(length_8BE(field) || field)", {
            "format": _HYBRID_SIGNATURE_FORMAT, "message": message,
            "fields": [dict(name=name, length=len(value), length_prefix=len(value).to_bytes(8, "big"), value=value)
                       for name, value in fields], "signed_data": data,
            "signed_data_sha256": hashlib.sha256(data).digest()}, "本项目双签名格式 v1",
            "两份签名均签署这里的完整绑定数据。每个字段的长度前缀为 8 字节大端整数。")
        classical_trace = trace.add(classical_algorithm+" 本次传统签名计算", "对同一份绑定数据签名；使用实际临时密钥和签名重算", {}, "RFC 8032 / FIPS 186-5 / RFC 8017")
        if not classical_signature_trace.calculate(classical_algorithm, data, classical_public, classical_signature, classical_trace, private):
            raise RuntimeError("传统签名计算重放失败")
        _append_pq_signature_calculation(pq_algorithm, data, pq_public, pq_signature, pq_secret, trace, module)
        result["calculation_trace"] = calculation_trace
    return result


def verify_hybrid_signature(message: bytes, signature_data: dict) -> dict:
    """Verify both components using public data; reject incomplete artifacts.

    The caller supplies the expected message. Stored size/encoding metadata
    is informational; verification uses the algorithm identifiers and bytes.
    """
    if not isinstance(message, bytes):
        raise TypeError("message 必须为 bytes")
    result = {"classical_verified": False, "pq_verified": False, "verified": False}
    if not isinstance(signature_data, dict):
        return result
    try:
        pq_algorithm = signature_data["pq_algorithm"]
        classical_algorithm = signature_data["classical_algorithm"]
        if (signature_data.get("format") != _HYBRID_SIGNATURE_FORMAT or
                pq_algorithm not in _SIGN_MODULES or
                classical_algorithm not in CLASSICAL_SIGNATURE_VARIANTS):
            return result
        pq_public, classical_public, pq_signature, classical_signature = (
            base64.b64decode(signature_data[field], validate=True) for field in (
                "pq_public_key_base64", "classical_public_key_base64",
                "pq_signature_base64", "classical_signature_base64"))
        data = _hybrid_signing_data(message, pq_algorithm, classical_algorithm,
                                    pq_public, classical_public)
    except (KeyError, TypeError, ValueError):
        return result

    try:
        public = _load_classical_signing_public(classical_algorithm, classical_public)
        public.verify(classical_signature, data,
                      *_classical_signature_arguments(classical_algorithm))
    except (InvalidSignature, UnsupportedAlgorithm, TypeError, ValueError):
        pass
    else:
        result["classical_verified"] = True

    module = _pq_module("sign", _SIGN_MODULES[pq_algorithm])
    try:
        result["pq_verified"] = bool(module.verify(pq_public, data, pq_signature))
    except (TypeError, ValueError):
        pass
    result["verified"] = result["classical_verified"] and result["pq_verified"]
    return result


def run_hybrid_signature_demo(message: bytes, pq_algorithm="ML-DSA-65",
                              classical_algorithm="Ed25519") -> dict:
    """Show AND verification and independent message/signature tampering."""
    result = _sign_hybrid_message(message, pq_algorithm, classical_algorithm, include_trace=True)
    checks = {
        "original": verify_hybrid_signature(message, result),
        "changed_message": verify_hybrid_signature(message + b"!", result),
    }
    for component in ("classical", "pq"):
        changed = dict(result)
        field = component + "_signature_base64"
        signature = bytearray(base64.b64decode(changed[field]))
        signature[0] ^= 1
        changed[field] = base64.b64encode(signature).decode("ascii")
        checks["changed_%s_signature" % component] = verify_hybrid_signature(message, changed)
    result["checks"] = checks
    Trace(result["calculation_trace"]["steps"]).add("混合 AND 验签与独立篡改", "accept=classical_verified AND pq_verified；分别修改消息与两份签名后重验", {
        **checks, "AND_result": checks["original"]["verified"]}, "本项目双签名验签规则")
    return result


def comparison_rows() -> list:
    """Representative parameters, with public-key/signature encoding noted.

    RSA public keys use SPKI DER with exponent 65537. EC points are uncompressed;
    ECDSA signatures are DER, with maximum lengths rather than fixed lengths.
    """
    return [
        {"name": "X25519", "kind": "经典密钥交换", "public_size": "32", "output_size": "32 字节共享秘密", "standard": "RFC 7748", "basis": "椭圆曲线离散对数"},
        {"name": "ECDH-P256", "kind": "经典密钥交换", "public_size": "65（未压缩点）", "output_size": "32 字节共享秘密", "standard": "SP 800-56A", "basis": "椭圆曲线离散对数"},
        {"name": "ECDH-P384", "kind": "经典密钥交换", "public_size": "97（未压缩点）", "output_size": "48 字节共享秘密", "standard": "SP 800-56A", "basis": "椭圆曲线离散对数"},
        {"name": "ML-KEM-768", "kind": "后量子密钥封装", "public_size": "1184", "output_size": "1088 字节封装密文", "standard": "FIPS 203", "basis": "模格"},
        {"name": "Ed25519", "kind": "经典数字签名", "public_size": "32", "output_size": "64 字节签名", "standard": "RFC 8032", "basis": "椭圆曲线离散对数"},
        {"name": "ECDSA-P256", "kind": "经典数字签名", "public_size": "65（未压缩点）", "output_size": "DER 签名 ≤72 字节；r‖s 为 64 字节", "standard": "FIPS 186-5 / RFC 3279", "basis": "椭圆曲线离散对数"},
        {"name": "ECDSA-P384", "kind": "经典数字签名", "public_size": "97（未压缩点）", "output_size": "DER 签名 ≤104 字节；r‖s 为 96 字节", "standard": "FIPS 186-5 / RFC 3279", "basis": "椭圆曲线离散对数"},
        {"name": "RSA-PSS-2048", "kind": "经典数字签名", "public_size": "294（SPKI DER）", "output_size": "256 字节签名", "standard": "FIPS 186-5 / RFC 8017", "basis": "整数分解"},
        {"name": "RSA-PSS-3072", "kind": "经典数字签名", "public_size": "422（SPKI DER）", "output_size": "384 字节签名", "standard": "FIPS 186-5 / RFC 8017", "basis": "整数分解"},
        {"name": "SM2", "kind": "经典数字签名（国密）", "public_size": "65（未压缩点）", "output_size": "64 字节签名（r‖s）；DER 长度可变", "standard": "GB/T 32918.2-2016", "basis": "椭圆曲线离散对数"},
        {"name": "ML-DSA-65", "kind": "后量子数字签名", "public_size": "1952", "output_size": "3309 字节签名", "standard": "FIPS 204", "basis": "模格"},
        {"name": "SLH-DSA-SHA2-128s", "kind": "后量子数字签名", "public_size": "32", "output_size": "7856 字节签名", "standard": "FIPS 205", "basis": "哈希"},
        {"name": "Falcon-512", "kind": "后量子数字签名", "public_size": "897", "output_size": "可变长签名（约 650 字节）", "standard": "FIPS 206 制定中", "basis": "NTRU 格"},
    ]
