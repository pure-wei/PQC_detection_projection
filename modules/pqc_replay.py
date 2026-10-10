# -*- coding: utf-8 -*-
"""Cryptographic replay checks for one captured or actively detected connection."""
from __future__ import annotations

import base64
import binascii
import hashlib
import importlib
import json
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.x509.oid import NameOID

PQC_PUBLIC_KEY_OIDS = {
    "2.16.840.1.101.3.4.4.1": ("ML-DSA-44", 1312, 2420),
    "2.16.840.1.101.3.4.4.2": ("ML-DSA-65", 1952, 3309),
    "2.16.840.1.101.3.4.4.3": ("ML-DSA-87", 2592, 4627),
    "1.3.9999.3.1": ("Falcon-512", 897, 666),
    "1.3.9999.3.4": ("Falcon-1024", 1793, 1280),
}
PQC_SIGNATURE_OIDS = {**PQC_PUBLIC_KEY_OIDS}
SIG_SCHEMES = {
    0x0403: ("ECDSA-SHA256", "ecdsa_sha256"),
    0x0503: ("ECDSA-SHA384", "ecdsa_sha384"),
    0x0603: ("ECDSA-SHA512", "ecdsa_sha512"),
    0x0804: ("RSA-PSS-SHA256", "rsa_pss_sha256"),
    0x0805: ("RSA-PSS-SHA384", "rsa_pss_sha384"),
    0x0806: ("RSA-PSS-SHA512", "rsa_pss_sha512"),
    0x0401: ("RSA-PKCS1-SHA256", "rsa_pkcs1_sha256"),
    0x0807: ("Ed25519", "ed25519"),
    0x0808: ("Ed448", "ed448"),
    0x0904: ("ML-DSA-44", "mldsa"),
    0x0905: ("ML-DSA-65", "mldsa"),
    0x0906: ("ML-DSA-87", "mldsa"),
}


class ReplayInputError(ValueError):
    pass


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def fingerprint(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest().upper()


def decode_material(value: Any, field: str = "material") -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, dict):
        raw = value.get("value", value.get("data", ""))
        encoding = str(value.get("encoding", "base64")).lower()
        if encoding == "hex":
            return decode_material("hex:" + str(raw), field)
        return decode_material(raw, field)
    if not isinstance(value, str):
        raise ReplayInputError("%s must be bytes, Base64, or prefixed text" % field)
    text = value.strip()
    try:
        if text.lower().startswith("hex:"):
            return bytes.fromhex(text[4:].replace(" ", "").replace(":", ""))
        if text.lower().startswith("base64:"):
            return base64.b64decode(text[7:], validate=True)
        if text and len(text) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in text):
            return bytes.fromhex(text)
        return base64.b64decode(text, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ReplayInputError("%s has invalid encoding: %s" % (field, exc)) from exc


def load_bundle(source: bytes | str | dict) -> dict:
    if isinstance(source, dict):
        return source
    if isinstance(source, bytes):
        source = source.decode("utf-8-sig")
    try:
        data = json.loads(source)
    except json.JSONDecodeError as exc:
        raise ReplayInputError("invalid JSON evidence bundle: %s" % exc) from exc
    if not isinstance(data, dict):
        raise ReplayInputError("evidence bundle must be a JSON object")
    return data


def _common_name(name: x509.Name) -> str:
    values = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return values[0].value if values else name.rfc4514_string()


def _public_key_parameters(public_key: Any) -> dict:
    if isinstance(public_key, rsa.RSAPublicKey):
        return {"kind": "RSA", "modulus_bits": public_key.key_size,
                "exponent": public_key.public_numbers().e}
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        point = public_key.public_bytes(serialization.Encoding.X962,
                                        serialization.PublicFormat.UncompressedPoint)
        return {"kind": "EC", "curve": public_key.curve.name, "point_bytes": len(point)}
    if isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        return {"kind": public_key.__class__.__name__}
    if hasattr(public_key, "algorithm"):
        return {"kind": str(public_key.algorithm)}
    return {"kind": type(public_key).__name__}


def _der_tlv(data: bytes, offset: int = 0) -> tuple[int, bytes, int]:
    if offset + 2 > len(data):
        raise ValueError("DER TLV is truncated")
    tag = data[offset]
    length = data[offset + 1]
    header = 2
    if length & 0x80:
        count = length & 0x7F
        if not count or offset + 2 + count > len(data):
            raise ValueError("invalid DER length")
        length = int.from_bytes(data[offset + 2:offset + 2 + count], "big")
        header += count
    end = offset + header + length
    if end > len(data):
        raise ValueError("DER value is truncated")
    return tag, data[offset + header:end], end


def _spki_public_key(spki: bytes) -> bytes:
    tag, body, end = _der_tlv(spki)
    if tag != 0x30 or end != len(spki):
        raise ValueError("SPKI is not one DER SEQUENCE")
    algorithm_tag, _, algorithm_end = _der_tlv(body)
    if algorithm_tag != 0x30:
        raise ValueError("SPKI AlgorithmIdentifier is missing")
    key_tag, key_bits, _ = _der_tlv(body, algorithm_end)
    if key_tag != 0x03 or not key_bits or key_bits[0] != 0:
        raise ValueError("SPKI public key BIT STRING is invalid")
    return key_bits[1:]


def parse_certificate_chain(chain: list[bytes] | tuple[bytes, ...], *,
                            same_handshake: bool = True) -> list[dict]:
    if not chain:
        raise ReplayInputError("the Certificate list is empty")
    parsed = []
    for index, der in enumerate(chain):
        try:
            certificate = x509.load_der_x509_certificate(der)
            spki = certificate.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            spki_key = _spki_public_key(spki)
        except Exception as exc:
            raise ReplayInputError(
                "certificate %d DER/SPKI parse failed: %s" % (index + 1, exc)) from exc
        signature_oid = certificate.signature_algorithm_oid.dotted_string
        public_oid = certificate.public_key_algorithm_oid.dotted_string
        signature_info = PQC_SIGNATURE_OIDS.get(signature_oid, (None, None, None))
        public_info = PQC_PUBLIC_KEY_OIDS.get(public_oid, (None, None, None))
        parsed.append({
            "position": "leaf" if index == 0 else str(index),
            "same_handshake": same_handshake,
            "subject": _common_name(certificate.subject),
            "issuer": _common_name(certificate.issuer),
            "serial_hex": "%X" % certificate.serial_number,
            "certificate_der_bytes": len(der),
            "certificate_der_base64": b64(der),
            "certificate_sha256": fingerprint(der),
            "signature_algorithm": certificate.signature_algorithm_oid._name or signature_oid,
            "signature_algorithm_oid": signature_oid,
            "signature_bytes": len(certificate.signature),
            "signature_parameter_set": signature_info[0],
            "signature_expected_bytes": signature_info[2],
            "spki_algorithm_oid": public_oid,
            "spki_algorithm_name": certificate.public_key_algorithm_oid._name or public_oid,
            "spki_public_key_bytes": len(spki_key),
            "spki_public_key_base64": b64(spki_key),
            "spki_public_key_sha256": fingerprint(spki_key),
            "public_key_parameters": _public_key_parameters(certificate.public_key()),
            "public_key_parameter_set": public_info[0],
            "public_key_expected_bytes": public_info[1],
            "parameter_lengths_consistent": (
                signature_info[2] in (None, len(certificate.signature)) and
                public_info[1] in (None, len(spki_key))),
        })
    return parsed


def _private_key(material: bytes):
    try:
        return serialization.load_pem_private_key(material, password=None)
    except ValueError:
        return serialization.load_der_private_key(material, password=None)


def _load_private_material(algorithm: str, material: Any) -> dict:
    normalized = algorithm.upper().replace("_", "-")
    if normalized in ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"):
        return {"mlkem_secret_key": decode_material(material, "key_exchange.private_key")}
    if normalized == "X25519":
        return {"x25519_private_key": decode_material(material, "key_exchange.private_key")}
    if normalized in ("P-256", "P-384", "SECP256R1", "SECP384R1"):
        return {"ec_private_key": _private_key(decode_material(material, "key_exchange.private_key"))}
    if isinstance(material, dict):
        classical = material.get("ecdh_private_key") or material.get("classical_private_key")
        kem = material.get("kem_private_key") or material.get("mlkem_private_key")
        if classical is None or kem is None:
            missing = "ecdh_private_key" if classical is None else "kem_private_key"
            raise ReplayInputError("key_exchange.private_key missing " + missing)
        classical_key = _load_private_material(
            str(material.get("ecdh_algorithm", "X25519")), classical)
        name = "x25519_private_key" if "x25519_private_key" in classical_key else "ec_private_key"
        return {"mlkem_secret_key": decode_material(kem, "kem private key"),
                name: classical_key[name]}
    raise ReplayInputError("unsupported key_exchange.algorithm: " + algorithm)


def _mlkem_module(parameter_set: str):
    names = {"512": "ml_kem_512", "768": "ml_kem_768", "1024": "ml_kem_1024"}
    try:
        return importlib.import_module("pqcrypto.kem." + names[parameter_set])
    except (KeyError, ImportError) as exc:
        raise ReplayInputError("unsupported or unavailable ML-KEM set %s: %s" %
                               (parameter_set, exc)) from exc


def _kem_parameter_set(algorithm: str) -> str:
    for size in ("1024", "768", "512"):
        if size in algorithm:
            return size
    raise ReplayInputError("cannot identify an ML-KEM set in " + algorithm)


def _is_hybrid(algorithm: str) -> bool:
    compact = algorithm.upper().replace("-", "")
    return any(prefix in compact for prefix in ("X25519MLKEM", "SECP256R1MLKEM", "SECP384R1MLKEM"))


def _hybrid_parts(algorithm: str, server_material: bytes) -> tuple[bytes, bytes]:
    layouts = {"X25519MLKEM768": (32, False), "SECP256R1MLKEM768": (65, True),
               "SECP384R1MLKEM1024": (97, True), "X25519MLKEM1024": (32, False)}
    layout = layouts.get(algorithm.upper().replace("-", ""))
    if layout is None:
        raise ReplayInputError("unknown hybrid layout: " + algorithm)
    size, classical_first = layout
    if len(server_material) <= size:
        raise ReplayInputError("server exchange material is too short")
    if classical_first:
        return server_material[:size], server_material[size:]
    return server_material[-size:], server_material[:-size]


def verify_key_exchange(section: dict, certificates: list[dict]) -> dict:
    required = ("algorithm", "server_public_key", "private_key", "expected_shared_secret")
    missing = [field for field in required if section.get(field) in (None, "")]
    if missing:
        return {"status": "missing", "missing": missing,
                "message": "missing: " + ", ".join(missing)}
    algorithm = str(section["algorithm"])
    server_material = decode_material(section["server_public_key"], "server exchange")
    private = _load_private_material(algorithm, section["private_key"])
    expected = decode_material(section["expected_shared_secret"], "expected shared secret")
    steps = []
    shared = b""
    if "mlkem_secret_key" in private:
        _, ciphertext = (_hybrid_parts(algorithm, server_material) if _is_hybrid(algorithm)
                         else (b"", server_material))
        shared = _mlkem_module(_kem_parameter_set(algorithm)).decrypt(
            private["mlkem_secret_key"], ciphertext)
        steps.append({"step": "ML-KEM decapsulation",
                      "parameter_set": "ML-KEM-" + _kem_parameter_set(algorithm),
                      "ciphertext_bytes": len(ciphertext),
                      "shared_secret_sha256": fingerprint(shared)})
    if "x25519_private_key" in private:
        peer = _hybrid_parts(algorithm, server_material)[0] if _is_hybrid(algorithm) else server_material
        private_key = x25519.X25519PrivateKey.from_private_bytes(private["x25519_private_key"])
        ecdh = private_key.exchange(x25519.X25519PublicKey.from_public_bytes(peer))
        steps.append({"step": "X25519 ECDH", "peer_public_bytes": len(peer),
                      "ecdh_secret_sha256": fingerprint(ecdh)})
        if not shared:
            shared = ecdh
        elif algorithm.upper().startswith("SECP"):
            shared = ecdh + shared
        else:
            shared = shared + ecdh
    elif "ec_private_key" in private:
        peer = _hybrid_parts(algorithm, server_material)[0] if _is_hybrid(algorithm) else server_material
        private_key = private["ec_private_key"]
        ecdh = private_key.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(
            private_key.curve, peer))
        steps.append({"step": "EC ECDH", "curve": private_key.curve.name,
                      "peer_public_bytes": len(peer), "ecdh_secret_sha256": fingerprint(ecdh)})
        if not shared:
            shared = ecdh
        elif algorithm.upper().startswith("SECP"):
            shared = ecdh + shared
        else:
            shared = shared + ecdh
    matches = shared == expected
    return {"status": "verified" if matches else "failed", "algorithm": algorithm,
            "server_material_bytes": len(server_material),
            "computed_shared_secret_bytes": len(shared),
            "computed_shared_secret_base64": b64(shared),
            "computed_shared_secret_sha256": fingerprint(shared),
            "expected_shared_secret_bytes": len(expected),
            "expected_shared_secret_sha256": fingerprint(expected),
            "shared_secret_matches": matches,
            "leaf_spki_sha256": certificates[0]["spki_public_key_sha256"] if certificates else "",
            "steps": steps,
            "message": "共享秘密复算一致" if matches else "共享秘密复算不一致"}


def _verify_signature(public_key: Any, scheme: str, content: bytes, signature: bytes) -> None:
    if scheme == "ed25519" and isinstance(public_key, ed25519.Ed25519PublicKey):
        public_key.verify(signature, content)
    elif scheme == "ed448" and isinstance(public_key, ed448.Ed448PublicKey):
        public_key.verify(signature, content)
    elif scheme in ("ecdsa_sha256", "ecdsa_sha384", "ecdsa_sha512") and isinstance(public_key, ec.EllipticCurvePublicKey):
        hash_class = {"ecdsa_sha256": hashes.SHA256, "ecdsa_sha384": hashes.SHA384,
                      "ecdsa_sha512": hashes.SHA512}[scheme]
        public_key.verify(signature, content, ec.ECDSA(hash_class()))
    elif scheme in ("rsa_pss_sha256", "rsa_pss_sha384", "rsa_pss_sha512") and isinstance(public_key, rsa.RSAPublicKey):
        hash_object = {"rsa_pss_sha256": hashes.SHA256, "rsa_pss_sha384": hashes.SHA384,
                       "rsa_pss_sha512": hashes.SHA512}[scheme]()
        public_key.verify(signature, content, padding.PSS(
            mgf=padding.MGF1(hash_object), salt_length=hash_object.digest_size), hash_object)
    elif scheme == "rsa_pkcs1_sha256" and isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(signature, content, padding.PKCS1v15(), hashes.SHA256())
    elif scheme == "mldsa" and hasattr(public_key, "verify"):
        public_key.verify(signature, content)
    else:
        raise ReplayInputError("leaf SPKI key and signature scheme are incompatible")


def verify_handshake_signature(section: dict, certificates: list[dict]) -> dict:
    required = ("signed_content", "signature", "scheme")
    missing = [field for field in required if section.get(field) in (None, "")]
    if not certificates:
        missing.insert(0, "certificates[0]")
    if missing:
        return {"status": "missing", "missing": missing,
                "message": "missing: " + ", ".join(missing)}
    content = decode_material(section["signed_content"], "signed handshake content")
    signature = decode_material(section["signature"], "handshake signature")
    try:
        scheme_code = int(str(section["scheme"]).replace("0x", ""), 16)
    except ValueError as exc:
        raise ReplayInputError("scheme must be a TLS scheme code") from exc
    if scheme_code not in SIG_SCHEMES:
        return {"status": "unsupported", "scheme": "0x%04X" % scheme_code,
                "message": "unsupported scheme 0x%04X" % scheme_code}
    scheme_name, scheme = SIG_SCHEMES[scheme_code]
    leaf = certificates[0]
    try:
        certificate = x509.load_der_x509_certificate(base64.b64decode(leaf["certificate_der_base64"]))
        _verify_signature(certificate.public_key(), scheme, content, signature)
        verified, error = True, ""
    except ReplayInputError:
        raise
    except Exception as exc:
        verified, error = False, "%s: %s" % (type(exc).__name__, exc)
    return {"status": "verified" if verified else "failed",
            "scheme": "0x%04X" % scheme_code, "scheme_name": scheme_name,
            "signed_content_bytes": len(content), "signed_content_sha256": fingerprint(content),
            "signature_bytes": len(signature), "signature_sha256": fingerprint(signature),
            "leaf_spki_algorithm_oid": leaf["spki_algorithm_oid"],
            "leaf_spki_public_key_sha256": leaf["spki_public_key_sha256"],
            "verified": verified, "error": error,
            "message": "用叶子证书 SPKI 公钥验签通过，服务器掌握对应私钥" if verified
                       else "叶子证书 SPKI 公钥验签失败：" + error}


def decrypt_encrypted_record(section: dict, index: int) -> dict:
    required = ("algorithm", "key", "nonce", "ciphertext")
    missing = [field for field in required if section.get(field) in (None, "")]
    if missing:
        return {"index": index, "status": "missing", "missing": missing,
                "message": "record %d missing: %s" % (index + 1, ", ".join(missing))}
    algorithm = str(section["algorithm"]).upper().replace("-", "")
    specs = {"AES128GCM": ("AES-128-GCM", 16), "AES256GCM": ("AES-256-GCM", 32),
             "CHACHA20POLY1305": ("ChaCha20-Poly1305", 32)}
    if algorithm not in specs:
        return {"index": index, "status": "unsupported",
                "message": "unsupported AEAD: " + str(section["algorithm"])}
    aead_name, key_len = specs[algorithm]
    key = decode_material(section["key"], "record key")
    nonce = decode_material(section["nonce"], "record nonce")
    ciphertext = decode_material(section["ciphertext"], "record ciphertext")
    aad = decode_material(section["aad"], "record AAD") if section.get("aad") else b""
    if len(key) != key_len:
        return {"index": index, "status": "failed",
                "message": "key length must be %d bytes, got %d" % (key_len, len(key))}
    try:
        aead = AESGCM(key) if algorithm.startswith("AES") else ChaCha20Poly1305(key)
        plaintext = aead.decrypt(nonce, ciphertext, aad)
        authenticated, error = True, ""
    except Exception as exc:
        plaintext, authenticated, error = b"", False, "%s: %s" % (type(exc).__name__, exc)
    expected_matches = None
    if section.get("expected_plaintext") not in (None, ""):
        expected = decode_material(section["expected_plaintext"], "expected plaintext")
        expected_matches = authenticated and plaintext == expected
    status = "failed" if not authenticated or expected_matches is False else "verified"
    return {"index": index, "status": status, "algorithm": aead_name,
            "key_sha256": fingerprint(key), "nonce_bytes": len(nonce),
            "aad_bytes": len(aad), "ciphertext_bytes": len(ciphertext),
            "plaintext_bytes": len(plaintext), "plaintext_base64": b64(plaintext) if plaintext else "",
            "authentication_verified": authenticated,
            "expected_plaintext_matches": expected_matches, "error": error,
            "message": ("认证解密通过，明文与记录一致" if authenticated and expected_matches is not False else
                        "认证解密失败：" + error if not authenticated else "认证解密通过，但明文与记录不一致")}


def run_replay(bundle: bytes | str | dict) -> dict:
    data = load_bundle(bundle)
    if (data.get("session") or {}).get("same_handshake") is False:
        raise ReplayInputError("evidence bundle explicitly marks certificates as another connection")
    certificate_materials = data.get("certificates") or []
    certificates = parse_certificate_chain([
        decode_material(item, "certificates[%d]" % index)
        for index, item in enumerate(certificate_materials)
    ], same_handshake=bool((data.get("session") or {}).get("same_handshake", True))) if certificate_materials else []
    key_exchange = verify_key_exchange(data.get("key_exchange") or {}, certificates)
    signature = verify_handshake_signature(data.get("handshake_signature") or {}, certificates)
    records = [decrypt_encrypted_record(item, index)
               for index, item in enumerate(data.get("encrypted_records") or [])]
    sections = [key_exchange, signature] + records
    failed = any(item.get("status") == "failed" for item in sections)
    incomplete = [item for item in sections if item.get("status") in ("missing", "unsupported")]
    conclusion = "failed" if failed else "verified" if not incomplete and records else "incomplete"
    messages = {
        "verified": "同次连接的共享秘密、握手签名和加密报文均复核一致",
        "failed": "至少一项密码学复核失败；不得认定该连接数据一致",
        "incomplete": "必要参数缺失或暂不支持；只能确认已提供材料的复核结果",
    }
    return {"session": data.get("session") or {}, "certificates": certificates,
            "key_exchange": key_exchange, "handshake_signature": signature,
            "encrypted_records": records,
            "missing": [field for item in incomplete
                        for field in item.get("missing", [item.get("message", "")])],
            "unsupported": [item.get("message", "") for item in sections
                            if item.get("status") == "unsupported"],
            "conclusion": conclusion, "message": messages[conclusion]}
