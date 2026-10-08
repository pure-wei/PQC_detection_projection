"""Regression tests for evidence provenance and fail-closed PQC conclusions."""

import datetime
import hashlib
import hmac
import struct

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pqcrypto.sign import ml_dsa_65

from modules import pqc_detect as p


def _der(tag, value):
    length = len(value)
    size = (length.bit_length() + 7) // 8
    encoded = bytes([length]) if length < 128 else bytes([128 + size]) + length.to_bytes(size, "big")
    return bytes([tag]) + encoded + value


def _pqc_cert(public=None, private=None, bad_length=False):
    if public is None:
        public, private = ml_dsa_65.generate_keypair()
    alg = _der(0x30, bytes.fromhex("0609608648016503040312"))
    name = bytes.fromhex("30133111300f06035504030c087071632e74657374")
    validity = _der(0x30, _der(0x17, b"260101000000Z") + _der(0x17, b"270101000000Z"))
    spki = _der(0x30, alg + _der(0x03, b"\x00" + (public[:256] if bad_length else public)))
    tbs = _der(0x30, b"\xa0\x03\x02\x01\x02\x02\x01\x01" + alg + name + validity + name + spki)
    return _der(0x30, tbs + alg + _der(0x03, b"\x00" + ml_dsa_65.sign(private, tbs)))


def _classic_cert():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "classic.test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1).not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER)


def _certificate_message(chain):
    entries = b"".join(len(der).to_bytes(3, "big") + der + b"\x00\x00" for der in chain)
    return b"\x00" + len(entries).to_bytes(3, "big") + entries


def _deep(chain, **overrides):
    result = {"host": "pqc.test", "port": 443, "ok": True, "verified": True,
              "finished_verified": True, "error": "", "group_id": 0x11EC,
              "group_name": "X25519MLKEM768", "is_pqc": True, "cipher_code": 0x1301,
              "cipher_suite": "TLS_AES_128_GCM_SHA256", "size_ok": True,
              "key_share_body": 1124, "expect_body": 1124,
              "cert_verify": {"verified": True, "scheme": "0x0905", "scheme_name": "mldsa65"},
              "cert_der": chain[0], "cert_chain_der": chain, "server_messages": [],
              "verification_status": "verified", "timings": {}}
    result.update(overrides)
    return result


def _detect(monkeypatch, deep, fetched=None, mode="deep"):
    monkeypatch.setattr(p, "deep_verify", lambda *a, **kw: deep)
    monkeypatch.setattr(p, "probe_tls", lambda *a, **kw: p._deep_to_probe(deep))
    monkeypatch.setattr(p, "probe_group_matrix", lambda *a, **kw: [])
    fetched = fetched or deep["cert_chain_der"]
    monkeypatch.setattr(p, "fetch_server_cert", lambda *a, **kw: {"der": fetched[0], "chain": fetched})
    return p.detect("pqc.test", mode=mode)


def test_certificate_list_keeps_all_entries_and_rejects_truncation():
    chain = [_pqc_cert(), _classic_cert()]
    body = _certificate_message(chain)
    assert p._cert_chain_from_certificate(body) == chain
    for malformed in (body[:-1], body + b"\x00", b"\x00\x00\x00\x03\x00\x00\x01"):
        with pytest.raises(ValueError):
            p._cert_chain_from_certificate(malformed)


def test_deep_report_uses_certificate_from_the_verified_connection(monkeypatch):
    chain = [_pqc_cert(), _pqc_cert()]
    report = _detect(monkeypatch, _deep(chain), fetched=[_classic_cert()])
    assert report["cert"]["pub_algorithm"] == "ML-DSA-65"
    assert len(report["cert_chain"]) == 2
    assert report["overall_state"] == "pqc"
    assert report["ca_trust_verified"] is False


@pytest.mark.parametrize("overrides", [
    {"size_ok": False},
    {"finished_verified": False, "verified": False},
    {"cert_verify": {"verified": False, "error": "InvalidSignature"}, "verified": False},
])
def test_failed_handshake_evidence_cannot_produce_pqc(monkeypatch, overrides):
    report = _detect(monkeypatch, _deep([_pqc_cert()], **overrides))
    assert report["overall_state"] == "unknown"
    assert report["verification_status"] == "failed"


def test_invalid_certificate_lengths_do_not_count_as_pqc(monkeypatch):
    der = _pqc_cert(bad_length=True)
    assert p.analyze_cert_der(der)["cert_is_pqc"] is False
    report = _detect(monkeypatch, _deep([der]))
    assert report["overall_state"] == "unknown"


def test_classical_issuer_blocks_full_pqc_conclusion(monkeypatch):
    report = _detect(monkeypatch, _deep([_pqc_cert(), _classic_cert()]))
    assert report["chain_fully_pqc"] is False
    assert report["overall_state"] == "partial"


def test_fast_mode_double_pqc_is_explicitly_unverified(monkeypatch):
    report = _detect(monkeypatch, _deep([_pqc_cert()]), mode="fast")
    assert report["overall_state"] != "pqc"
    assert report["verification_status"] == "unverified"
    assert "未验证" in report["overall"]


def test_classical_nist_signature_oid_is_not_pqc():
    assert p._is_pqc_oid("2.16.840.1.101.3.4.3.2") is False  # dsa-with-sha256
    assert p._is_pqc_oid("2.16.840.1.101.3.4.3.10") is False  # ecdsa-with-sha3-256


def test_mldsa_fallback_verifies_real_signature_and_rejects_wrong_scheme():
    public, private = ml_dsa_65.generate_keypair()
    cert_der = _pqc_cert(public, private)
    message = b" " * 64 + b"TLS 1.3, server CertificateVerify\x00" + b"\x42" * 32
    signature = ml_dsa_65.sign(private, message)
    # Passing no native key exercises the compatibility path for old cryptography.
    assert p._verify_cert_verify(None, 0x0905, message, signature, cert_der=cert_der)
    with pytest.raises(InvalidSignature):
        p._verify_cert_verify(None, 0x0905, message + b"!", signature, cert_der=cert_der)
    with pytest.raises(ValueError):
        p._verify_cert_verify(None, 0x0904, message, signature, cert_der=cert_der)


def _server_flight(monkeypatch, chain, private, scheme=0x0905,
                   incomplete=False, tampered=False):
    """Feed a real encrypted flight through the production TLS record parser."""
    hello, keys = p.build_client_hello("pqc.test", groups=[0x001D], return_keys=True)
    server_key = x25519.X25519PrivateKey.generate()
    server_public = server_key.public_key().public_bytes(serialization.Encoding.Raw,
                                                       serialization.PublicFormat.Raw)
    shared = server_key.exchange(keys[0x001D][1].public_key())
    session_id = hello[44:76]
    extensions = (b"\x00\x2b\x00\x02\x03\x04" +
                  b"\x00\x33\x00\x24\x00\x1d\x00\x20" + server_public)
    server_body = (b"\x03\x03" + b"\x19" * 32 + bytes([len(session_id)]) + session_id +
                   b"\x13\x01\x00" + len(extensions).to_bytes(2, "big") + extensions)

    def hs(kind, body):
        return bytes([kind]) + len(body).to_bytes(3, "big") + body

    sh = hs(2, server_body)
    transcript = hello[5:] + sh
    handshake_keys = p._tls13_handshake_keys(shared, 0x1301, transcript)
    cert_messages = hs(8, b"\x00\x00") + hs(11, _certificate_message(chain))
    transcript += cert_messages
    flight = cert_messages
    if not incomplete:
        signed = (b" " * 64 + b"TLS 1.3, server CertificateVerify\x00" +
                  hashlib.sha256(transcript).digest())
        signature = ml_dsa_65.sign(private, signed)
        if tampered:
            signature = bytes([signature[0] ^ 1]) + signature[1:]
        cv = hs(15, struct.pack(">HH", scheme, len(signature)) + signature)
        transcript += cv
        finished = hmac.new(handshake_keys["server_finished_key"],
                            hashlib.sha256(transcript).digest(), "sha256").digest()
        flight += cv + hs(20, finished)
    plain = flight + b"\x16"
    header = b"\x17\x03\x03" + (len(plain) + 16).to_bytes(2, "big")
    ciphertext = AESGCM(handshake_keys["server_key"]).encrypt(
        p._nonce(handshake_keys["server_iv"], 0), plain, header)
    incoming = b"\x16\x03\x03" + len(sh).to_bytes(2, "big") + sh + header + ciphertext

    class Socket:
        def __init__(self):
            self.incoming = incoming

        def settimeout(self, timeout):
            pass

        def sendall(self, data):
            assert data == hello

        def recv(self, size):
            chunk, self.incoming = self.incoming[:size], self.incoming[size:]
            return chunk

        def close(self):
            pass

    monkeypatch.setattr(p.socket, "create_connection", lambda *a, **kw: Socket())
    monkeypatch.setattr(p, "build_client_hello", lambda *a, **kw: (hello, keys))
    return p.deep_verify("pqc.test", groups=[0x001D])


def test_deep_verification_retains_presented_chain_before_incomplete_finished(monkeypatch):
    public, private = ml_dsa_65.generate_keypair()
    chain = [_pqc_cert(public, private), _pqc_cert()]
    result = _server_flight(monkeypatch, chain, private, incomplete=True)
    assert result["verified"] is False
    assert result["cert_der"] == chain[0]
    assert result["cert_chain_der"] == chain


@pytest.mark.parametrize("scheme,tampered,expected", [
    (0x0905, False, "verified"),
    (0x0905, True, "failed"),
    (0xFEFE, False, "unsupported"),
])
def test_real_mldsa_certificate_verify_distinguishes_invalid_and_unsupported(
        monkeypatch, scheme, tampered, expected):
    public, private = ml_dsa_65.generate_keypair()
    result = _server_flight(monkeypatch, [_pqc_cert(public, private)], private,
                            scheme=scheme, tampered=tampered)
    assert result["finished_verified"] is True
    assert result["verification_status"] == expected
    assert result["verified"] is (expected == "verified")
