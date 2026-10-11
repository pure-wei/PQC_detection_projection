"""Real key shares must be usable by a conforming TLS peer."""

import pytest
import hashlib
import hmac
import os
import socket
import struct
import threading

from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from pqcrypto.kem import ml_kem_768, ml_kem_1024

from modules import pqc_detect


@pytest.mark.parametrize("group,kem,ec_len,kem_first", [
    (0x11EC, ml_kem_768, 32, True),
    (0x11EB, ml_kem_768, 65, False),
    (0x11ED, ml_kem_1024, 97, False),
])
def test_hybrid_share_is_valid_and_derives_server_secret(group, kem, ec_len, kem_first):
    client_share, key_handle = pqc_detect._client_share_and_key(group)
    assert key_handle is not None

    kem_public = client_share[:kem.PUBLIC_KEY_SIZE] if kem_first else client_share[ec_len:]
    ec_public = client_share[kem.PUBLIC_KEY_SIZE:] if kem_first else client_share[:ec_len]
    assert len(kem_public) == kem.PUBLIC_KEY_SIZE
    ciphertext, kem_secret = kem.encrypt(kem_public)

    if ec_len == 32:
        server_ec = x25519.X25519PrivateKey.generate()
        server_public = server_ec.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        classical_secret = server_ec.exchange(x25519.X25519PublicKey.from_public_bytes(ec_public))
    else:
        curve = ec.SECP256R1() if ec_len == 65 else ec.SECP384R1()
        server_ec = ec.generate_private_key(curve)
        server_public = server_ec.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        classical_secret = server_ec.exchange(
            ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(curve, ec_public))
    server_share = ciphertext + server_public if kem_first else server_public + ciphertext
    expected = kem_secret + classical_secret if kem_first else classical_secret + kem_secret

    assert pqc_detect._derive_shared(group, server_share, key_handle) == expected


def test_classical_x25519_share_has_private_key_for_deep_verification():
    share, key_handle = pqc_detect._client_share_and_key(0x001D)
    assert len(share) == 32
    assert key_handle is not None


def test_support_matrix_checks_primary_hybrid_groups_even_after_classical_selection(monkeypatch):
    def fake_probe(host, port, timeout, groups):
        selected = groups[0] if groups[0] == 0x11EC else 0x001D
        return {"ok": True, "group_id": selected,
                "group_name": pqc_detect.lookup_group(selected)[0], "size_ok": True}

    monkeypatch.setattr(pqc_detect, "probe_tls", fake_probe)
    rows = pqc_detect.probe_group_matrix("example.com", skip_groups=[0x001D])
    x25519_mlkem = next(row for row in rows if row["group_id"] == "0x11EC")
    assert x25519_mlkem["supported"] is True


def test_classical_result_describes_this_connection_without_global_claim():
    evidence = pqc_detect.transport_evidence({
        "ok": True, "verified": False, "is_pqc": False,
        "group_id": 0x001D, "group_name": "X25519",
    })
    assert "本次连接" in evidence
    assert "该站点不支持" not in evidence


@pytest.mark.parametrize("cipher,hash_name,key_len,aead", [
    (0x1301, "sha256", 16, "aes"),
    (0x1302, "sha384", 32, "aes"),
    (0x1303, "sha256", 32, "chacha"),
])
@pytest.mark.parametrize("failure", ["", "key_derivation", "server_handshake", "finished",
                                     "certificate_verify", "certificate_verify_empty"])
def test_deep_verify_tracks_completed_and_failed_stages(cipher, hash_name, key_len, aead, failure):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def server():
        with listener:
            conn, _ = listener.accept()
            with conn:
                header = conn.recv(5)
                length = int.from_bytes(header[3:5], "big")
                hello = header
                while len(hello) < 5 + length:
                    hello += conn.recv(5 + length - len(hello))
                body = hello[9:]
                sid_len = body[34]
                sid = body[35:35 + sid_len]
                offset = 35 + sid_len
                cipher_len = int.from_bytes(body[offset:offset + 2], "big")
                offset += 2 + cipher_len
                offset += 1 + body[offset]
                ext_len = int.from_bytes(body[offset:offset + 2], "big")
                offset += 2
                end = offset + ext_len
                client_pub = None
                while offset < end:
                    kind, size = struct.unpack(">HH", body[offset:offset + 4])
                    value = body[offset + 4:offset + 4 + size]
                    if kind == 51:
                        assert value[2:4] == b"\x00\x1d"
                        client_pub = value[6:38]
                    offset += 4 + size
                assert client_pub and len(client_pub) == 32

                server_key = x25519.X25519PrivateKey.generate()
                server_pub = server_key.public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                shared = server_key.exchange(x25519.X25519PublicKey.from_public_bytes(client_pub))
                share = server_pub[:-1] if failure == "key_derivation" else server_pub
                share_ext = b"\x00\x1d" + len(share).to_bytes(2, "big") + share
                exts = (b"\x00\x2b\x00\x02\x03\x04" + b"\x00\x33" +
                        len(share_ext).to_bytes(2, "big") + share_ext)
                sh_body = (b"\x03\x03" + os.urandom(32) + bytes([len(sid)]) + sid +
                           cipher.to_bytes(2, "big") + b"\x00" + len(exts).to_bytes(2, "big") + exts)
                sh = b"\x02" + len(sh_body).to_bytes(3, "big") + sh_body
                sh_record = b"\x16\x03\x03" + len(sh).to_bytes(2, "big") + sh
                keys = pqc_detect._tls13_handshake_keys(shared, cipher, hello[5:] + sh)

                def encrypted(content, seq):
                    plain = content + b"\x16"
                    rec_header = b"\x17\x03\x03" + (len(plain) + 16).to_bytes(2, "big")
                    encryptor = AESGCM if aead == "aes" else ChaCha20Poly1305
                    return rec_header + encryptor(keys["server_key"]).encrypt(
                        pqc_detect._nonce(keys["server_iv"], seq), plain, rec_header)

                ee = b"\x08\x00\x00\x02\x00\x00"
                flight = ee
                if failure.startswith("certificate_verify"):
                    from test_pqc_authenticity import _pqc_cert
                    cert = _pqc_cert()
                    cert_entry = len(cert).to_bytes(3, "big") + cert + b"\x00\x00"
                    cert_body = b"\x00" + len(cert_entry).to_bytes(3, "big") + cert_entry
                    flight += b"\x0b" + len(cert_body).to_bytes(3, "big") + cert_body
                    # An authenticated, truncated CertificateVerify must fail at signature parsing.
                    cv_body = b"" if failure == "certificate_verify_empty" else b"\x09\x05\x00"
                    flight += b"\x0f" + len(cv_body).to_bytes(3, "big") + cv_body
                digest = hashlib.new(hash_name, hello[5:] + sh + flight).digest()
                verify_data = hmac.new(keys["server_finished_key"], digest, hash_name).digest()
                if failure == "finished":
                    verify_data = b""
                finished = b"\x14" + len(verify_data).to_bytes(3, "big") + verify_data
                extra = b"\x17\x03\x03\x00\x20" + os.urandom(32)
                encrypted_flight = encrypted(flight, 0)
                if failure == "server_handshake":
                    encrypted_flight = encrypted_flight[:-1] + bytes([encrypted_flight[-1] ^ 1])
                conn.sendall(sh_record + encrypted_flight + encrypted(finished, 1) + extra)

    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    result = pqc_detect.deep_verify("127.0.0.1", port, timeout=2, groups=[0x001D])
    thread.join(2)
    expected_stage = "certificate_verify" if failure.startswith("certificate_verify") else failure
    if failure:
        assert result["verification_error_kind"] == "invalid"
        assert result["failed_stage"] == expected_stage
    else:
        assert result["error"] == ""
        assert [m["name"] for m in result["server_messages"]] == ["EncryptedExtensions", "Finished"]
    assert result["finished_verified"] is (expected_stage in ("", "certificate_verify"))
    if failure == "finished":
        assert result["finished_len"] == 0
    if failure == "key_derivation":
        assert "key_derivation" not in result
        return
    assert result["key_derivation"] == {
        "hash_name": hash_name, "aead": aead, "key_len": key_len,
        "iv_len": 12, "finished_key_len": hashlib.new(hash_name).digest_size,
    }
    exported = pqc_detect.report_to_json({"deep": result})
    assert exported["deep_verification"]["key_derivation"] == result["key_derivation"]
    if failure:
        assert exported["deep_verification"]["failed_stage"] == expected_stage
