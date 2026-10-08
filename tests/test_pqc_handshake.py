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
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
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


def test_deep_verify_stops_at_finished_before_post_handshake_record():
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
                exts = (b"\x00\x2b\x00\x02\x03\x04" +
                        b"\x00\x33\x00\x24\x00\x1d\x00\x20" + server_pub)
                sh_body = (b"\x03\x03" + os.urandom(32) + bytes([len(sid)]) + sid +
                           b"\x13\x01\x00" + len(exts).to_bytes(2, "big") + exts)
                sh = b"\x02" + len(sh_body).to_bytes(3, "big") + sh_body
                sh_record = b"\x16\x03\x03" + len(sh).to_bytes(2, "big") + sh
                keys = pqc_detect._tls13_handshake_keys(shared, 0x1301, hello[5:] + sh)

                def encrypted(content, seq):
                    plain = content + b"\x16"
                    rec_header = b"\x17\x03\x03" + (len(plain) + 16).to_bytes(2, "big")
                    return rec_header + AESGCM(keys["server_key"]).encrypt(
                        pqc_detect._nonce(keys["server_iv"], seq), plain, rec_header)

                ee = b"\x08\x00\x00\x02\x00\x00"
                digest = hashlib.sha256(hello[5:] + sh + ee).digest()
                verify_data = hmac.new(keys["server_finished_key"], digest, "sha256").digest()
                finished = b"\x14\x00\x00\x20" + verify_data
                extra = b"\x17\x03\x03\x00\x20" + os.urandom(32)
                conn.sendall(sh_record + encrypted(ee, 0) + encrypted(finished, 1) + extra)

    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    result = pqc_detect.deep_verify("127.0.0.1", port, timeout=2, groups=[0x001D])
    thread.join(2)
    assert result["error"] == ""
    assert result["finished_verified"] is True
    assert [m["name"] for m in result["server_messages"]] == ["EncryptedExtensions", "Finished"]
