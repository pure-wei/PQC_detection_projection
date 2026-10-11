"""Recheck actual wire bytes against independently generated crypto material."""
import copy
import hashlib
import hmac
import importlib
import socket
import selectors
import subprocess
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519, ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.x509.oid import NameOID
from pqcrypto.kem import ml_kem_512, ml_kem_768, ml_kem_1024


def engine():
    return importlib.import_module("modules.pqc_recheck")


def handshake(kind, body):
    return bytes([kind]) + len(body).to_bytes(3, "big") + body


def extension(kind, value):
    return kind.to_bytes(2, "big") + len(value).to_bytes(2, "big") + value


def record(kind, payload):
    return bytes([kind]) + b"\x03\x03" + len(payload).to_bytes(2, "big") + payload


def wire_fixture(group=0x11EC, cipher=0x1301):
    """Test endpoint uses native KEM/AEAD/signature, independent HKDF encoding."""
    kem = {0x0200: ml_kem_512, 0x0201: ml_kem_768, 0x0202: ml_kem_1024,
           0x11EB: ml_kem_768, 0x11EC: ml_kem_768, 0x11ED: ml_kem_1024}[group]
    pk, sk = kem.generate_keypair()
    ct, kem_shared = kem.encrypt(pk)
    parameters = {"kem_private_key": sk.hex()}
    if group in (0x11EB, 0x11EC, 0x11ED):
        if group == 0x11EC:
            client = x25519.X25519PrivateKey.generate()
            server = x25519.X25519PrivateKey.generate()
            cp = client.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            sp = server.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            scalar = client.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                          serialization.NoEncryption())
            classic = client.exchange(server.public_key())
        else:
            curve = ec.SECP256R1() if group == 0x11EB else ec.SECP384R1()
            client, server = ec.generate_private_key(curve), ec.generate_private_key(curve)
            cp = client.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
            sp = server.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
            scalar = client.private_numbers().private_value.to_bytes((curve.key_size + 7) // 8, "big")
            classic = client.exchange(ec.ECDH(), server.public_key())
        parameters["ecdh_private_key"] = scalar.hex()
        client_share = pk + cp if group == 0x11EC else cp + pk
        server_share = ct + sp if group == 0x11EC else sp + ct
        shared = kem_shared + classic if group == 0x11EC else classic + kem_shared
    else:
        client_share, server_share, shared = pk, ct, kem_shared
    gid = group.to_bytes(2, "big")
    share = gid + len(client_share).to_bytes(2, "big") + client_share
    exts = extension(43, b"\x02\x03\x04") + extension(51, len(share).to_bytes(2, "big") + share)
    ch = handshake(1, b"\x03\x03" + b"\x11" * 32 + b"\x00\x00\x02" +
                   cipher.to_bytes(2, "big") + b"\x01\x00" + len(exts).to_bytes(2, "big") + exts)
    exts = extension(43, b"\x03\x04") + extension(51, gid + len(server_share).to_bytes(2, "big") + server_share)
    sh = handshake(2, b"\x03\x03" + b"\x22" * 32 + b"\x00" + cipher.to_bytes(2, "big") +
                   b"\x00" + len(exts).to_bytes(2, "big") + exts)
    hash_name, algorithm, key_len, encryptor = {
        0x1301: ("sha256", hashes.SHA256(), 16, AESGCM),
        0x1302: ("sha384", hashes.SHA384(), 32, AESGCM),
        0x1303: ("sha256", hashes.SHA256(), 32, ChaCha20Poly1305),
    }[cipher]
    hlen = algorithm.digest_size

    def expand(secret, label, context=b"", size=hlen):
        label = b"tls13 " + label
        info = size.to_bytes(2, "big") + bytes([len(label)]) + label + bytes([len(context)]) + context
        return HKDFExpand(algorithm=algorithm, length=size, info=info).derive(secret)

    zeros = b"\0" * hlen
    early = hmac.new(zeros, zeros, hash_name).digest()
    derived = expand(early, b"derived", hashlib.new(hash_name, b"").digest())
    hs = hmac.new(derived, shared, hash_name).digest()
    s_hs = expand(hs, b"s hs traffic", hashlib.new(hash_name, ch + sh).digest())
    identity = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "wire.fixture")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(identity.public_key())
            .serial_number(7).not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
            .sign(identity, None).public_bytes(serialization.Encoding.DER))
    entry = len(cert).to_bytes(3, "big") + cert + b"\x00\x00"
    ee = handshake(8, b"\x00\x00")
    certificate = handshake(11, b"\x00" + len(entry).to_bytes(3, "big") + entry)
    transcript = ch + sh + ee + certificate
    signed = b" " * 64 + b"TLS 1.3, server CertificateVerify\0" + hashlib.new(hash_name, transcript).digest()
    signature = identity.sign(signed)
    cv = handshake(15, b"\x08\x07" + len(signature).to_bytes(2, "big") + signature)
    finished_data = hmac.new(expand(s_hs, b"finished"), hashlib.new(hash_name, transcript + cv).digest(), hash_name).digest()
    finished = handshake(20, finished_data)
    master = hmac.new(expand(hs, b"derived", hashlib.new(hash_name, b"").digest()), zeros, hash_name).digest()
    s_app = expand(master, b"s ap traffic", hashlib.new(hash_name, transcript + cv + finished).digest())

    def encrypt(payload, secret, seq, kind=22):
        key, iv = expand(secret, b"key", size=key_len), expand(secret, b"iv", size=12)
        nonce = bytes(a ^ b for a, b in zip(iv, seq.to_bytes(12, "big")))
        inner = payload + bytes([kind]) + b"\0\0"
        header = b"\x17\x03\x03" + (len(inner) + 16).to_bytes(2, "big")
        return header + encryptor(key).encrypt(nonce, inner, header)

    plain = b"HTTP/1.1 200 OK\r\n\r\nactual connection payload"
    server_stream = record(22, sh) + encrypt(ee + certificate + cv, s_hs, 0) + encrypt(finished, s_hs, 1) + encrypt(plain, s_app, 0, 23)
    parameters["expected_shared_secret"] = shared.hex()
    parameters["server_application_traffic_secret"] = s_app.hex()
    keylog = "\n".join(f"{label} {'11' * 32} {value.hex()}" for label, value in [
        ("SERVER_HANDSHAKE_TRAFFIC_SECRET", s_hs), ("SERVER_TRAFFIC_SECRET_0", s_app)])
    return {"client": record(22, ch), "server": server_stream, "parameters": parameters,
            "shared": shared, "plain": plain, "keylog": keylog, "signature": signature,
            "cert": cert, "transcript": transcript}


def session_and_parameters(fixture):
    session = engine().session_from_streams(fixture["client"], fixture["server"], label="test connection")
    parameters = dict(fixture["parameters"], session_id=session["session_id"])
    return session, parameters


@pytest.mark.parametrize("group", [0x0200, 0x0201, 0x0202, 0x11EB, 0x11EC, 0x11ED])
@pytest.mark.parametrize("cipher", [0x1301, 0x1302, 0x1303])
def test_rechecks_wire_exchange_signature_and_handshake_to_application_epoch(group, cipher):
    fixture = wire_fixture(group, cipher)
    session, parameters = session_and_parameters(fixture)
    result = engine().recheck(session, parameters)
    assert result["exchange"]["status"] == "passed", result
    assert result["exchange"]["output"]["shared_secret"] == fixture["shared"].hex()
    assert result["signature"]["status"] == "passed", result
    assert result["records"]["status"] == "passed", result
    assert result["records"]["output"]["finished_verified"] is True
    rows = result["records"]["output"]["records"]
    assert [row["sequence"] for row in rows] == [0, 1, 0]
    assert bytes.fromhex(rows[-1]["content"]) == fixture["plain"]
    assert rows[-1]["authenticated"] is True
    assert all(result[key]["steps"] for key in ["exchange", "signature", "records"])


def test_keylog_replays_capture_but_cannot_supply_kem_private_key():
    fixture = wire_fixture()
    session, _ = session_and_parameters(fixture)
    result = engine().recheck(session, keylog=fixture["keylog"])
    assert result["exchange"]["status"] == "missing"
    assert "kem_private_key" in result["exchange"]["missing"]
    assert result["signature"]["status"] == "passed"
    assert result["records"]["status"] == "passed"


def test_wrong_session_secret_bundle_is_rejected_and_wrong_keylog_has_no_match():
    fixture = wire_fixture()
    session, parameters = session_and_parameters(fixture)
    parameters["session_id"] = "another connection"
    with pytest.raises(ValueError, match="会话"):
        engine().recheck(session, parameters)
    result = engine().recheck(session, keylog=fixture["keylog"].replace("11" * 32, "33" * 32))
    assert result["records"]["status"] == "missing"
    assert result["signature"]["status"] == "missing"


def test_ciphertext_tampering_reports_authentication_failure_without_plaintext():
    fixture = wire_fixture()
    fixture["server"] = fixture["server"][:-1] + bytes([fixture["server"][-1] ^ 1])
    session, parameters = session_and_parameters(fixture)
    result = engine().recheck(session, parameters)
    assert result["records"]["status"] == "failed"
    last = result["records"]["output"]["records"][-1]
    assert last["authenticated"] is False
    assert "content" not in last


def test_keyupdate_uses_updated_application_secret_and_resets_sequence():
    fixture = wire_fixture()
    secret = bytes.fromhex(fixture["parameters"]["server_application_traffic_secret"])

    def expand(secret, label, size):
        label = b"tls13 " + label
        info = size.to_bytes(2, "big") + bytes([len(label)]) + label + b"\x00"
        return HKDFExpand(algorithm=hashes.SHA256(), length=size, info=info).derive(secret)

    def encrypted(content, kind, secret, seq):
        iv = expand(secret, b"iv", 12)
        nonce = bytes(a ^ b for a, b in zip(iv, seq.to_bytes(12, "big")))
        inner = content + bytes([kind])
        header = b"\x17\x03\x03" + (len(inner) + 16).to_bytes(2, "big")
        return header + AESGCM(expand(secret, b"key", 16)).encrypt(nonce, inner, header)

    update = handshake(24, b"\x00")
    updated = expand(secret, b"traffic upd", 32)
    fixture["server"] += encrypted(update, 22, secret, 1) + encrypted(b"after real key update", 23, updated, 0)
    session, parameters = session_and_parameters(fixture)
    result = engine().recheck(session, parameters)
    assert result["records"]["status"] == "passed", result
    last = result["records"]["output"]["records"][-1]
    assert last["sequence"] == 0
    assert bytes.fromhex(last["content"]) == b"after real key update"


def test_computing_without_a_comparison_secret_does_not_claim_consistency():
    fixture = wire_fixture()
    session, parameters = session_and_parameters(fixture)
    del parameters["expected_shared_secret"]
    result = engine().recheck(session, parameters)
    assert result["exchange"]["status"] == "computed"
    assert "expected_shared_secret" in result["exchange"]["missing"]
    parameters["expected_shared_secret"] = "00" * len(fixture["shared"])
    assert engine().recheck(session, parameters)["exchange"]["status"] == "failed"


def test_original_ephemeral_private_keys_are_enough_to_derive_application_keys():
    fixture = wire_fixture()
    session, parameters = session_and_parameters(fixture)
    del parameters["server_application_traffic_secret"]
    result = engine().recheck(session, parameters)
    assert result["records"]["status"] == "passed", result
    assert bytes.fromhex(result["records"]["output"]["records"][-1]["content"]) == fixture["plain"]


def test_import_does_not_reuse_plaintext_as_an_authentication_result():
    fixture = wire_fixture()
    session, parameters = session_and_parameters(fixture)
    session["certificate_chain"] = [fixture["cert"].hex()]
    session["signature"] = fixture["signature"].hex()
    session["signature_scheme"] = 0x0807
    session["transcript_before_cv"] = fixture["transcript"].hex()
    session["signature"] = "00" * 64
    result = engine().verify_signature(session)
    assert result["status"] == "failed"
    # Authenticated wire bytes replace imported signature observations during replay.
    assert engine().recheck(session, parameters)["signature"]["status"] == "passed"


def test_incomplete_wire_and_no_secrets_are_reported_as_missing():
    session = engine().session_from_streams(b"", b"", label="incomplete capture")
    result = engine().recheck(session)
    assert result["exchange"]["status"] == "missing"
    assert result["records"]["status"] == "missing"
    assert result["signature"]["status"] == "missing"


def test_complete_record_boundary_before_finished_cannot_claim_full_success():
    fixture = wire_fixture()
    # Both full records are present: ServerHello, then EE/Certificate/CV.
    records, _ = engine()._records(fixture["server"])
    fixture["server"] = b"".join(records[:2])
    session, parameters = session_and_parameters(fixture)
    result = engine().recheck(session, parameters)
    assert result["exchange"]["status"] == "passed"
    assert result["signature"]["status"] == "passed"
    assert result["records"]["status"] == "missing"
    assert result["records"]["output"]["finished_verified"] is None
    assert "server_finished" in result["records"]["missing"]


def test_imported_signature_transcript_must_belong_to_the_recorded_hellos():
    fixture = wire_fixture()
    session, _ = session_and_parameters(fixture)
    session.update(certificate_chain=[fixture["cert"].hex()], signature_scheme=0x0807,
                   signature=fixture["signature"].hex(), transcript_before_cv=fixture["transcript"].hex())
    other = wire_fixture()
    session["client_hello"] = engine().session_from_streams(other["client"], other["server"])["client_hello"]
    # Native verification would still pass if the transcript/connection binding were ignored.
    assert engine().verify_signature(session)["status"] == "failed"


def test_actual_kem_decapsulation_trace_includes_reencryption_and_implicit_rejection():
    fixture = wire_fixture(0x0201)
    session, parameters = session_and_parameters(fixture)
    share = bytes.fromhex(session["server_key_share"])
    session["server_key_share"] = (share[:-1] + bytes([share[-1] ^ 1])).hex()
    result = engine().verify_exchange(session, parameters)
    assert result["status"] == "failed"
    stack = list(result["steps"])
    values = []
    while stack:
        step = stack.pop()
        values.append(step["values"])
        stack.extend(step.get("children", []))
    rejection = next(v for v in values if "ciphertext_matches" in v)
    assert rejection["ciphertext_matches"] is False
    assert rejection["selected_K"].hex() == result["output"]["shared_secret"]


def test_actual_local_pqc_detection_retains_recheck_material_only_when_requested(tmp_path, pqc_openssl):
    from modules import pqc_detect
    from pqc_lab import lab
    lab.init_lab(tmp_path, pqc_openssl)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    with (tmp_path / "server.log").open("wb") as log:
        server = subprocess.Popen(lab.server_command(tmp_path, pqc_openssl, port),
                                  cwd=tmp_path / "public", stdout=log, stderr=log)
        try:
            for _ in range(100):
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=.1):
                        break
                except OSError:
                    time.sleep(.03)
            report = pqc_detect.detect("127.0.0.1", port, timeout=3, groups=[0x11EC], retain_secrets=True)
            session = engine().session_from_report(report)
            result = engine().recheck(session, session["_secrets"])
            assert result["exchange"]["status"] == "passed", result
            assert result["signature"]["status"] == "passed", result
            assert result["records"]["status"] == "passed", result
            public = pqc_detect.report_to_json(report)
            assert "recheck_session" in public
            assert "_secrets" not in str(public)
            assert session["_secrets"]["kem_private_key"] not in str(public)
            restored = engine().session_from_report(public)
            assert restored["session_id"] == session["session_id"]
            assert engine().verify_signature(restored)["status"] == "passed"
            private_free = pqc_detect.detect("127.0.0.1", port, timeout=3, groups=[0x11EC])
            assert "_recheck_secrets" not in private_free["deep"]
        finally:
            server.terminate()
            server.wait(timeout=10)


def test_actual_http_capture_and_keylog_replays_both_directions(tmp_path, pqc_openssl):
    """Record socket traffic of a genuine ML-KEM + ML-DSA HTTPS connection."""
    from pqc_lab import lab
    lab.init_lab(tmp_path, pqc_openssl)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    proxy = socket.socket()
    proxy.bind(("127.0.0.1", 0))
    proxy.listen(1)
    proxy_port = proxy.getsockname()[1]
    captured = {"client": bytearray(), "server": bytearray()}
    errors = []

    def forward():
        try:
            client, _ = proxy.accept()
            with client, socket.create_connection(("127.0.0.1", port), timeout=3) as upstream:
                with selectors.DefaultSelector() as selector:
                    selector.register(client, selectors.EVENT_READ, ("client", upstream))
                    selector.register(upstream, selectors.EVENT_READ, ("server", client))
                    while True:
                        events = selector.select(5)
                        if not events:
                            raise TimeoutError("实际连接代理等待超时")
                        for key, _ in events:
                            data = key.fileobj.recv(16384)
                            if not data:
                                return
                            direction, destination = key.data
                            captured[direction].extend(data)
                            destination.sendall(data)
        except Exception as exc:
            errors.append(exc)

    with (tmp_path / "http-server.log").open("wb") as log:
        server = subprocess.Popen(lab.server_command(tmp_path, pqc_openssl, port),
                                  cwd=tmp_path / "public", stdout=log, stderr=log)
        thread = None
        try:
            for _ in range(100):
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=.1):
                        break
                except OSError:
                    time.sleep(.03)
            thread = threading.Thread(target=forward, daemon=True)
            thread.start()
            keylog_path = tmp_path / "client-keys.log"
            client = subprocess.run([pqc_openssl, "s_client", "-connect", f"127.0.0.1:{proxy_port}",
                "-servername", "localhost", "-tls1_3", "-groups", "X25519MLKEM768", "-sigalgs", "mldsa65",
                "-verifyCAfile", str(tmp_path / "public/root.cert.pem"), "-verify_return_error",
                "-keylogfile", str(keylog_path), "-quiet", "-ign_eof"],
                input=b"GET /index.html HTTP/1.0\r\nHost: localhost\r\n\r\n", capture_output=True, timeout=10)
            thread.join(5)
            assert not thread.is_alive() and not errors
            assert b"HTTP/1.0 200" in client.stdout, client.stderr
            session = engine().session_from_streams(bytes(captured["client"]), bytes(captured["server"]))
            result = engine().recheck(session, keylog=keylog_path.read_text())
            assert result["exchange"]["status"] == "missing"
            assert result["signature"]["status"] == "passed", result
            assert result["records"]["status"] == "passed", result
            rows = result["records"]["output"]["records"]
            server_plain = b"".join(bytes.fromhex(r["content"]) for r in rows if r["direction"] == "server" and r["content_type"] == 23)
            client_plain = b"".join(bytes.fromhex(r["content"]) for r in rows if r["direction"] == "client" and r["content_type"] == 23)
            assert (tmp_path / "public/index.html").read_bytes() in server_plain
            assert client_plain == b"GET /index.html HTTP/1.0\r\nHost: localhost\r\n\r\n"
        finally:
            proxy.close()
            server.terminate()
            server.wait(timeout=10)
            if thread is not None:
                thread.join(5)
