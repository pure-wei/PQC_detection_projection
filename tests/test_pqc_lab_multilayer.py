"""Real loopback protocol/signature experiments, not generated UI fixtures."""
import base64
import copy
import json
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

PQ_SIGNATURES = (
    "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
    "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f",
    "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
    "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f",
    "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
    "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f",
    "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f",
    "Falcon-512", "Falcon-1024",
)


@pytest.mark.parametrize("protocol", ["tcp", "udp"])
@pytest.mark.parametrize("signature", PQ_SIGNATURES)
def test_real_signed_network_messages(tmp_path, protocol, signature):
    from pqc_lab import lab
    from pqc_lab.profiles import LabProfile
    from pqc_lab.signed_messages import SignedMessageServer
    profile = LabProfile(protocol=protocol, signature=signature)
    with SignedMessageServer(tmp_path, ("127.0.0.1", 0), profile) as server:
        result = lab.verify_lab(tmp_path, None, server.server_address[1],
                                profile=profile, message="实际网络消息：你好")
    assert result["status"] == "passed", result
    assert all(item["passed"] for item in result["checks"])
    assert result["summary"]["protocol"] == protocol.upper()
    assert result["summary"]["signature_algorithm"] == signature
    assert result["summary"]["message_signature_verified"] is True
    assert result["summary"]["transport_confidentiality"] is False
    assert {"reject_changed_message", "reject_changed_signature", "reject_wrong_key",
            "reject_replay", "reject_wrong_protocol"} <= {item["id"] for item in result["checks"]}
    assert result["profile"]["protocol"] == protocol
    if protocol == "udp" and signature == "SLH-DSA-SHA2-256f":
        assert result["summary"]["response_fragments"] > 1
        assert result["summary"]["signature_bytes"] == 49856
    assert not any("key" in item.name for item in (tmp_path / "public").iterdir())


@pytest.mark.parametrize("classic", ["Ed25519", "ECDSA-P256", "ECDSA-P384",
                                    "RSA-PSS-2048", "RSA-PSS-3072"])
def test_hybrid_network_signature_requires_both_components(tmp_path, classic):
    from pqc_lab import lab
    from pqc_lab.profiles import LabProfile
    from pqc_lab.signed_messages import SignedMessageServer
    profile = LabProfile(protocol="udp", signature="ML-DSA-65", classical_signature=classic)
    with SignedMessageServer(tmp_path, ("127.0.0.1", 0), profile) as server:
        result = lab.verify_lab(tmp_path, None, server.server_address[1], profile=profile)
    assert result["status"] == "passed", result
    assert result["summary"]["classical_signature_verified"] is True
    assert result["summary"]["pq_signature_verified"] is True
    assert {"reject_classical_component", "reject_pq_component"} <= {
        item["id"] for item in result["checks"]}


@pytest.mark.parametrize("group", ["X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024"])
@pytest.mark.parametrize("signature,size,sigsize", [("ML-DSA-44", 1312, 2420),
                                                 ("ML-DSA-65", 1952, 3309),
                                                 ("ML-DSA-87", 2592, 4627)])
def test_real_tls_algorithm_combinations(tmp_path, pqc_openssl, group, signature, size, sigsize):
    from pqc_lab import lab
    from pqc_lab.profiles import LabProfile
    from pqc_lab.tls_frontend import ConcurrentTLSServer
    profile = LabProfile(protocol="tls" if signature == "ML-DSA-87" else "https",
                         group=group, signature=signature)
    lab.init_lab(tmp_path, pqc_openssl, profile=profile)
    server = ConcurrentTLSServer(("127.0.0.1", 0),
        lambda port: lab.server_command(tmp_path, pqc_openssl, port, profile=profile),
        tmp_path / "public", tmp_path / "server.log")
    server.start()
    try:
        result = lab.verify_lab(tmp_path, pqc_openssl, server.server_address[1], profile=profile)
        assert result["status"] == "passed", result
        summary = result["summary"]
        assert summary["group_name"].startswith(group)
        assert summary["certificate_algorithm"] == signature
        assert summary["certificate_public_key_bytes"] == size
        assert summary["certificate_signature_bytes"] == sigsize
        ids = {item["id"] for item in result["checks"]}
        assert ("https_get" in ids) is (profile.protocol == "https")
        assert ("tls_session" in ids) is (profile.protocol == "tls")
    finally:
        server.close()


def test_switching_tls_identity_preserves_original(tmp_path, pqc_openssl):
    from pqc_lab import lab
    from pqc_lab.profiles import LabProfile
    lab.init_lab(tmp_path, pqc_openssl)
    original = (tmp_path / "public/server.cert.pem").read_bytes()
    lab.init_lab(tmp_path, pqc_openssl, profile=LabProfile(signature="ML-DSA-44"))
    lab.init_lab(tmp_path, pqc_openssl)
    assert (tmp_path / "public/server.cert.pem").read_bytes() == original


@pytest.mark.parametrize("protocol", ["https", "tcp"])
def test_stopped_tls_port_can_immediately_restart_in_selected_mode(tmp_path, pqc_openssl, protocol):
    from pqc_lab import lab
    from pqc_lab.profiles import LabProfile
    from pqc_lab.signed_messages import SignedMessageServer
    from pqc_lab.tls_frontend import ConcurrentTLSServer
    lab.init_lab(tmp_path, pqc_openssl)
    def tls_server(port):
        return ConcurrentTLSServer(("127.0.0.1", port),
            lambda worker_port: lab.server_command(tmp_path, pqc_openssl, worker_port),
            tmp_path / "public", tmp_path / "restart.log")
    with tls_server(0) as first:
        port = first.server_address[1]
        occupied = tls_server(port)
        with pytest.raises(OSError):
            occupied.start()
        # The server closes first, producing TIME_WAIT on its listening port.
        with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
            connection.sendall(b"GET /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n")
            response = bytearray()
            while chunk := connection.recv(4096):
                response.extend(chunk)
            assert b"307" in response
    profile = LabProfile(protocol=protocol)
    second = tls_server(port) if profile.is_tls else SignedMessageServer(tmp_path, ("127.0.0.1", port), profile)
    with second:
        result = lab.verify_lab(tmp_path, pqc_openssl, port, profile=profile)
    assert result["status"] == "passed", result


def test_signature_proof_is_bound_to_pinned_identity():
    from pqc_lab.profiles import LabProfile
    from pqc_lab.signed_messages import SigningIdentity, verify_proof
    identity = SigningIdentity(LabProfile(protocol="tcp", classical_signature="Ed25519"))
    payload = b"expected challenge and message"
    proof = identity.sign(payload)
    assert verify_proof(payload, proof, identity.public)["verified"]
    changed = copy.deepcopy(proof)
    changed["classical_signature_base64"] = base64.b64encode(b"x" * 64).decode()
    assert not verify_proof(payload, changed, identity.public)["verified"]
    assert not verify_proof(payload + b"x", proof, identity.public)["verified"]
    other = SigningIdentity(LabProfile(protocol="tcp", classical_signature="Ed25519"))
    assert not verify_proof(payload, proof, other.public)["verified"]


def test_oversized_network_message_fails_with_new_report(tmp_path):
    from pqc_lab import lab
    from pqc_lab.profiles import LabProfile
    public = tmp_path / "public"
    public.mkdir()
    (public / "evidence.json").write_text('{"status":"passed"}')
    result = lab.verify_lab(tmp_path, None, 12345, profile=LabProfile(protocol="udp"),
                            message="你" * 1366)
    assert result["status"] == "failed"
    assert json.loads((public / "evidence.json").read_text())["status"] == "failed"


@pytest.mark.parametrize("kwargs", [{"protocol": "ipsec"}, {"group": "unknown"},
                                  {"signature": "Falcon-512"},
                                  {"classical_signature": "Ed25519"}])
def test_invalid_tls_profile_rejected_before_start(kwargs):
    from pqc_lab.profiles import LabProfile
    with pytest.raises(ValueError):
        LabProfile(**kwargs)


def test_udp_cli_status_and_retest_use_managed_protocol_and_port(tmp_path):
    script = Path(__file__).resolve().parents[1] / "pqc_lab/lab.py"
    def free_port():
        with socket.socket() as connection:
            connection.bind(("127.0.0.1", 0))
            return connection.getsockname()[1]
    port, http_port = free_port(), free_port()
    while port == http_port:
        http_port = free_port()
    command = [sys.executable, str(script)]
    with (tmp_path / "manager.log").open("wb") as log:
        process = subprocess.Popen(command + ["serve", "--base", str(tmp_path),
            "--protocol", "udp", "--signature", "Falcon-512", "--port", str(port),
            "--http-port", str(http_port)], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 15
            report = tmp_path / "public/evidence.json"
            while time.monotonic() < deadline:
                if report.exists() and json.loads(report.read_text())["status"] == "passed":
                    break
                assert process.poll() is None, (tmp_path / "manager.log").read_text()
                time.sleep(.05)
            status = subprocess.run(command + ["status", "--base", str(tmp_path)], capture_output=True, timeout=10)
            assert status.returncode == 0, status.stdout + status.stderr
            retest = subprocess.run(command + ["verify", "--base", str(tmp_path)], capture_output=True, timeout=15)
            assert retest.returncode == 0, retest.stdout + retest.stderr
            result = json.loads(report.read_text())
            assert result["target"] == "127.0.0.1:" + str(port)
            assert result["profile"]["signature"] == "Falcon-512"
        finally:
            subprocess.run(command + ["stop", "--base", str(tmp_path)], capture_output=True, timeout=10)
            if process.poll() is None:
                process.wait(timeout=10)


@pytest.mark.parametrize("protocol", ["tcp", "udp"])
@pytest.mark.parametrize("character", ["\\", "\x00"])
def test_full_byte_limit_includes_json_escaping(tmp_path, protocol, character):
    from pqc_lab import lab
    from pqc_lab.profiles import LabProfile
    from pqc_lab.signed_messages import SignedMessageServer
    profile = LabProfile(protocol=protocol)
    with SignedMessageServer(tmp_path, ("127.0.0.1", 0), profile) as server:
        result = lab.verify_lab(tmp_path, None, server.server_address[1],
                                profile=profile, message=character * 4096)
    assert result["status"] == "passed", result


def test_udp_duplicates_cannot_extend_absolute_deadline(monkeypatch):
    import struct
    import threading
    from types import SimpleNamespace
    from pqc_lab import signed_messages
    from pqc_lab.profiles import LabProfile
    # Advance only this module's clock, retaining real UDP sockets and peer behavior.
    real_monotonic = time.monotonic
    monkeypatch.setattr(signed_messages, "time", SimpleNamespace(monotonic=lambda: real_monotonic() * 100))
    request = {"format": "pqc-lab-message-v1", "protocol": "udp", "nonce": "ab" * 32, "message": "deadline"}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
        peer.bind(("127.0.0.1", 0))
        peer.settimeout(2)
        def delayed_fragments():
            _data, address = peer.recvfrom(8192)
            header = lambda index: struct.pack("!4s32sHH", b"PQM1", bytes.fromhex("ab" * 32), index, 2)
            stop = real_monotonic() + .3
            while real_monotonic() < stop:
                peer.sendto(header(0) + b"{", address)
                time.sleep(.005)
            peer.sendto(header(1) + b"}", address)
        thread = threading.Thread(target=delayed_fragments)
        thread.start()
        try:
            with pytest.raises(TimeoutError):
                signed_messages.exchange(peer.getsockname()[1], LabProfile(protocol="udp"), request)
        finally:
            thread.join(timeout=3)


def test_cli_preflight_failure_replaces_old_success(tmp_path):
    public = tmp_path / "public"
    public.mkdir()
    report = public / "evidence.json"
    report.write_text('{"status":"passed"}')  # Stale fixture, not a handshake measurement.
    script = Path(__file__).resolve().parents[1] / "pqc_lab/lab.py"
    result = subprocess.run([sys.executable, str(script), "verify", "--base", str(tmp_path),
        "--openssl", "/unavailable/openssl"], capture_output=True, timeout=10)
    assert result.returncode != 0
    evidence = json.loads(report.read_text())
    assert evidence["status"] == "failed"
    assert "error" in evidence
