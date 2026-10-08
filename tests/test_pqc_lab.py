"""Integration tests use a real OpenSSL server, keys, signatures and HTTP traffic."""
import importlib.util
import json
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "pqc_lab" / "lab.py"


def load_lab():
    assert SCRIPT.is_file(), "The reproducible PQC laboratory is not implemented"
    spec = importlib.util.spec_from_file_location("pqc_lab_script", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_real_dual_pqc_site_and_negative_controls(tmp_path, pqc_openssl):
    lab = load_lab()
    openssl = pqc_openssl
    lab.init_lab(tmp_path, openssl)
    # Re-initialization must preserve the private CA and leaf identity.
    original = (tmp_path / "public" / "server.cert.pem").read_bytes()
    lab.init_lab(tmp_path, openssl)
    assert original == (tmp_path / "public" / "server.cert.pem").read_bytes()
    assert not list((tmp_path / "public").glob("*key*"))
    port = free_port()
    with (tmp_path / "server.log").open("wb") as log:
        process = subprocess.Popen(lab.server_command(tmp_path, openssl, port),
                                   cwd=tmp_path / "public", stdin=subprocess.DEVNULL,
                                   stdout=log, stderr=log)
        try:
            for _ in range(100):
                if process.poll() is not None:
                    pytest.fail((tmp_path / "server.log").read_text(errors="replace"))
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=.1):
                        break
                except OSError:
                    time.sleep(.05)
            result = lab.verify_lab(tmp_path, openssl, port)
            assert result["status"] == "passed", result
            assert all(check["passed"] for check in result["checks"]), result
            assert result["summary"]["group_name"].startswith("X25519MLKEM768")
            assert result["summary"]["finished_verified"] is True
            assert result["summary"]["certificate_verify_verified"] is True
            assert result["summary"]["certificate_public_key_bytes"] == 1952
            assert result["summary"]["certificate_signature_bytes"] == 3309
            assert result["summary"]["chain_certificates"] == 2
            assert {"https_get", "reject_classical", "reject_wrong_hostname",
                    "reject_tampered_cert", "trusted_chain"} <= {
                        check["id"] for check in result["checks"]}
        finally:
            process.terminate()
            process.wait(timeout=10)
    # A stale success must never survive a new failed test against a stopped server.
    result = lab.verify_lab(tmp_path, openssl, port)
    assert result["status"] == "failed"
    assert '"status": "failed"' in (tmp_path / "public" / "evidence.json").read_text(encoding="utf-8")


def test_incomplete_identity_is_not_silently_reissued(tmp_path):
    lab = load_lab()
    private = tmp_path / ".runtime" / "private"
    private.mkdir(parents=True)
    (private / "root.key.pem").write_text("incomplete existing identity")
    with pytest.raises(RuntimeError, match="incomplete|不完整"):
        lab.init_lab(tmp_path, "unused-openssl")


def test_service_lifecycle_keeps_private_files_outside_web_root(tmp_path, pqc_openssl):
    lab = load_lab()
    openssl = pqc_openssl
    port, http_port = free_port(), free_port()
    while port == http_port:
        http_port = free_port()
    with (tmp_path / "manager.log").open("wb") as log:
        process = subprocess.Popen([sys.executable, str(SCRIPT), "serve", "--base", str(tmp_path),
            "--openssl", openssl, "--port", str(port), "--http-port", str(http_port)],
            stdout=log, stderr=log, creationflags=lab.NO_WINDOW)
        try:
            address = f"http://127.0.0.1:{http_port}"
            for _ in range(150):
                if process.poll() is not None:
                    pytest.fail((tmp_path / "manager.log").read_text(errors="replace"))
                try:
                    with urlopen(address + "/index.html", timeout=.2) as response:
                        assert response.status == 200
                    break
                except (OSError, URLError):
                    time.sleep(.1)
            else:
                pytest.fail("HTTP evidence viewer failed to start")
            for path in ("/.runtime/private/root.key.pem", "/../.runtime/private/server.key.pem"):
                with pytest.raises(HTTPError) as error:
                    urlopen(address + path, timeout=2)
                assert error.value.code == 404
            with pytest.raises(HTTPError) as error:
                urlopen(Request(address + "/_stop", data=b"", method="POST"), timeout=2)
            assert error.value.code == 403
            state_file = tmp_path / ".runtime/service.json"
            first_state = json.loads(state_file.read_text(encoding="utf-8"))
            second = subprocess.Popen([sys.executable, str(SCRIPT), "serve", "--base", str(tmp_path),
                "--openssl", openssl, "--port", str(free_port()), "--http-port", str(free_port())],
                stdout=log, stderr=log, creationflags=lab.NO_WINDOW)
            try:
                for _ in range(50):
                    if second.poll() is not None:
                        break
                    time.sleep(.1)
                assert second.poll() is not None, "A second manager must not overwrite this directory's service record"
                assert second.returncode != 0
                assert json.loads(state_file.read_text(encoding="utf-8"))["pid"] == process.pid
            finally:
                if second.poll() is None:
                    # Cleanup the reproduced pre-fix defect without orphaning TLS children.
                    second_state = json.loads(state_file.read_text(encoding="utf-8"))
                    req = Request(f"http://127.0.0.1:{second_state['http_port']}/_stop", data=b"",
                                  headers={"X-Lab-Token": second_state["token"]}, method="POST")
                    with urlopen(req, timeout=2):
                        pass
                    second.wait(timeout=30)
                    state_file.write_text(json.dumps(first_state), encoding="utf-8")
            stopped = subprocess.run([sys.executable, str(SCRIPT), "stop", "--base", str(tmp_path)],
                                     capture_output=True, timeout=10)
            assert stopped.returncode == 0, stopped.stderr
            assert process.wait(timeout=30) == 0
            assert not (tmp_path / ".runtime/service.json").exists()
        finally:
            if process.poll() is None:
                subprocess.run([sys.executable, str(SCRIPT), "stop", "--base", str(tmp_path)],
                               capture_output=True, timeout=10)
                process.wait(timeout=30)
