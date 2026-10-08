"""Real OpenSSL regressions for connections that previously blocked the lab."""
import importlib.util
import socket
import subprocess
import threading
import time
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from pqc_lab import lab


@pytest.fixture(scope="module")
def identity(tmp_path_factory, pqc_openssl):
    base = tmp_path_factory.mktemp("concurrent-pqc")
    openssl = pqc_openssl
    lab.init_lab(base, openssl)
    return base, openssl


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@contextmanager
def standalone(identity):
    base, openssl = identity
    port = free_port()
    with (base / "baseline.log").open("ab") as log:
        process = subprocess.Popen(lab.server_command(base, openssl, port),
            cwd=base / "public", stdin=subprocess.DEVNULL, stdout=log, stderr=log,
            creationflags=lab.NO_WINDOW)
        try:
            for _ in range(100):
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=.1):
                        break
                except OSError:
                    assert process.poll() is None
                    time.sleep(.02)
            else:
                pytest.fail("baseline OpenSSL listener did not start")
            yield port
        finally:
            process.terminate()
            process.wait(timeout=5)


@contextmanager
def held_connection(identity, port, kind):
    if kind == "idle_tcp":
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            # Give the single-connection baseline time to accept this socket.
            time.sleep(.05)
            yield
        return
    base, openssl = identity
    process = subprocess.Popen([openssl, "s_client", "-connect", f"127.0.0.1:{port}",
        "-servername", "localhost", "-tls1_3", "-groups", "X25519MLKEM768",
        "-sigalgs", "mldsa65", "-verifyCAfile", str(base / "public/root.cert.pem"),
        "-verify_return_error", "-verify_hostname", "localhost", "-brief", "-ign_eof"],
        stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        creationflags=lab.NO_WINDOW)
    established = threading.Event()
    messages = []

    def read_status():
        for line in iter(process.stderr.readline, b""):
            messages.append(line)
            if b"Verification: OK" in line:
                established.set()

    reader = threading.Thread(target=read_status, daemon=True)
    reader.start()
    try:
        assert established.wait(5), b"".join(messages).decode(errors="replace")
        assert process.poll() is None
        yield  # A complete TLS connection that never sends an HTTP request.
    finally:
        process.terminate()
        process.wait(timeout=5)
        reader.join(timeout=2)
        process.stdin.close()
        process.stderr.close()


def frontend_class():
    path = Path(lab.__file__).with_name("tls_frontend.py")
    assert path.is_file(), "Concurrent TLS frontend has not been implemented"
    spec = importlib.util.spec_from_file_location("pqc_concurrent_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.ConcurrentTLSServer


@pytest.mark.parametrize("kind", ["idle_tcp", "tls_without_http"])
def test_standalone_server_reproduces_head_of_line_blocking(identity, kind):
    with standalone(identity) as port:
        with held_connection(identity, port, kind):
            blocked = lab.pqc_detect.deep_verify("127.0.0.1", port, timeout=.3)
            assert not blocked["verified"]
            assert "ServerHello" in blocked["error"]
        recovered = lab.pqc_detect.deep_verify("127.0.0.1", port, timeout=2)
        assert recovered["verified"], recovered["error"]


@pytest.mark.parametrize("kind", ["idle_tcp", "tls_without_http"])
def test_held_connection_does_not_block_another_real_pqc_handshake(identity, kind):
    base, openssl = identity
    server = frontend_class()(("127.0.0.1", 0),
        lambda port: lab.server_command(base, openssl, port), base / "public", base / "frontend.log")
    server.start()
    try:
        port = server.server_address[1]
        with held_connection(identity, port, kind):
            result = lab.pqc_detect.deep_verify("127.0.0.1", port, timeout=2)
            assert result["verified"], result["error"]
            assert result["group_id"] == 0x11EC
            assert result["cert_verify"]["scheme"] == "0x0905"
    finally:
        server.close()


def test_http_redirect_and_complete_https_preserve_real_identity(identity):
    base, openssl = identity
    server = frontend_class()(("127.0.0.1", 0),
        lambda port: lab.server_command(base, openssl, port), base / "public", base / "frontend.log")
    server.start()
    try:
        port = server.server_address[1]
        with socket.create_connection(server.server_address, timeout=2) as client:
            client.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            response = client.recv(4096)
        assert response.startswith(b"HTTP/1.1 307")
        assert f"Location: https://localhost:{port}/index.html\r\n".encode() in response
        evidence = lab.verify_lab(base, openssl, port)
        assert evidence["status"] == "passed", evidence
        assert all(check["passed"] for check in evidence["checks"])
    finally:
        server.close()


def test_close_releases_idle_connections_and_openssl_processes(identity, monkeypatch):
    base, openssl = identity
    factory = frontend_class()
    spawned = []
    real_popen = subprocess.Popen

    def record_process(*args, **kwargs):
        process = real_popen(*args, **kwargs)
        spawned.append(process)
        return process

    monkeypatch.setattr(subprocess, "Popen", record_process)
    server = factory(("127.0.0.1", 0), lambda port: lab.server_command(base, openssl, port),
        base / "public", base / "frontend.log")
    server.start()
    idle = socket.create_connection(server.server_address, timeout=2)
    try:
        with held_connection(identity, server.server_address[1], "tls_without_http"):
            assert len(spawned) >= 2
            # Exclude our independent s_client process; only service children must stop.
            workers = [proc for proc in spawned if "s_server" in proc.args]
            assert workers
            server.close()
            assert all(proc.poll() is not None for proc in workers)
        idle.settimeout(1)
        assert idle.recv(1) == b""
    finally:
        idle.close()
        server.close()


def test_idle_preconnection_expires_without_starting_openssl(identity):
    base, openssl = identity
    commands = []

    def command(port):
        commands.append(port)
        return lab.server_command(base, openssl, port)

    with frontend_class()(("127.0.0.1", 0), command, base / "public", base / "frontend.log") as server:
        with socket.create_connection(server.server_address, timeout=5) as idle:
            assert idle.recv(1) == b""
        assert not commands
        result = lab.pqc_detect.deep_verify("127.0.0.1", server.server_address[1], timeout=2)
        assert result["verified"], result["error"]


def test_worker_limit_rejects_extra_client_and_recovers(identity):
    base, openssl = identity
    held = []
    with frontend_class()(("127.0.0.1", 0), lambda port: lab.server_command(base, openssl, port),
                         base / "public", base / "frontend.log") as server:
        hello = lab.pqc_detect.build_client_hello("localhost")
        try:
            for _ in range(8):
                client = socket.create_connection(server.server_address, timeout=2)
                held.append(client)
                client.sendall(hello)
                assert client.recv(5)[0] == 22
            with socket.create_connection(server.server_address, timeout=2) as overflow:
                overflow.sendall(hello)
                assert overflow.recv(1) == b""
        finally:
            for client in held:
                client.close()
        deadline = time.monotonic() + 3
        while True:
            recovered = lab.pqc_detect.deep_verify("127.0.0.1", server.server_address[1], timeout=2)
            if recovered["verified"] or time.monotonic() >= deadline:
                break
            time.sleep(.02)
        assert recovered["verified"], recovered["error"]


def test_simultaneous_clients_complete_real_pqc_handshakes(identity):
    base, openssl = identity
    ready = threading.Barrier(8)
    with frontend_class()(("127.0.0.1", 0), lambda port: lab.server_command(base, openssl, port),
                         base / "public", base / "frontend.log") as server:
        def verify(_):
            ready.wait(timeout=5)
            return lab.pqc_detect.deep_verify("127.0.0.1", server.server_address[1], timeout=3)

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(verify, range(8)))
        assert all(result["verified"] for result in results), [result["error"] for result in results]
