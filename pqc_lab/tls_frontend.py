"""Small loopback TCP frontend; OpenSSL still performs every TLS operation.

The OpenSSL demonstration HTTP server handles one connection at a time. Give
each TLS client its own short-lived server so browser preconnections cannot
block the detector. This is a bounded local teaching service, not a web proxy.
"""
from __future__ import annotations

import os
from pathlib import Path
import select
import socket
import subprocess
import threading
import time


class ConcurrentTLSServer:
    def __init__(self, address, command_factory, public_dir, log_path):
        if address[0] != "127.0.0.1":
            raise ValueError("The laboratory TLS frontend must bind to 127.0.0.1")
        self.server_address = address
        self._command_factory = command_factory
        self._public_dir = Path(public_dir)
        self._log_path = Path(log_path)
        self._stopping = threading.Event()
        self._lock = threading.Lock()
        self._connections = set()
        self._processes = set()
        self._threads = set()
        self._workers = threading.BoundedSemaphore(8)
        self._pending = threading.BoundedSemaphore(32)
        self._listener = self._thread = self._log = None

    def start(self):
        if self._thread is not None:
            raise RuntimeError("TLS frontend has already been started")
        if self._stopping.is_set():
            raise RuntimeError("TLS frontend has been closed")
        listener = socket.socket()
        try:
            if os.name == "nt":
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            else:
                # Permit immediate restart after accepted sockets enter TIME_WAIT.
                # SO_REUSEPORT remains disabled: an active listener stays exclusive.
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(self.server_address)
            listener.listen(32)
            listener.settimeout(.2)
            self._log = self._log_path.open("ab", buffering=0)
        except Exception:
            listener.close()
            raise
        self._listener = listener
        self.server_address = listener.getsockname()
        self._thread = threading.Thread(target=self._accept, daemon=True)
        self._thread.start()
        return self

    def is_alive(self):
        return bool(self._thread and self._thread.is_alive() and not self._stopping.is_set())

    def _accept(self):
        while not self._stopping.is_set():
            try:
                client, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not self._pending.acquire(blocking=False):
                client.close()
                continue
            worker = threading.Thread(target=self._handle, args=(client,), daemon=True)
            with self._lock:
                if self._stopping.is_set():
                    client.close()
                    self._pending.release()
                    break
                self._connections.add(client)
                self._threads.add(worker)
                worker.start()

    def _first_bytes(self, client):
        deadline = time.monotonic() + 3
        data = b""
        while len(data) < 6:
            client.settimeout(max(.001, deadline - time.monotonic()))
            chunk = client.recv(8192)
            if not chunk:
                return b""
            data += chunk
            if time.monotonic() >= deadline:
                return b""
        return data

    def _start_worker(self):
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        command = list(self._command_factory(port)) + ["-naccept", "1", "-quiet"]
        with self._lock:
            if self._stopping.is_set():
                raise OSError("TLS frontend is stopping")
            process = subprocess.Popen(command, cwd=self._public_dir,
                stdin=subprocess.DEVNULL, stdout=self._log, stderr=self._log,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
            self._processes.add(process)
        return process, port

    def _connect_worker(self, process, port):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and not self._stopping.is_set():
            if process.poll() is not None:
                raise OSError("OpenSSL worker exited before accepting a connection")
            try:
                # This successful connection consumes the only accept and must
                # become the relay socket; never open a separate health probe.
                return socket.create_connection(("127.0.0.1", port), timeout=.15)
            except OSError:
                self._stopping.wait(.02)
        raise OSError("OpenSSL worker did not become ready")

    def _relay(self, client, backend):
        client.settimeout(1)
        backend.settimeout(1)
        idle_deadline = time.monotonic() + 10
        lifetime_deadline = time.monotonic() + 30
        while not self._stopping.is_set():
            remaining = min(idle_deadline, lifetime_deadline) - time.monotonic()
            if remaining <= 0:
                return
            readable, _, _ = select.select([client, backend], [], [], min(.2, remaining))
            for source in readable:
                data = source.recv(65536)
                if not data:
                    return
                destination = backend if source is client else client
                destination.sendall(data)
                idle_deadline = time.monotonic() + 10

    @staticmethod
    def _stop_process(process):
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)

    def _handle(self, client):
        backend = process = None
        acquired = False
        try:
            data = self._first_bytes(client)
            if not data:
                return
            if data.startswith((b"GET ", b"HEAD ", b"POST ", b"PUT ", b"DELETE", b"OPTION", b"PATCH ")):
                location = f"https://localhost:{self.server_address[1]}/index.html"
                client.sendall(("HTTP/1.1 307 Temporary Redirect\r\n"
                    f"Location: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").encode("ascii"))
                return
            # Only a TLS handshake record beginning with ClientHello gets a
            # process. Fragmented ClientHello bytes remain untouched.
            if data[0] != 22 or data[1] != 3 or data[5] != 1:
                return
            acquired = self._workers.acquire(blocking=False)
            if not acquired:
                return
            process, port = self._start_worker()
            backend = self._connect_worker(process, port)
            with self._lock:
                if self._stopping.is_set():
                    return
                self._connections.add(backend)
            backend.settimeout(1)
            backend.sendall(data)
            self._relay(client, backend)
        except (OSError, ValueError, subprocess.SubprocessError):
            # Native OpenSSL errors remain in the shared server log. Socket
            # cancellation and clients leaving before a handshake are normal.
            pass
        finally:
            for conn in (client, backend):
                if conn is not None:
                    conn.close()
                    with self._lock:
                        self._connections.discard(conn)
            if process is not None:
                self._stop_process(process)
                with self._lock:
                    self._processes.discard(process)
            if acquired:
                self._workers.release()
            self._pending.release()
            with self._lock:
                self._threads.discard(threading.current_thread())

    def close(self):
        self._stopping.set()
        if self._listener is not None:
            self._listener.close()
        with self._lock:
            connections = list(self._connections)
            processes = list(self._processes)
            threads = list(self._threads)
        for conn in connections:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            conn.close()
        for process in processes:
            self._stop_process(process)
        if self._thread is not None:
            self._thread.join(timeout=2)
        for thread in threads:
            thread.join(timeout=4)
        if self._log is not None:
            self._log.close()

    def __enter__(self):
        return self.start()

    def __exit__(self, *_):
        self.close()
