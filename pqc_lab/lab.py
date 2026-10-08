"""Real loopback HTTPS, TLS and TCP/UDP signed-message experiments."""
from __future__ import annotations

import argparse
import base64
import functools
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from contextlib import contextmanager
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import Request, urlopen

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from modules import pqc_detect
from pqc_lab.profiles import LabProfile, PROTOCOLS, TLS_GROUPS, TLS_SIGNATURES

NO_WINDOW = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
CONFIG = """[req]
distinguished_name = dn
[dn]
[root_ca]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
[server_cert]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost,IP:127.0.0.1
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
"""


def run(args, *, data=None, timeout=20):
    return subprocess.run([str(a) for a in args], input=data, capture_output=True,
                          timeout=timeout, creationflags=NO_WINDOW)


def output(proc):
    return (proc.stdout + proc.stderr).decode("utf-8", "replace")


def require(args):
    proc = run(args)
    if proc.returncode:
        raise RuntimeError(output(proc))
    return proc


def find_openssl(explicit=None, profile=None):
    profile = profile or LabProfile()
    candidates = [explicit] if explicit else openssl_candidates()
    for path in dict.fromkeys(p for p in candidates if p):
        try:
            groups = require([path, "list", "-tls-groups"]).stdout
            schemes = require([path, "list", "-tls-signature-algorithms"]).stdout.lower()
            if profile.group.encode("ascii") in groups and TLS_SIGNATURES[profile.signature]["openssl"].encode("ascii") in schemes:
                return str(Path(path).resolve())
        except (OSError, RuntimeError, subprocess.TimeoutExpired):
            continue
    raise RuntimeError("No OpenSSL with " + profile.group + " and " + profile.signature + " found; use --openssl PATH.")


def openssl_candidates():
    """Return likely OpenSSL executables across Windows, macOS, Linux and Conda."""
    candidates = [os.environ.get("PQC_OPENSSL"), shutil.which("openssl"), pqc_detect.find_openssl()]
    git = shutil.which("git")
    if git:
        candidates.append(str(Path(git).parent.parent / "mingw64/bin/openssl.exe"))
    roots = [Path(sys.prefix), Path(sys.prefix).parent,
             Path.home() / ".conda", Path.home() / "miniconda3",
             Path.home() / "anaconda3", Path("C:/ProgramData/miniconda3"),
             Path("C:/ProgramData/anaconda3")]
    for root in roots:
        candidates.extend(path for pattern in ("envs/*/bin/openssl", "envs/*/Library/bin/openssl.exe")
                          for path in root.glob(pattern))
    if os.name == "nt":
        candidates.append(Path.home() / "scoop/apps/openssl/current/openssl.exe")
    return [str(Path(path).resolve()) for path in dict.fromkeys(p for p in candidates if p)]


def write_json(path, value):
    # Atomic replacement: readers never see half a report.
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)


def now():
    return datetime.now(timezone(timedelta(hours=8))).isoformat(timespec="seconds")


def identity_paths(base, profile):
    base = Path(base)
    suffix = "" if profile.signature == "ML-DSA-65" else "." + TLS_SIGNATURES[profile.signature]["openssl"]
    return (base / (".runtime/private/root" + suffix + ".key.pem"),
            base / (".runtime/private/server" + suffix + ".key.pem"),
            base / ("public/root" + suffix + ".cert.pem"),
            base / ("public/server" + suffix + ".cert.pem"))


def prepare_page(base):
    public = Path(base) / "public"
    public.mkdir(parents=True, exist_ok=True)
    template = HERE / "public/index.html"
    if template.exists() and template.resolve() != (public / "index.html").resolve():
        shutil.copyfile(template, public / "index.html")
    if not (public / "index.html").exists():
        raise RuntimeError("Missing public/index.html")


def init_lab(base, openssl, *, profile=None):
    profile = profile or LabProfile()
    base = Path(base).resolve()
    if not profile.is_tls:
        prepare_page(base)
        return base
    private, public = base / ".runtime/private", base / "public"
    private.mkdir(parents=True, exist_ok=True)
    public.mkdir(parents=True, exist_ok=True)
    # Private keys never enter the HTTP document root.
    if os.name != "nt":
        private.chmod(0o700)
    root_key, leaf_key, root_cert, leaf_cert = identity_paths(base, profile)
    identity = [root_key, leaf_key, root_cert, leaf_cert]
    present = [p.exists() for p in identity]
    if any(present) and not all(present):
        raise RuntimeError("Existing identity is incomplete; preserve it and select a new --base directory.")
    config = private / "pqc.cnf"
    config.write_text(CONFIG, encoding="ascii")
    if not all(present):
        require([openssl, "genpkey", "-algorithm", profile.signature, "-out", root_key])
        require([openssl, "req", "-new", "-x509", "-key", root_key, "-out", root_cert,
                 "-days", "365", "-subj", "/CN=Local PQC Lab Root", "-config", config,
                 "-extensions", "root_ca"])
        require([openssl, "genpkey", "-algorithm", profile.signature, "-out", leaf_key])
        csr = private / "server.csr.pem"
        require([openssl, "req", "-new", "-key", leaf_key, "-out", csr,
                 "-subj", "/CN=localhost", "-config", config])
        require([openssl, "x509", "-req", "-in", csr, "-CA", root_cert,
                 "-CAkey", root_key, "-set_serial", "0x" + secrets.token_hex(16),
                 "-out", leaf_cert, "-days", "30", "-extfile", config,
                 "-extensions", "server_cert"])
    if os.name != "nt":
        root_key.chmod(0o600)
        leaf_key.chmod(0o600)
    require(chain_command(base, openssl, profile=profile))
    expected_oid = TLS_SIGNATURES[profile.signature]["oid"]
    for cert_file in (root_cert, leaf_cert):
        info = pqc_detect.analyze_cert_der(pqc_detect.load_cert_bytes(cert_file.read_bytes()))
        if info["pub_oid"] != expected_oid or info["sig_oid"] != expected_oid:
            raise RuntimeError("Existing identity does not match selected signature algorithm")
    # Detect stale/mismatched private keys without printing private material.
    for key, cert in [(root_key, root_cert), (leaf_key, leaf_cert)]:
        key_pub = require([openssl, "pkey", "-in", key, "-pubout"]).stdout.strip()
        cert_pub = require([openssl, "x509", "-in", cert, "-pubkey", "-noout"]).stdout.strip()
        if key_pub != cert_pub:
            raise RuntimeError("Certificate and private key do not match: " + str(cert))
    prepare_page(base)
    return base


def chain_command(base, openssl, *, hostname="localhost", cert=None, profile=None):
    _root_key, _leaf_key, root_cert, leaf_cert = identity_paths(base, profile or LabProfile())
    return [openssl, "verify", "-trusted", root_cert, "-check_ss_sig",
            "-x509_strict", "-purpose", "sslserver", "-verify_hostname", hostname,
            cert or leaf_cert]


def server_command(base, openssl, port=8443, *, profile=None):
    profile = profile or LabProfile()
    base = Path(base).resolve()
    _root_key, leaf_key, root_cert, leaf_cert = identity_paths(base, profile)
    return [str(x) for x in [openssl, "s_server", "-accept", f"127.0.0.1:{port}",
            "-cert", leaf_cert, "-key", leaf_key,
            "-cert_chain", root_cert, "-tls1_3", "-groups", profile.group,
            "-sigalgs", TLS_SIGNATURES[profile.signature]["openssl"], "-ciphersuites", "TLS_AES_256_GCM_SHA384",
            "-num_tickets", "0", "-no_cache", "-WWW", "-http_server_binmode"]]


def verify_lab(base, openssl, port=8443, *, profile=None, message="本地后量子签名消息实验"):
    profile = profile or LabProfile()
    if not profile.is_tls:
        from pqc_lab.signed_messages import verify_messages
        return verify_messages(base, port, profile, message)
    base = Path(base).resolve()
    public = base / "public"
    public.mkdir(parents=True, exist_ok=True)
    _root_key, _leaf_key, root_cert, leaf_cert = identity_paths(base, profile)
    signature_info = TLS_SIGNATURES[profile.signature]
    evidence = {"status": "running", "generated_at": now(), "target": f"127.0.0.1:{port}",
                "checks": [], "summary": {}, "profile": profile.as_dict(),
                "trust_scope": "Explicit local laboratory CA only; not public Web PKI."}
    write_json(public / "evidence.json", evidence)

    def check(identifier, label, passed, detail):
        evidence["checks"].append(dict(id=identifier, label=label, passed=bool(passed), detail=detail))

    def save(name, proc):
        (public / name).write_text(output(proc), encoding="utf-8")

    try:
        evidence["openssl_version"] = output(require([openssl, "version"])).strip()
        report = pqc_detect.detect("127.0.0.1", port, timeout=3, mode="deep",
                                   groups=[TLS_GROUPS[profile.group]])
        write_json(public / "detector-report.json", pqc_detect.report_to_json(report))
        (public / "handshake.txt").write_text(pqc_detect.interaction_full_text(report), encoding="utf-8")
        deep, transport, cert = report.get("deep") or {}, report.get("transport") or {}, report.get("cert") or {}
        cv = deep.get("cert_verify") or {}
        evidence["summary"] = dict(group_name=transport.get("group_name"), protocol=transport.get("protocol"),
            cipher_suite=transport.get("cipher_suite"), certificate_algorithm=cert.get("sig_algorithm"),
            certificate_fingerprint_sha256=cert.get("fingerprint_sha256"),
            certificate_public_key_bytes=cert.get("pub_bytes"), certificate_signature_bytes=cert.get("sig_bytes"),
            finished_verified=deep.get("finished_verified", False), certificate_verify_verified=cv.get("verified", False),
            chain_certificates=len(report.get("cert_chain") or []),
            root_certificate_file=root_cert.name, server_certificate_file=leaf_cert.name)
        check("hybrid_exchange", "真实混合密钥交换及长度校验", transport.get("group_id") == TLS_GROUPS[profile.group]
              and transport.get("size_ok") is True, str(transport.get("group_name")))
        check("finished", "服务器 Finished 密码学校验", deep.get("finished_verified") is True, deep.get("error") or "TLS transcript HMAC")
        check("certificate_verify", profile.signature + " CertificateVerify 验签", cv.get("verified") is True
              and cv.get("scheme") == signature_info["scheme"], json.dumps(cv, ensure_ascii=False))
        check("pqc_chain", "两张 " + profile.signature + " 证书及规范长度", len(report.get("cert_chain") or []) == 2
              and all(c.get("sig_oid") == signature_info["oid"] and c.get("pub_oid") == signature_info["oid"]
                      and c.get("sig_size_ok") is True and c.get("pub_size_ok") is True for c in report.get("cert_chain", [])),
              "Inspect detector-report.json for per-certificate measurements")
        check("detector", "原项目双层检测通过", report.get("overall_state") == "pqc" and deep.get("verified") is True,
              report.get("overall", ""))
        chain = run(chain_command(base, openssl, profile=profile))
        save("openssl-chain.txt", chain)
        check("trusted_chain", "指定实验 CA：证书链、有效期、主机名及根自签名验证", chain.returncode == 0, output(chain).strip())
        client = [openssl, "s_client", "-connect", f"127.0.0.1:{port}", "-servername", "localhost",
                  "-tls1_3", "-groups", profile.group, "-sigalgs", signature_info["openssl"],
                  "-verifyCAfile", root_cert, "-verify_return_error", "-verify_hostname", "localhost",
                  "-check_ss_sig", "-x509_strict", "-showcerts", "-ign_eof"]
        request = b"GET /index.html HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        if profile.protocol == "tls":
            client.remove("-ign_eof")
        session = run(client, data=request if profile.protocol == "https" else b"")
        save("openssl-session.txt", session)
        response_match = re.search(rb"HTTP/1\.[01] 200[^\r\n]*\r?\n.*?\r?\n\r?\n", session.stdout, re.S)
        body_ok = bool(response_match and session.stdout[response_match.end():].startswith((public / "index.html").read_bytes()))
        if profile.protocol == "https":
            check("https_get", "完成受信任的真实 HTTPS GET 并比对网页字节", session.returncode == 0 and body_ok,
                  f"OpenSSL exit={session.returncode}; HTTP 200 and exact HTML bytes={body_ok}")
        else:
            check("tls_session", "完成受信任的真实 TLS 1.3 会话", session.returncode == 0
                  and "TLSv1.3" in output(session) and "TLS_AES_256_GCM_SHA384" in output(session),
                  f"OpenSSL exit={session.returncode}; no HTTP request")
        pems = re.findall(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", session.stdout, re.S)
        local_der = pqc_detect.load_cert_bytes(leaf_cert.read_bytes())
        fingerprint = hashlib.sha256(local_der).hexdigest().upper()
        check("same_identity", "检测器、完整 %s 会话与本地证书指纹一致" % ("HTTPS" if profile.protocol == "https" else "TLS"),
              bool(pems) and pqc_detect.load_cert_bytes(pems[0]) == local_der
              and cert.get("fingerprint_sha256") == fingerprint, fingerprint)
        classical = client.copy()
        classical[classical.index("-groups") + 1] = "X25519"
        rejected = run(classical, data=request)
        save("negative-classical.txt", rejected)
        check("reject_classical", "负向对照：仅经典 X25519 被服务器拒绝", rejected.returncode != 0
              and "handshake failure" in output(rejected).lower(), output(rejected).strip()[-600:])
        wrong = run(chain_command(base, openssl, hostname="wrong.invalid", profile=profile))
        save("negative-hostname.txt", wrong)
        check("reject_wrong_hostname", "负向对照：错误主机名被拒绝", wrong.returncode != 0
              and "hostname mismatch" in output(wrong).lower(), output(wrong).strip())
        damaged = bytearray(local_der)
        damaged[-1] ^= 1  # Actual signature corruption, with OID and length unchanged.
        damaged_cert = base / ".runtime/tampered.cert.pem"
        payload = base64.b64encode(damaged).decode("ascii")
        damaged_cert.write_text("-----BEGIN CERTIFICATE-----\n" + "\n".join(payload[i:i+64] for i in range(0, len(payload), 64))
                                + "\n-----END CERTIFICATE-----\n", encoding="ascii")
        bad_signature = run(chain_command(base, openssl, cert=damaged_cert, profile=profile))
        save("negative-signature.txt", bad_signature)
        check("reject_tampered_cert", "负向对照：长度/OID 不变但篡改签名的证书被拒绝", bad_signature.returncode != 0
              and "certificate signature failure" in output(bad_signature).lower(), output(bad_signature).strip())
        evidence["status"] = "passed" if all(c["passed"] for c in evidence["checks"]) else "failed"
    except Exception as exc:
        evidence["status"] = "failed"
        evidence["error"] = f"{type(exc).__name__}: {exc}"
    evidence["generated_at"] = now()
    write_json(public / "evidence.json", evidence)
    return evidence


@contextmanager
def service_lock(base):
    """An OS-held lock survives stale lock files but is released on process exit."""
    runtime = Path(base) / ".runtime"
    runtime.mkdir(parents=True, exist_ok=True)
    with (runtime / "service.lock").open("a+b") as handle:
        if handle.tell() == 0:
            handle.write(b"\x00")
            handle.flush()
        handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise RuntimeError("A service already manages this --base directory; stop it first or use another --base.") from exc
        yield  # Closing the handle releases the lock even after an exception.


def service_is_active(base):
    """A stale record is not a running manager; check its OS-held lock without writing."""
    try:
        handle = (Path(base) / ".runtime/service.lock").open("r+b")
    except OSError:
        return False
    with handle:
        handle.seek(0)
        if os.name == "nt":
            import msvcrt
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError:
                return True
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return True
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    return False


def serve(base, openssl, port=8443, http_port=8080, *, profile=None, message="本地后量子签名消息实验"):
    with service_lock(base):
        _serve(base, openssl, port, http_port, profile=profile, message=message)


def _serve(base, openssl, port=8443, http_port=8080, *, profile=None, message="本地后量子签名消息实验"):
    from pqc_lab.tls_frontend import ConcurrentTLSServer
    from pqc_lab.signed_messages import SignedMessageServer
    profile = profile or LabProfile()
    base = init_lab(base, openssl, profile=profile)
    token = secrets.token_urlsafe(32)
    stopping = threading.Event()

    class Handler(SimpleHTTPRequestHandler):
        def end_headers(self):
            self.send_header("Cache-Control", "no-store")
            super().end_headers()

        def do_POST(self):
            if self.path != "/_stop" or not hmac.compare_digest(self.headers.get("X-Lab-Token", ""), token):
                self.send_error(403)
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Stopping local PQC lab.\n")
            stopping.set()

    http = ThreadingHTTPServer(("127.0.0.1", http_port), functools.partial(Handler, directory=str(base / "public")))
    tls = (ConcurrentTLSServer(("127.0.0.1", port),
        lambda worker_port: server_command(base, openssl, worker_port, profile=profile),
        base / "public", base / ".runtime/server.log") if profile.is_tls else
        SignedMessageServer(base, ("127.0.0.1", port), profile))
    http_started = False
    runtime_file = base / ".runtime/service.json"
    try:
        tls.start()
        write_json(runtime_file, dict(pid=os.getpid(), tls_engine="OpenSSL per connection" if profile.is_tls else "pqcrypto signed messages", port=port,
                                     http_port=http_port, token=token, started_at=now(),
                                     profile=profile.as_dict(), message=message, openssl=openssl))
        threading.Thread(target=http.serve_forever, daemon=True).start()
        http_started = True
        print(f"Experiment: {PROTOCOLS[profile.protocol]} 127.0.0.1:{port}", flush=True)
        print(f"Read-only HTTP evidence viewer: http://127.0.0.1:{http_port}/index.html", flush=True)
        result = verify_lab(base, openssl, port, profile=profile, message=message)
        print(f"Verification: {result['status']}; see public/evidence.json", flush=True)
        while not stopping.wait(.5):
            if not tls.is_alive():
                raise RuntimeError("TLS listener unexpectedly stopped")
    finally:
        tls.close()
        if runtime_file.exists():
            runtime_file.unlink()
        # shutdown is only safe after serve_forever has started.
        if http_started:
            http.shutdown()
        http.server_close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["init", "serve", "verify", "stop", "status"])
    parser.add_argument("--openssl")
    parser.add_argument("--base", type=Path, default=HERE)
    parser.add_argument("--port", type=int)
    parser.add_argument("--http-port", type=int)
    parser.add_argument("--protocol", choices=tuple(PROTOCOLS))
    parser.add_argument("--group", choices=tuple(TLS_GROUPS))
    parser.add_argument("--signature")
    parser.add_argument("--classical-signature")
    parser.add_argument("--message", help="TCP/UDP 消息，最多 4096 UTF-8 字节")
    args = parser.parse_args()
    base = args.base.resolve()
    if args.command in ("stop", "status"):
        runtime = base / ".runtime/service.json"
        if not runtime.exists():
            print("No managed service is recorded.")
            return 0
        state = json.loads(runtime.read_text(encoding="utf-8"))
        if args.command == "stop":
            req = Request(f"http://127.0.0.1:{state['http_port']}/_stop", data=b"",
                          headers={"X-Lab-Token": state["token"]}, method="POST")
            with urlopen(req, timeout=5) as response:
                print(response.read().decode())
        else:
            state.pop("token", None)
            print(json.dumps(state, indent=2))
            if not service_is_active(base):
                print("Recorded service manager is not active.")
                return 1
            if (state.get("profile") or {}).get("protocol") == "udp":
                print("UDP service manager is active (not a cryptographic verification).")
                return 0
            try:
                with socket.create_connection(("127.0.0.1", state["port"]), timeout=2):
                    print("TCP port is listening (not a cryptographic verification).")
            except OSError:
                print("Recorded TLS service is not reachable.")
                return 1
        return 0
    state = {}
    if args.command == "verify" and service_is_active(base):
        state = json.loads((base / ".runtime/service.json").read_text(encoding="utf-8"))
    port = args.port if args.port is not None else state.get("port", 8443)
    http_port = args.http_port if args.http_port is not None else state.get("http_port", 8080)
    if not 1 <= port <= 65535 or not 1 <= http_port <= 65535 or port == http_port:
        parser.error("Use distinct protocol and viewer ports in 1..65535")
    fields = dict(state.get("profile") or {})
    for name in ("protocol", "group", "signature", "classical_signature"):
        value = getattr(args, name)
        if value is not None:
            fields[name] = value
    try:
        profile = LabProfile.from_dict(fields)
        message = args.message if args.message is not None else state.get("message", "本地后量子签名消息实验")
        if len(message.encode("utf-8")) > 4096:
            parser.error("消息不能超过 4096 UTF-8 字节")
    except ValueError as exc:
        parser.error(str(exc))
    try:
        openssl = find_openssl(args.openssl or state.get("openssl"), profile) if profile.is_tls else None
    except RuntimeError as exc:
        if args.command == "verify":
            public = base / "public"
            public.mkdir(parents=True, exist_ok=True)
            write_json(public / "evidence.json", {
                "status": "failed", "generated_at": now(), "target": f"127.0.0.1:{port}",
                "profile": profile.as_dict(), "checks": [], "summary": {},
                "error": str(exc), "trust_scope": "Verification could not start."})
        raise
    if args.command == "init":
        init_lab(base, openssl, profile=profile)
        print("Experiment files ready; system trust store unchanged.")
    elif args.command == "serve":
        serve(base, openssl, port, http_port, profile=profile, message=message)
    else:
        result = verify_lab(base, openssl, port, profile=profile, message=message)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["status"] == "passed" else 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("Lab stopped.")
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
