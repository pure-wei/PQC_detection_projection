"""Loopback signed messages. This application protocol provides no encryption."""
import base64
import copy
import hashlib
import json
import secrets
import socket
import socketserver
import struct
import threading
import time
from pathlib import Path
from importlib.metadata import version

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from modules import pqc_demo

MAX_MESSAGE = 4096
MAX_REQUEST = 6 * MAX_MESSAGE + 1024  # Worst-case JSON escaping plus fixed envelope.
MAX_RESPONSE = 128 * 1024
UDP_HEADER = struct.Struct("!4s32sHH")
UDP_PAYLOAD = 1200 - UDP_HEADER.size
DOMAIN = b"crypto-analysis-tool-local-signed-message-v1\x00"


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def backend(algorithm):
    return pqc_demo._pq_module("sign", pqc_demo._SIGN_MODULES[algorithm])


def signing_data(payload, identity):
    fields = {key: identity[key] for key in (
        "format", "algorithm", "classical_algorithm", "pq_public_key_base64",
        "classical_public_key_base64")}
    public_data = canonical(fields)
    if identity.get("fingerprint_sha256") != hashlib.sha256(public_data).hexdigest().upper():
        raise ValueError("固定公钥指纹与身份内容不一致")
    return DOMAIN + len(public_data).to_bytes(4, "big") + public_data + payload


class SigningIdentity:
    """Private keys stay in the managed service's memory."""
    def __init__(self, profile):
        self.profile = profile
        self.module = backend(profile.signature)
        public, self._secret = self.module.generate_keypair()
        self._classical = None
        classical_public = b""
        if profile.classical_signature:
            self._classical, classical_public, _ = pqc_demo._classical_signing_key(profile.classical_signature)
        self.public = {"format": "pqc-lab-signing-identity-v1", "algorithm": profile.signature,
                       "classical_algorithm": profile.classical_signature,
                       "pq_public_key_base64": base64.b64encode(public).decode("ascii"),
                       "classical_public_key_base64": base64.b64encode(classical_public).decode("ascii")}
        self.public["fingerprint_sha256"] = hashlib.sha256(canonical(self.public)).hexdigest().upper()

    def sign(self, payload):
        data = signing_data(payload, self.public)
        classical = (self._classical.sign(data, *pqc_demo._classical_signature_arguments(
            self.profile.classical_signature)) if self._classical else b"")
        return {"format": "pqc-lab-message-proof-v1", "algorithm": self.profile.signature,
                "classical_algorithm": self.profile.classical_signature,
                "identity_fingerprint": self.public["fingerprint_sha256"],
                "pq_signature_base64": base64.b64encode(self.module.sign(self._secret, data)).decode("ascii"),
                "classical_signature_base64": base64.b64encode(classical).decode("ascii")}


def verify_proof(payload, proof, identity):
    result = {"verified": False, "pq_verified": False, "classical_verified": False}
    try:
        algorithm, classic = identity["algorithm"], identity["classical_algorithm"]
        if (identity["format"] != "pqc-lab-signing-identity-v1"
                or algorithm not in pqc_demo.SIGNATURE_VARIANTS
                or classic and classic not in pqc_demo.CLASSICAL_SIGNATURE_VARIANTS
                or proof["format"] != "pqc-lab-message-proof-v1"
                or proof["algorithm"] != algorithm or proof["classical_algorithm"] != classic
                or proof["identity_fingerprint"] != identity["fingerprint_sha256"]):
            return result
        data = signing_data(payload, identity)
        public = base64.b64decode(identity["pq_public_key_base64"], validate=True)
        signature = base64.b64decode(proof["pq_signature_base64"], validate=True)
        result["pq_verified"] = bool(backend(algorithm).verify(public, data, signature))
        if classic:
            key = pqc_demo._load_classical_signing_public(classic,
                base64.b64decode(identity["classical_public_key_base64"], validate=True))
            key.verify(base64.b64decode(proof["classical_signature_base64"], validate=True),
                       data, *pqc_demo._classical_signature_arguments(classic))
            result["classical_verified"] = True
        elif proof.get("classical_signature_base64"):
            return result
        result["verified"] = result["pq_verified"] and (not classic or result["classical_verified"])
    except (KeyError, ValueError, TypeError, InvalidSignature, UnsupportedAlgorithm):
        pass
    return result


def request_payload(request, protocol):
    if (not isinstance(request, dict) or set(request) != {"format", "protocol", "nonce", "message"}
            or request["format"] != "pqc-lab-message-v1" or request["protocol"] != protocol
            or not isinstance(request["nonce"], str) or len(request["nonce"]) != 64
            or len(bytes.fromhex(request["nonce"])) != 32
            or not isinstance(request["message"], str)
            or len(request["message"].encode("utf-8")) > MAX_MESSAGE):
        raise ValueError("消息协议、挑战或长度无效")
    return canonical(request)


def receive_exact(connection, count, deadline):
    data = bytearray()
    while len(data) < count:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("TCP 签名消息超出总等待时间")
        connection.settimeout(remaining)
        chunk = connection.recv(count - len(data))
        if not chunk:
            raise ValueError("TCP 消息不完整")
        data.extend(chunk)
    return bytes(data)


def receive_frame(connection, maximum, deadline=None):
    deadline = deadline if deadline is not None else time.monotonic() + (connection.gettimeout() or 10)
    size = int.from_bytes(receive_exact(connection, 4, deadline), "big")
    if not 0 < size <= maximum:
        raise ValueError("TCP 消息长度越界")
    return receive_exact(connection, size, deadline)


class _BoundedThreads(socketserver.ThreadingMixIn):
    daemon_threads = True
    block_on_close = False
    allow_reuse_address = True

    def process_request(self, request, address):
        if not self.owner._workers.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.owner._workers.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.owner._workers.release()


class SignedMessageServer:
    def __init__(self, base, address, profile):
        if profile.is_tls or address[0] != "127.0.0.1":
            raise ValueError("签名消息服务仅支持本机 TCP/UDP")
        from pqc_lab.lab import write_json
        self.profile = profile
        self.identity = SigningIdentity(profile)
        self._workers = threading.BoundedSemaphore(16)
        self._connections, self._lock = set(), threading.Lock()
        public = Path(base) / "public"
        public.mkdir(parents=True, exist_ok=True)
        write_json(public / "message-identity.json", self.identity.public)
        owner = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                connection = self.request if profile.protocol == "tcp" else None
                try:
                    if connection:
                        connection.settimeout(5)
                        with owner._lock:
                            owner._connections.add(connection)
                        wire = receive_frame(connection, MAX_REQUEST)
                    else:
                        wire = self.request[0]
                        if len(wire) > MAX_REQUEST:
                            return
                    request = json.loads(wire)
                    payload = request_payload(request, profile.protocol)
                    response = canonical({"payload": request, "proof": owner.identity.sign(payload)})
                    if len(response) > MAX_RESPONSE:
                        return
                    if connection:
                        connection.sendall(len(response).to_bytes(4, "big") + response)
                    else:
                        chunks = [response[i:i + UDP_PAYLOAD] for i in range(0, len(response), UDP_PAYLOAD)]
                        nonce = bytes.fromhex(request["nonce"])
                        for index, chunk in enumerate(chunks):
                            self.request[1].sendto(UDP_HEADER.pack(b"PQM1", nonce, index, len(chunks)) + chunk,
                                                   self.client_address)
                except (OSError, ValueError, TypeError, KeyError):
                    return
                finally:
                    if connection:
                        with owner._lock:
                            owner._connections.discard(connection)

        parent = socketserver.TCPServer if profile.protocol == "tcp" else socketserver.UDPServer
        server_type = type("LocalSignedMessageServer", (_BoundedThreads, parent), {})
        server_type.owner = self
        server_type.max_packet_size = MAX_REQUEST + 1
        self._server = server_type(address, Handler)
        self.server_address = self._server.server_address
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def start(self):
        self._thread.start()

    def is_alive(self):
        return self._thread.is_alive()

    def close(self):
        with self._lock:
            for connection in tuple(self._connections):
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                connection.close()
        if self._thread.is_alive():
            self._server.shutdown()
            self._thread.join(timeout=6)
        self._server.server_close()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *_args):
        self.close()


def exchange(port, profile, request):
    wire = request_payload(request, profile.protocol)
    deadline = time.monotonic() + 10
    if profile.protocol == "tcp":
        with socket.create_connection(("127.0.0.1", port), timeout=10) as connection:
            connection.sendall(len(wire).to_bytes(4, "big") + wire)
            return json.loads(receive_frame(connection, MAX_RESPONSE, deadline)), 1
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        connection.connect(("127.0.0.1", port))
        connection.settimeout(10)
        connection.send(wire)
        pieces, total, size = {}, None, 0
        while total is None or len(pieces) < total:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("UDP 签名响应超出总等待时间")
            connection.settimeout(remaining)
            packet = connection.recv(1201)
            if time.monotonic() >= deadline:
                raise TimeoutError("UDP 签名响应超出总等待时间")
            if not UDP_HEADER.size < len(packet) <= 1200:
                raise ValueError("UDP 分片长度无效")
            magic, nonce, index, count = UDP_HEADER.unpack(packet[:UDP_HEADER.size])
            if (magic != b"PQM1" or nonce != bytes.fromhex(request["nonce"])
                    or not 1 <= count <= (MAX_RESPONSE + UDP_PAYLOAD - 1) // UDP_PAYLOAD
                    or index >= count or total is not None and count != total):
                raise ValueError("UDP 分片标识或编号无效")
            total = count
            chunk = packet[UDP_HEADER.size:]
            if index in pieces and pieces[index] != chunk:
                raise ValueError("UDP 分片内容冲突")
            if index not in pieces:
                size += len(chunk)
                if size > MAX_RESPONSE:
                    raise ValueError("UDP 响应超过重组上限")
                pieces[index] = chunk
        return json.loads(b"".join(pieces[index] for index in range(total))), total


def verify_messages(base, port, profile, message):
    from pqc_lab.lab import write_json, now
    public = Path(base) / "public"
    public.mkdir(parents=True, exist_ok=True)
    report = {"status": "running", "generated_at": now(), "target": f"127.0.0.1:{port}",
              "profile": profile.as_dict(), "checks": [], "summary": {},
              "openssl_version": "应用签名后端 pqcrypto " + version("pqcrypto"),
              "trust_scope": "Local pinned signing public key; plaintext application protocol; no TLS CA trust."}
    write_json(public / "evidence.json", report)

    def check(identifier, label, passed, detail):
        report["checks"].append({"id": identifier, "label": label, "passed": bool(passed), "detail": detail})

    try:
        request = {"format": "pqc-lab-message-v1", "protocol": profile.protocol,
                   "nonce": secrets.token_hex(32), "message": message}
        payload = request_payload(request, profile.protocol)
        identity = json.loads((public / "message-identity.json").read_text(encoding="utf-8"))
        if identity["algorithm"] != profile.signature or identity["classical_algorithm"] != profile.classical_signature:
            raise ValueError("服务固定公钥与本次选择的签名算法不一致")
        response, fragments = exchange(port, profile, request)
        proof = response["proof"]
        verified = verify_proof(payload, proof, identity)
        signature = base64.b64decode(proof["pq_signature_base64"], validate=True)
        check("message_exchange", "真实 " + profile.protocol.upper() + " 消息往返与内容核对",
              response["payload"] == request, f"UTF-8 {len(message.encode('utf-8'))} 字节；响应分片 {fragments}")
        check("message_signature", "使用本地固定公钥验证实际消息签名", verified["verified"],
              profile.signature + (" + " + profile.classical_signature if profile.classical_signature else ""))
        changed = dict(request, message=message + "!")
        check("reject_changed_message", "负向对照：篡改消息被拒绝",
              not verify_proof(canonical(changed), proof, identity)["verified"], "保留原签名，修改消息")
        bad = copy.deepcopy(proof)
        broken = bytearray(signature)
        broken[-1] ^= 1
        bad["pq_signature_base64"] = base64.b64encode(broken).decode("ascii")
        bad_result = verify_proof(payload, bad, identity)
        check("reject_changed_signature", "负向对照：篡改签名被拒绝",
              not bad_result["verified"], "保持签名长度，改变签名字节")
        wrong = copy.deepcopy(identity)
        wrong["pq_public_key_base64"] = base64.b64encode(b"x" * len(base64.b64decode(
            identity["pq_public_key_base64"]))).decode("ascii")
        check("reject_wrong_key", "负向对照：错误固定公钥被拒绝",
              not verify_proof(payload, proof, wrong)["verified"], "不接受响应自行声明的新公钥")
        check("reject_replay", "负向对照：旧签名不能用于新挑战",
              not verify_proof(canonical(dict(request, nonce=secrets.token_hex(32))), proof, identity)["verified"],
              "每轮请求绑定 32 字节随机挑战")
        check("reject_wrong_protocol", "负向对照：跨协议使用签名被拒绝",
              not verify_proof(canonical(dict(request, protocol="udp" if profile.protocol == "tcp" else "tcp")),
                               proof, identity)["verified"], "签名绑定 TCP/UDP 实验协议标识")
        if profile.classical_signature:
            check("reject_pq_component", "混合签名：后量子组成部分损坏即拒绝",
                  not bad_result["verified"], "接受规则为传统验签 AND 后量子验签")
            classic = bytearray(base64.b64decode(proof["classical_signature_base64"], validate=True))
            classic[-1] ^= 1
            bad = dict(proof, classical_signature_base64=base64.b64encode(classic).decode("ascii"))
            partial = verify_proof(payload, bad, identity)
            check("reject_classical_component", "混合签名：传统组成部分损坏即拒绝",
                  partial["pq_verified"] and not partial["verified"], "后量子签名仍有效，也必须拒绝")
        report["summary"] = {
            "protocol": profile.protocol.upper(), "group_name": "无密钥交换（明文消息）",
            "signature_algorithm": profile.signature, "classical_signature_algorithm": profile.classical_signature,
            "certificate_algorithm": profile.signature, "message_signature_verified": verified["verified"],
            "pq_signature_verified": verified["pq_verified"],
            "classical_signature_verified": verified["classical_verified"],
            "transport_confidentiality": False, "response_fragments": fragments,
            "signature_bytes": len(signature), "public_key_bytes": len(base64.b64decode(identity["pq_public_key_base64"])),
            "signing_key_fingerprint_sha256": identity["fingerprint_sha256"], "message": message,
        }
        write_json(public / "signed-message.json", response)
        report["status"] = "passed" if all(item["passed"] for item in report["checks"]) else "failed"
    except Exception as exc:
        report["status"], report["error"] = "failed", f"{type(exc).__name__}: {exc}"
    report["generated_at"] = now()
    write_json(public / "evidence.json", report)
    return report
