"""Recompute one recorded TLS 1.3 connection, without opening a new connection.

Session fields are public hex-encoded wire observations. ``_secrets`` is a
separate, memory-only bundle bound to the ClientHello/ServerHello fingerprint.
RFC 8446 sections 4.4.3, 4.4.4, 5.2, 5.3 and 7 define the replay operations.
"""
import copy
import hashlib
import hmac

from cryptography.exceptions import InvalidSignature, InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519

from modules import pqc_detect


REFERENCE = "RFC 8446 §4.4、§5、§7"
KEM_GROUPS = {0x0200: "ml_kem_512", 0x0201: "ml_kem_768", 0x0202: "ml_kem_1024",
              0x11EB: "ml_kem_768", 0x11EC: "ml_kem_768",
              0x11ED: "ml_kem_1024", 0x11EE: "ml_kem_1024"}
HYBRID_GROUPS = {0x11EB, 0x11EC, 0x11ED, 0x11EE}
STATUS_TEXT = {"passed": "通过 / 一致", "failed": "失败 / 不一致", "missing": "缺少参数",
               "computed": "已计算，缺少比较值", "unsupported": "不支持",
               "not_applicable": "不适用"}


def _bytes(value):
    if isinstance(value, bytes):
        return value
    if not isinstance(value, str):
        raise ValueError("字节参数必须为十六进制字符串")
    return bytes.fromhex(value)


def _number(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def _step(title, formula, **values):
    return {"title": title, "formula": formula, "values": values, "reference": REFERENCE}


def _result(status, detail="", *, missing=None, output=None, steps=None):
    return {"status": status, "detail": detail, "missing": missing or [],
            "output": output or {}, "steps": steps or []}


def _records(stream):
    records, offset = [], 0
    while offset + 5 <= len(stream):
        size = int.from_bytes(stream[offset + 3:offset + 5], "big")
        if stream[offset] not in (20, 21, 22, 23) or stream[offset + 1:offset + 3] not in (b"\x03\x01", b"\x03\x03"):
            return records, "TLS 记录头无效（可能存在抓包缺口或非 TLS 数据）"
        if offset + 5 + size > len(stream):
            return records, "TLS 记录截断：缺少完整密文 / 认证标签"
        records.append(stream[offset:offset + 5 + size])
        offset += 5 + size
    return records, "TLS 记录头截断" if offset != len(stream) else ""


def _messages(data):
    messages, offset = [], 0
    while offset + 4 <= len(data):
        size = int.from_bytes(data[offset + 1:offset + 4], "big")
        if offset + 4 + size > len(data):
            break
        messages.append(data[offset:offset + 4 + size])
        offset += 4 + size
    return messages, data[offset:]


def _extensions(body, offset):
    if offset + 2 > len(body):
        raise ValueError("Hello 扩展列表缺失")
    end = offset + 2 + int.from_bytes(body[offset:offset + 2], "big")
    offset += 2
    if end != len(body):
        raise ValueError("Hello 扩展列表长度不符")
    result = {}
    while offset < end:
        if offset + 4 > end:
            raise ValueError("Hello 扩展头截断")
        kind, size = int.from_bytes(body[offset:offset + 2], "big"), int.from_bytes(body[offset + 2:offset + 4], "big")
        offset += 4
        if offset + size > end or kind in result:
            raise ValueError("Hello 扩展截断或重复")
        result[kind] = body[offset:offset + size]
        offset += size
    return result


def session_from_streams(client, server, *, label="真实 TLS 会话"):
    client, server = _bytes(client), _bytes(server)
    cr, ce = _records(client)
    sr, se = _records(server)
    cm, _ = _messages(b"".join(r[5:] for r in cr if r[0] == 22))
    sm, _ = _messages(b"".join(r[5:] for r in sr if r[0] == 22))
    ch = next((m for m in cm if m[0] == 1), b"")
    sh = next((m for m in sm if m[0] == 2), b"")
    session = {"schema": "tls13-recheck-v1", "label": label,
               "session_id": hashlib.sha256(ch + sh).hexdigest(),
               "client_wire": client.hex(), "server_wire": server.hex(),
               "client_hello": ch.hex(), "server_hello": sh.hex(),
               "client_records": [r.hex() for r in cr if r[0] == 23],
               "server_records": [r.hex() for r in sr if r[0] == 23],
               "wire_errors": [e for e in (ce, se) if e],
               "group_id": 0, "group_name": "未取得", "cipher_code": 0,
               "certificate_chain": [], "signature": "", "transcript_before_cv": ""}
    try:
        shares = {}
        if ch:
            body = ch[4:]
            if len(body) < 38:
                raise ValueError("ClientHello 截断")
            session["client_random"] = body[2:34].hex()
            offset = 35 + body[34]
            offset += 2 + int.from_bytes(body[offset:offset + 2], "big")
            offset += 1 + body[offset]
            exts = _extensions(body, offset)
            session["early_data"] = 42 in exts
            share = exts.get(51, b"")
            if share:
                if int.from_bytes(share[:2], "big") != len(share) - 2:
                    raise ValueError("ClientHello key_share 列表长度不符")
                offset = 2
                while offset < len(share):
                    if offset + 4 > len(share):
                        raise ValueError("客户端 key_share 截断")
                    gid, size = int.from_bytes(share[offset:offset + 2], "big"), int.from_bytes(share[offset + 2:offset + 4], "big")
                    offset += 4
                    if offset + size > len(share) or gid in shares:
                        raise ValueError("客户端 key_share 长度无效或重复")
                    shares[gid] = share[offset:offset + size]
                    offset += size
        if sh:
            body = sh[4:]
            if len(body) < 38:
                raise ValueError("ServerHello 截断")
            session["hrr"] = body[2:34] == pqc_detect.HRR_RANDOM or len([m for m in sm if m[0] == 2]) > 1
            offset = 35 + body[34]
            cipher = int.from_bytes(body[offset:offset + 2], "big")
            session.update(cipher_code=cipher, cipher_suite=pqc_detect._cipher_name(cipher))
            exts = _extensions(body, offset + 3)
            session["tls13"] = exts.get(43) == b"\x03\x04"
            session["psk"] = 41 in exts
            share = exts.get(51, b"")
            if share and not session["hrr"]:
                if len(share) < 4 or int.from_bytes(share[2:4], "big") != len(share) - 4:
                    raise ValueError("服务器 key_share 长度无效")
                gid = int.from_bytes(share[:2], "big")
                session.update(group_id=gid, group_name=pqc_detect.lookup_group(gid)[0],
                               client_key_share=shares.get(gid, b"").hex(), server_key_share=share[4:].hex())
    except (ValueError, IndexError) as exc:
        session["wire_errors"].append(str(exc))
    return session


def private_parameters(group, handle):
    """Serialize our own temporary key only for the in-memory review bundle."""
    kind = handle[0]
    parameters = {}
    if kind in ("mlkem", "hybrid"):
        parameters["kem_private_key"] = handle[1].hex()
    if kind in ("ec", "x25519", "hybrid"):
        private = handle[3] if kind == "hybrid" else handle[1]
        if isinstance(private, x25519.X25519PrivateKey):
            raw = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        else:
            raw = private.private_numbers().private_value.to_bytes((private.curve.key_size + 7) // 8, "big")
        parameters["ecdh_private_key"] = raw.hex()
    return parameters


def _observe_messages(session, messages):
    transcript = _bytes(session["client_hello"]) + _bytes(session["server_hello"])
    for message in messages:
        body = message[4:]
        if message[0] == 11:
            session["certificate_chain"] = [c.hex() for c in pqc_detect._cert_chain_from_certificate(body)]
        elif message[0] == 15:
            if len(body) < 4 or int.from_bytes(body[2:4], "big") != len(body) - 4:
                raise ValueError("CertificateVerify 签名长度不符")
            session.update(signature_scheme=int.from_bytes(body[:2], "big"), signature=body[4:].hex(),
                           transcript_before_cv=transcript.hex())
        transcript += message
    return transcript


def session_from_report(report, *, label=None):
    public = report.get("recheck_session")
    if public:
        session = session_from_streams(public.get("client_wire", ""), public.get("server_wire", ""),
                                       label=label or public.get("label", "导入的会话"))
        for key in ("certificate_chain", "signature_scheme", "signature", "transcript_before_cv"):
            if key in public:
                session[key] = copy.deepcopy(public[key])
        return session
    deep = report.get("deep") or {}
    # A failed deep attempt and any fallback probe are distinct connections.
    source = deep if deep.get("trace") else report.get("transport") or {}
    trace = source.get("trace") or []
    client = b"".join(i.get("raw", b"") for i in trace if i.get("dir") == "→")
    server = b"".join(i.get("raw", b"") for i in trace if i.get("dir") == "←")
    session = session_from_streams(client, server, label=label or "检测 %s:%s · %s" % (
        report.get("host", ""), report.get("port", ""), report.get("started_at", "")))
    plain = b"".join(i.get("plain", b"")[:-1] for i in trace if i.get("content_type") == 22)
    messages, _ = _messages(plain)
    try:
        _observe_messages(session, messages)
    except ValueError as exc:
        session["wire_errors"].append(str(exc))
    if source is deep and deep.get("_recheck_secrets"):
        session["_secrets"] = dict(deep["_recheck_secrets"], session_id=session["session_id"])
    return session


def public_session(session):
    return {key: copy.deepcopy(value) for key, value in session.items() if not key.startswith("_")}


def verify_exchange(session, parameters):
    group = session.get("group_id", 0)
    need = []
    if not group:
        need.append("group_id")
    if not session.get("server_key_share"):
        need.append("server_key_share")
    if group in KEM_GROUPS and not parameters.get("kem_private_key"):
        need.append("kem_private_key")
    if group in HYBRID_GROUPS | {0x0017, 0x0018, 0x001D} and not parameters.get("ecdh_private_key"):
        need.append("ecdh_private_key")
    if need:
        return _result("missing", "需要同次连接的交换材料与客户端临时私钥；抓包不能恢复私钥。", missing=need)
    if group not in KEM_GROUPS and group not in (0x0017, 0x0018, 0x001D):
        return _result("unsupported", "尚不支持该密钥交换组")
    steps, out = [], {}
    try:
        server, client = _bytes(session["server_key_share"]), _bytes(session.get("client_key_share", ""))
        expected_size = pqc_detect.KEY_SHARE_BODY_SIZES.get(group)
        if expected_size and len(server) + 4 != expected_size:
            raise ValueError("服务器交换材料长度不符")
        kem_ct, kem_pk, ec_pub, ec_client = server, client, server, client
        if group in HYBRID_GROUPS:
            ec_size = 32 if group in (0x11EC, 0x11EE) else 65 if group == 0x11EB else 97
            if group in (0x11EC, 0x11EE):
                kem_ct, ec_pub = server[:-ec_size], server[-ec_size:]
                kem_pk, ec_client = client[:-ec_size], client[-ec_size:]
            else:
                ec_pub, kem_ct = server[:ec_size], server[ec_size:]
                ec_client, kem_pk = client[:ec_size], client[ec_size:]
        if group in KEM_GROUPS:
            from importlib import import_module
            kem = import_module("pqcrypto.kem." + KEM_GROUPS[group])
            sk = _bytes(parameters["kem_private_key"])
            if len(sk) != kem.SECRET_KEY_SIZE or len(kem_ct) != kem.CIPHERTEXT_SIZE:
                raise ValueError("ML-KEM 私钥 / 封装密文长度不符")
            pk_offset = kem.SECRET_KEY_SIZE - kem.PUBLIC_KEY_SIZE - 64
            if kem_pk and sk[pk_offset:pk_offset + kem.PUBLIC_KEY_SIZE] != kem_pk:
                raise ValueError("ML-KEM 私钥与本次 ClientHello 的公钥不匹配")
            secret = kem.decrypt(sk, kem_ct)
            out["kem_shared_secret"] = secret.hex()
            steps.append(_step("ML-KEM 解封装", "K_KEM = ML-KEM.Decaps(dk, c)；隐式拒绝结果仍须与实际比较值核对",
                               algorithm=KEM_GROUPS[group], private_key=sk, ciphertext=kem_ct, shared_secret=secret))
            from modules.mlkem_trace import MLKEM, Trace
            trace = Trace()
            traced = MLKEM("ML-KEM-" + KEM_GROUPS[group].rsplit("_", 1)[1]).decaps(sk, kem_ct, trace)
            steps.extend(trace.steps)
            if not hmac.compare_digest(secret, traced):
                raise ValueError("实际 ML-KEM 数学重算与原生解封装输出不一致")
        else:
            secret = b""
        if group in HYBRID_GROUPS | {0x0017, 0x0018, 0x001D}:
            raw = _bytes(parameters["ecdh_private_key"])
            if group in (0x001D, 0x11EC, 0x11EE):
                private = x25519.X25519PrivateKey.from_private_bytes(raw)
                own_pub = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                classic = private.exchange(x25519.X25519PublicKey.from_public_bytes(ec_pub))
            else:
                curve = ec.SECP384R1() if group in (0x0018, 0x11ED) else ec.SECP256R1()
                if len(raw) != (curve.key_size + 7) // 8:
                    raise ValueError("ECDHE 临时私钥长度不符")
                private = ec.derive_private_key(int.from_bytes(raw, "big"), curve)
                own_pub = private.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
                classic = private.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(curve, ec_pub))
            if ec_client and own_pub != ec_client:
                raise ValueError("ECDHE 临时私钥与本次 ClientHello 公钥不匹配")
            out["ecdh_shared_secret"] = classic.hex()
            steps.append(_step("ECDHE 重算", "K_ECDHE = ECDHE(客户端临时私钥, 服务器临时公钥)", private_key=raw,
                               peer_public_key=ec_pub, shared_secret=classic))
            secret = secret + classic if group in (0x11EC, 0x11EE) else classic + secret
        out["shared_secret"] = secret.hex()
        baseline = parameters.get("expected_shared_secret")
        if not baseline:
            return _result("computed", "共享秘密已重算；未提供原连接的共享秘密，不能声明一致。",
                           missing=["expected_shared_secret"], output=out, steps=steps)
        matches = hmac.compare_digest(secret, _bytes(baseline))
        out["consistent"] = matches
        steps.append(_step("共享秘密一致性比较", "constant_time_compare(K_recomputed, K_recorded)",
                           actual=secret, recorded=_bytes(baseline), consistent=matches))
        return _result("passed" if matches else "failed", "重算共享秘密与原连接记录%s" % ("一致" if matches else "不一致"), output=out, steps=steps)
    except (UnsupportedAlgorithm, ImportError) as exc:
        return _result("unsupported", str(exc), output=out, steps=steps)
    except (ValueError, TypeError) as exc:
        return _result("failed", str(exc), output=out, steps=steps)


def verify_signature(session):
    need = [key for key in ("certificate_chain", "signature_scheme", "signature", "transcript_before_cv") if not session.get(key)]
    if need:
        return _result("missing", "TLS 1.3 的 Certificate / CertificateVerify 位于加密握手中，需要先解密或导入同次握手记录。", missing=need)
    steps = []
    try:
        suite = pqc_detect._TLS13_SUITES.get(session.get("cipher_code"))
        if suite is None:
            return _result("unsupported", "未取得支持的 TLS 1.3 密码套件")
        digest = hashlib.new(suite[0], _bytes(session["transcript_before_cv"])).digest()
        transcript = _bytes(session["transcript_before_cv"])
        prefix = _bytes(session.get("client_hello", "")) + _bytes(session.get("server_hello", ""))
        if not session.get("client_hello") or not session.get("server_hello") or not transcript.startswith(prefix):
            raise ValueError("握手转录与所选会话的 ClientHello / ServerHello 不匹配")
        content = b" " * 64 + b"TLS 1.3, server CertificateVerify\0" + digest
        cert, sig = _bytes(session["certificate_chain"][0]), _bytes(session["signature"])
        prior, remainder = _messages(transcript[len(prefix):])
        if remainder or not any(msg[0] == 11 and pqc_detect._cert_chain_from_certificate(msg[4:])[0] == cert for msg in prior):
            raise ValueError("验签证书不在所选会话的完整握手转录中")
        scheme = _number(session["signature_scheme"])
        oid, public, _ = pqc_detect.spki_from_der(cert)
        steps.append(_step("握手转录摘要", "H = Hash(ClientHello || ServerHello || ... || Certificate)",
                           transcript=_bytes(session["transcript_before_cv"]), hash_algorithm=suite[0], digest=digest))
        steps.append(_step("CertificateVerify 验签", "Verify(证书公钥, 64 个空格 || context || 00 || H, 原握手签名)",
                           certificate=cert, public_key_oid=oid, public_key=public, scheme=scheme, signed_content=content, signature=sig))
        verified = pqc_detect._verify_cert_verify(None, scheme, content, sig, cert_der=cert)
        return _result("passed" if verified else "failed", "握手签名%s；该结果不包含 CA 信任或域名验证。" % ("验证通过" if verified else "验证失败"),
                       output={"verified": bool(verified), "transcript_hash": digest.hex(), "signed_content": content.hex()}, steps=steps)
    except (UnsupportedAlgorithm, ImportError) as exc:
        return _result("unsupported", str(exc), steps=steps)
    except (InvalidSignature, ValueError, TypeError) as exc:
        return _result("failed", "握手签名验证失败：" + (str(exc) or type(exc).__name__), output={"verified": False}, steps=steps)


def _handshake_secrets(session, shared):
    hash_name, size, _, _ = pqc_detect._TLS13_SUITES[session["cipher_code"]]
    zeros = bytes(size)
    early = pqc_detect._hkdf_extract(zeros, zeros, hash_name)
    derived = pqc_detect._derive_secret(early, b"derived", b"", hash_name, size)
    handshake = pqc_detect._hkdf_extract(derived, shared, hash_name)
    transcript = _bytes(session["client_hello"]) + _bytes(session["server_hello"])
    values = {direction + "_handshake_traffic_secret": pqc_detect._derive_secret(handshake, label, transcript, hash_name, size).hex()
              for direction, label in (("server", b"s hs traffic"), ("client", b"c hs traffic"))}
    steps = [_step("TLS 1.3 握手秘密与流量秘密派生", "early = HKDF-Extract(0, 0)；derived = Derive-Secret(early, derived, Hash(空))；"
                   "handshake = HKDF-Extract(derived, shared)；traffic = Derive-Secret(handshake, c/s hs traffic, Hash(CH || SH))",
                   hash_algorithm=hash_name, early_secret=early, derived_secret=derived, shared_secret=shared,
                   handshake_secret=handshake, transcript=transcript,
                   transcript_hash=hashlib.new(hash_name, transcript).digest(), **{k: _bytes(v) for k, v in values.items()})]
    return values, steps, handshake


def _keylog_parameters(text, client_random, size):
    mapping = {"SERVER_HANDSHAKE_TRAFFIC_SECRET": "server_handshake_traffic_secret",
               "CLIENT_HANDSHAKE_TRAFFIC_SECRET": "client_handshake_traffic_secret",
               "SERVER_TRAFFIC_SECRET_0": "server_application_traffic_secret",
               "CLIENT_TRAFFIC_SECRET_0": "client_application_traffic_secret"}
    found = {}
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) != 3:
            raise ValueError("Key Log 第 %d 行格式无效" % number)
        label, random, secret = fields
        if random.lower() != client_random.lower() or label not in mapping:
            continue
        if len(_bytes(secret)) != size:
            raise ValueError("Key Log 流量秘密长度与密码套件不符")
        name = mapping[label]
        if name in found and found[name] != secret.lower():
            raise ValueError("Key Log 中同一会话流量秘密冲突")
        found[name] = secret.lower()
    return found


def _decrypt_records(session, parameters):
    hash_name, hlen, klen, aead = pqc_detect._TLS13_SUITES[session["cipher_code"]]
    output, steps, missing, failures = [], [], [], []
    server_messages = []
    finished_verified = None
    for direction in ("server", "client"):
        records = session.get(direction + "_records") or []
        if not records:
            continue
        if direction == "client" and session.get("early_data"):
            missing.append("0-RTT / early_data 解密尚不支持")
            continue
        epoch, seq, pending = "handshake", 0, b""
        finished_seen = False
        traffic = None
        for raw in records:
            prefix = direction + "_" + epoch
            secret = traffic if traffic is not None else parameters.get(prefix + "_traffic_secret")
            if secret:
                secret = _bytes(secret)
                if len(secret) != hlen:
                    raise ValueError(prefix + "_traffic_secret 长度不符")
                key = pqc_detect._expand_label(secret, b"key", b"", klen, hash_name)
                iv = pqc_detect._expand_label(secret, b"iv", b"", 12, hash_name)
            elif parameters.get(prefix + "_key") and parameters.get(prefix + "_iv"):
                key, iv = _bytes(parameters[prefix + "_key"]), _bytes(parameters[prefix + "_iv"])
            else:
                missing.append(prefix + "_traffic_secret（或 " + prefix + "_key + " + prefix + "_iv）")
                break
            if len(key) != klen or len(iv) != 12:
                raise ValueError("原连接 AEAD 密钥或 IV 长度不符")
            wire = _bytes(raw)
            if len(wire) < 5 or wire[0:3] != b"\x17\x03\x03" or int.from_bytes(wire[3:5], "big") != len(wire) - 5:
                failures.append("加密记录头 / 长度无效")
                break
            header, ciphertext = wire[:5], wire[5:]
            nonce = pqc_detect._nonce(iv, seq)
            row = {"direction": direction, "epoch": epoch, "sequence": seq, "authenticated": False}
            output.append(row)
            values = {"traffic_secret": secret or b"", "key": key, "iv": iv, "sequence": seq,
                      "nonce": nonce, "aad": header, "ciphertext_and_tag": ciphertext}
            seq += 1
            try:
                plain = pqc_detect._aead_decrypt(aead, key, nonce, header, ciphertext)
                unpadded = plain.rstrip(b"\0")
                if not unpadded or unpadded[-1] not in (21, 22, 23):
                    raise ValueError("TLSInnerPlaintext 内容类型无效")
                kind, content = unpadded[-1], unpadded[:-1]
                row.update(authenticated=True, inner_plaintext=plain.hex(), content_type=kind,
                           content=content.hex(), utf8=content.decode("utf-8", "replace"))
                steps.append(_step("%s %s 记录 #%d" % (direction, epoch, row["sequence"]),
                                   "nonce = IV XOR padded_seq；AEAD.Decrypt(key, nonce, ciphertext || tag, TLS 记录头)",
                                   **values, plaintext=plain, authenticated=True))
                if kind == 22:
                    pending += content
                    messages, pending = _messages(pending)
                    for msg in messages:
                        if direction == "server":
                            if msg[0] == 20:
                                if secret:
                                    transcript = _bytes(session["client_hello"]) + _bytes(session["server_hello"]) + b"".join(server_messages)
                                    digest = hashlib.new(hash_name, transcript).digest()
                                    finished_key = pqc_detect._expand_label(secret, b"finished", b"", hlen, hash_name)
                                    expect = hmac.new(finished_key, digest, hash_name).digest()
                                    finished_verified = hmac.compare_digest(expect, msg[4:])
                                    steps.append(_step("服务器 Finished 校验", "verify_data = HMAC(finished_key, Hash(transcript))",
                                                       finished_key=finished_key, transcript_hash=digest, expected=expect,
                                                       actual=msg[4:], consistent=finished_verified))
                                    if not finished_verified:
                                        failures.append("服务器 Finished 不一致")
                                else:
                                    missing.append("server_handshake_traffic_secret（校验 Finished）")
                            server_messages.append(msg)
                            if msg[0] == 20 and finished_verified and parameters.get("_derived_handshake_secret"):
                                handshake_secret = parameters["_derived_handshake_secret"]
                                derived = pqc_detect._derive_secret(handshake_secret, b"derived", b"", hash_name, hlen)
                                master = pqc_detect._hkdf_extract(derived, bytes(hlen), hash_name)
                                transcript = _bytes(session["client_hello"]) + _bytes(session["server_hello"]) + b"".join(server_messages)
                                app_values = {}
                                for side, label in (("server", b"s ap traffic"), ("client", b"c ap traffic")):
                                    field = side + "_application_traffic_secret"
                                    value = pqc_detect._derive_secret(master, label, transcript, hash_name, hlen)
                                    if parameters.get(field) and _bytes(parameters[field]) != value:
                                        raise ValueError("原连接的应用流量秘密与重算值不一致：" + field)
                                    parameters[field] = value.hex()
                                    app_values[field] = value
                                steps.append(_step("原连接主秘密与应用流量秘密派生", "master = HKDF-Extract(Derive-Secret(handshake, derived, 空), 0)；"
                                                   "app_traffic = Derive-Secret(master, c/s ap traffic, Hash(转录至服务器 Finished))",
                                                   derived_secret=derived, master_secret=master,
                                                   transcript_hash=hashlib.new(hash_name, transcript).digest(), **app_values))
                        if msg[0] == 20:
                            finished_seen = True
                            epoch, seq, traffic = "application", 0, None
                        elif msg[0] == 24:
                            if not secret or len(msg) != 5 or msg[4] not in (0, 1):
                                missing.append(prefix + "_traffic_secret（KeyUpdate）")
                                break
                            traffic = pqc_detect._expand_label(secret, b"traffic upd", b"", hlen, hash_name).hex()
                            seq = 0
            except (InvalidTag, ValueError) as exc:
                row["error"] = "认证失败 / 记录无效：" + (str(exc) or type(exc).__name__)
                failures.append(row["error"])
                steps.append(_step("记录认证失败", "认证失败时不输出明文", **values, authenticated=False))
                break
        if pending:
            missing.append(direction + " 握手记录不完整")
        if not finished_seen:
            missing.append(direction + "_finished")
    out = {"records": output, "finished_verified": finished_verified}
    if failures:
        status, detail = "failed", "；".join(failures)
    elif missing or session.get("wire_errors"):
        status, detail = "missing", "部分记录尚未完成复核"
        missing += session.get("wire_errors", [])
    elif not output:
        status, detail, missing = "missing", "没有实际加密记录", ["encrypted_records"]
    else:
        status, detail = "passed", "实际记录均通过 AEAD 认证；显示原始明文及去除 TLS 内层类型和填充后的内容。"
        if not any(row.get("content_type") == 23 for row in output):
            detail += "本次材料仅包含握手 / 控制密文，未记录应用报文。"
    return _result(status, detail, missing=list(dict.fromkeys(missing)), output=out, steps=steps), server_messages


def recheck(session, parameters=None, *, keylog=""):
    session = copy.deepcopy(session)
    parameters = dict(parameters or {})
    if parameters and parameters.get("session_id") != session.get("session_id"):
        raise ValueError("秘密参数必须绑定所选会话的 session_id；禁止混用不同连接的材料")
    if session.get("hrr") or (session.get("server_hello") and not session.get("tls13")):
        reason = "暂不支持 HelloRetryRequest 的转录重建" if session.get("hrr") else "当前复核支持 TLS 1.3；该连接未协商 TLS 1.3"
        return dict(input=public_session(session), **{k: _result("unsupported", reason) for k in ("exchange", "signature", "records")})
    exchange = verify_exchange(session, parameters)
    suite = pqc_detect._TLS13_SUITES.get(session.get("cipher_code"))
    if not suite:
        records = _result("missing", "缺少支持的 TLS 1.3 密码套件", missing=["cipher_code"])
    else:
        if keylog:
            for key, value in _keylog_parameters(keylog, session.get("client_random", ""), suite[1]).items():
                if parameters.get(key) and _bytes(parameters[key]) != _bytes(value):
                    raise ValueError("秘密参数与 Key Log 的 " + key + " 冲突")
                parameters[key] = value
        shared = exchange["output"].get("shared_secret")
        if shared and session.get("client_hello") and session.get("server_hello") and not session.get("psk"):
            derived, derivation_steps, handshake_secret = _handshake_secrets(session, _bytes(shared))
            exchange["steps"].extend(derivation_steps)
            parameters["_derived_handshake_secret"] = handshake_secret
            for key, value in derived.items():
                if parameters.get(key) and _bytes(parameters[key]) != _bytes(value):
                    raise ValueError("重算流量秘密与所提供的 " + key + " 不一致")
                parameters[key] = value
        try:
            records, messages = _decrypt_records(session, parameters)
            # Signature observations from authenticated wire take precedence over
            # stored observations. A cached `verified=True` is never consulted.
            if messages:
                for key in ("certificate_chain", "signature_scheme", "signature", "transcript_before_cv"):
                    session.pop(key, None)
                _observe_messages(session, messages)
        except (ValueError, TypeError) as exc:
            records = _result("failed", str(exc))
    return {"input": public_session(session), "exchange": exchange,
            "signature": verify_signature(session), "records": records}
