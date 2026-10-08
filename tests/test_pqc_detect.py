# -*- coding: utf-8 -*-
"""抗量子检测模块（modules/pqc_detect.py）离线自检。

完全离线：用本地模拟 TLS 服务器构造 ServerHello，验证传输层判定；
用现场生成/手工构造的证书验证证书层判定。运行：

    python tests/test_pqc_detect.py
"""
import datetime
import base64
import os
import socket
import struct
import sys
import threading
import time
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules import pqc_detect   # noqa: E402


# ---------------------------------------------------------------- 模拟 TLS 服务器
def _hs(msg_type, body):
    return bytes([msg_type]) + len(body).to_bytes(3, "big") + body


def _ext(t, body):
    return struct.pack(">HH", t, len(body)) + body


def mock_server(port, group_id, share_len, ready):
    """只回一个 ServerHello，key_share 用指定组与长度（用于验证判定与长度校验）。"""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)
    ready.set()
    conn, _ = srv.accept()
    conn.recv(65535)                       # 读掉 ClientHello
    exts = _ext(43, b"\x03\x04") + _ext(51, struct.pack(">HH", group_id, share_len)
                                        + os.urandom(share_len))
    body = (b"\x03\x03" + os.urandom(32) + b"\x00" + b"\x13\x01" + b"\x00"
            + struct.pack(">H", len(exts)) + exts)
    hs = _hs(2, body)
    conn.sendall(b"\x16\x03\x03" + struct.pack(">H", len(hs)) + hs)
    time.sleep(0.3)
    conn.close()
    srv.close()


def probe_mock(group_id, share_len, port):
    ready = threading.Event()
    threading.Thread(target=mock_server, args=(port, group_id, share_len, ready),
                     daemon=True).start()
    ready.wait(3)
    return pqc_detect.probe_tls("127.0.0.1", port, timeout=6)


# ---------------------------------------------------------------- 手工构造证书
def _der(tag, val):
    if len(val) < 128:
        return bytes([tag, len(val)]) + val
    n = (len(val).bit_length() + 7) // 8
    return bytes([tag, 0x80 | n]) + len(val).to_bytes(n, "big") + val


def _oid(dotted):
    parts = [int(x) for x in dotted.split(".")]
    out = bytes([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        chunk = [p & 0x7F]
        p >>= 7
        while p:
            chunk.append((p & 0x7F) | 0x80)
            p >>= 7
        out += bytes(reversed(chunk))
    return _der(0x06, out)


def _mk_cert(sig_oid, pub_bytes, sig_bytes, cn="pqc-demo.local"):
    """构造一张结构合法、签名算法为指定 OID 的证书（不校验签名，仅用于解析测试）。"""
    name = _der(0x30, _der(0x31, _der(0x30, _oid("2.5.4.3") + _der(0x0C, cn.encode()))))
    validity = _der(0x30, _der(0x17, b"260101000000Z") + _der(0x17, b"270101000000Z"))
    spki = _der(0x30, _der(0x30, _oid(sig_oid)) + _der(0x03, b"\x00" + b"\x11" * pub_bytes))
    tbs = _der(0x30, _der(0xA0, _der(0x02, b"\x02")) + _der(0x02, b"\x01")
               + _der(0x30, _oid(sig_oid)) + name + validity + name + spki)
    return _der(0x30, tbs + _der(0x30, _oid(sig_oid)) + _der(0x03, b"\x00" + b"\x22" * sig_bytes))


def check(label, ok, detail=""):
    print("%-46s %s %s" % (label, "PASS" if ok else "FAIL", detail))
    return ok


def main():
    failed = 0

    # ---- 传输层：三种 ServerHello ----
    r = probe_mock(0x11EC, 1120, 35101)          # X25519MLKEM768，1124 字节
    failed += not check("传输层：选中 X25519MLKEM768 判为抗量子",
                        r["ok"] and r["is_pqc"] and r["group_id"] == 0x11EC
                        and r["key_share_body"] == 1124 and r["size_ok"] is True,
                        "group=0x%04X body=%d" % (r["group_id"], r["key_share_body"]))

    r = probe_mock(0x11EC, 300, 35102)           # 长度与规范不符
    failed += not check("传输层：key_share 长度不符被判为不一致",
                        r["ok"] and r["size_ok"] is False,
                        "body=%d expect=%d" % (r["key_share_body"], r["expect_body"]))

    r = probe_mock(0x001D, 32, 35103)            # 经典组
    failed += not check("传输层：选中 X25519 判为非抗量子",
                        r["ok"] and not r["is_pqc"] and r["size_ok"] is True,
                        "group=0x%04X" % r["group_id"])

    # ---- key_share 客户端长度必须与规范一致 ----
    sizes_ok = all(len(pqc_detect._client_share_bytes(g)) == n
                   for g, n in pqc_detect.CLIENT_SHARE_SIZES.items())
    failed += not check("ClientHello：各抗量子组 key_share 长度符合规范", sizes_ok)

    # ---- 证书层：经典证书 ----
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "demo.local")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .sign(key, hashes.SHA256()))
    info = pqc_detect.analyze_cert_der(cert.public_bytes(serialization.Encoding.DER))
    failed += not check("证书层：RSA 证书判为经典算法",
                        info["sig_is_pqc"] is False and info["pub_is_pqc"] is False
                        and info["cert_is_pqc"] is False and info["pub_bits"] == 2048,
                        "sig=%s pub=%s" % (info["sig_algorithm"], info["pub_algorithm"]))

    # ---- 证书层：ML-DSA-65（FIPS 204）----
    info = pqc_detect.analyze_cert_der(_mk_cert("2.16.840.1.101.3.4.3.18", 1952, 3309))
    failed += not check("证书层：ML-DSA-65 证书判为抗量子且长度一致",
                        info["cert_is_pqc"] and info["sig_size_ok"] and info["pub_size_ok"],
                        "sig=%d/%s pub=%d/%s" % (info["sig_bytes"], info["sig_size_ok"],
                                                 info["pub_bytes"], info["pub_size_ok"]))

    # ---- 证书层：伪造场景 ----
    info = pqc_detect.analyze_cert_der(_mk_cert("2.16.840.1.101.3.4.3.18", 256, 3309))
    failed += not check("证书层：OID 标称 ML-DSA-65 但公钥长度不符",
                        info["pub_size_ok"] is False and "不一致" in info["cert_evidence"],
                        "pub=%d expect=%d" % (info["pub_bytes"], info.get("pub_expect_bytes", 0)))

    # ---- 本地静态文件检测：证书 / 公钥 / 原始块 ----
    tmpdir = tempfile.mkdtemp(prefix="pqc_static_test_")
    cert_bytes = _mk_cert("2.16.840.1.101.3.4.3.18", 1952, 3309)
    cert_pem = (b"-----BEGIN CERTIFICATE-----\n" + base64.encodebytes(cert_bytes)
                + b"-----END CERTIFICATE-----\n")
    cert_path = os.path.join(tmpdir, "mldsa65.pem")
    with open(cert_path, "wb") as f:
        f.write(cert_pem)
    fi = pqc_detect.analyze_file(cert_path)
    failed += not check("静态文件：PEM 证书判为 ML-DSA-65 且长度一致",
                        fi.get("kind") == "certificate" and fi.get("is_pqc")
                        and fi.get("sig_size_ok") and fi.get("pub_size_ok"),
                        "%s / %s" % (fi.get("sig_algorithm"), fi.get("pub_algorithm")))

    spki = _der(0x30, _der(0x30, _oid("2.16.840.1.101.3.4.4.2"))
                + _der(0x03, b"\x00" + b"\x41" * 1184))
    pk_path = os.path.join(tmpdir, "mlkem768_spki.der")
    with open(pk_path, "wb") as f:
        f.write(spki)
    fi = pqc_detect.analyze_file(pk_path)
    failed += not check("静态文件：DER 公钥判为 ML-KEM-768 且长度一致",
                        fi.get("kind") == "public-key" and fi.get("is_pqc")
                        and fi.get("pub_size_ok") and fi.get("nist_level") == 3,
                        fi.get("pub_algorithm"))

    blob_path = os.path.join(tmpdir, "blob_1952.bin")
    with open(blob_path, "wb") as f:
        f.write(b"\x55" * 1952)
    fi = pqc_detect.analyze_file(blob_path)
    failed += not check("静态文件：原始块按长度命中 ML-DSA-65 候选",
                        fi.get("kind") == "raw-blob" and fi.get("is_pqc")
                        and any("ML-DSA-65" in c for c in fi.get("candidates", [])),
                        str(fi.get("candidates", []))[:60])

    # ---- 结论整理与 JSON ----
    report = {"host": "example.com", "port": 443, "started_at": "now", "error": "",
              "transport": probe_mock(0x11EC, 1120, 35104), "cert": info,
              "overall": "部分抗量子", "overall_state": "partial"}
    rows = pqc_detect.report_rows(report)
    js = pqc_detect.report_to_json(report)
    failed += not check("报告整理：表格行与 JSON 结构完整",
                        "综合结论" in rows and js["transport"]["group_name"]
                        and "cert" in js and "rows" in js)

    # ---- 深度验证：握手无法完成时应安全返回，不抛异常 ----
    ready = threading.Event()
    threading.Thread(target=mock_server, args=(35105, 0x11EC, 1120, ready),
                     daemon=True).start()
    ready.wait(3)
    d = pqc_detect.deep_verify("127.0.0.1", 35105, timeout=4)
    failed += not check("深度验证：握手未完成时安全返回（verified=False）",
                        d["ok"] is False and d["verified"] is False and bool(d["error"]),
                        (d["error"] or "")[:46])

    print()
    print("结果：%s" % ("全部通过" if not failed else "%d 项失败" % failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
