# -*- coding: utf-8 -*-
"""IPSec parsing self-test.

Builds IKEv2 SA_INIT / IKE_AUTH, IKEv1, ESP, AH and NAT-T packets with scapy,
writes them to a temporary pcap and asserts the parsing results.

    python tests/test_ipsec_parser.py
"""
import os
import struct
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.all import Ether, IP, UDP, Raw, wrpcap, rdpcap    # noqa: E402

from modules import ipsec_parser as ip                     # noqa: E402
from modules import pcap_analysis, packet_parser            # noqa: E402

C_IP, S_IP = "192.0.2.10", "198.51.100.20"


def _tlv_attr(atype, value):
    return struct.pack(">HH", atype, len(value)) + value


def _transform(ttype, tid, attrs=b"", last=False):
    return struct.pack(">BBHBBH", 0 if last else 3, 0, 8 + len(attrs), ttype, 0, tid) + attrs


def _proposal(num, proto_id, spi, transforms, last=False):
    hdr = struct.pack(">BBHBBBB", 0 if last else 2, 0, 0, num, proto_id,
                      len(spi), len(transforms))
    body = hdr + spi + b"".join(transforms)
    return body[:2] + struct.pack(">H", len(body)) + body[4:]


def _payload(payload_type, body, next_type=0, critical=False):
    return struct.pack(">BBH", next_type, 0x80 if critical else 0, 4 + len(body)) + body


def _ike_header(i_spi, r_spi, nxt, exch, flags, msg_id, payload):
    total = 28 + len(payload)
    return (i_spi + r_spi + struct.pack(">BBBBII", nxt, 0x20, exch, flags, msg_id, total)
            + payload)


def _ike_header_v1(i_spi, r_spi, nxt, exch, flags, msg_id, payload):
    total = 28 + len(payload)
    return (i_spi + r_spi + struct.pack(">BBBBII", nxt, 0x10, exch, flags, msg_id, total)
            + payload)


def build_ikev2_sa_init():
    t_ike = [
        _transform(1, 12, struct.pack(">HH", 0x800E, 256)),
        _transform(2, 5),
        _transform(3, 12),
        _transform(4, 31, last=True),
    ]
    t_esp = [
        _transform(1, 20, struct.pack(">HH", 0x800E, 256)),
        _transform(4, 31, last=True),
    ]
    prop_ike = _proposal(1, 1, b"", t_ike)
    prop_esp = _proposal(2, 3, b"\x0a\x0b\x0c\x0d", t_esp, last=True)
    sa = _payload(33, prop_ike + prop_esp, next_type=34)
    ke = _payload(34, struct.pack(">HH", 31, 0) + b"\x11" * 32, next_type=40)
    ni = _payload(40, b"\x22" * 16)
    return _ike_header(b"\x01" * 8, b"\x00" * 8, 33, 34, 0x08, 0, sa + ke + ni)


def build_ikev2_sa_init_resp():
    t_ike = [
        _transform(1, 12, struct.pack(">HH", 0x800E, 256)),
        _transform(2, 5),
        _transform(3, 12),
        _transform(4, 31, last=True),
    ]
    prop = _proposal(1, 1, b"", t_ike, last=True)
    sa = _payload(33, prop, next_type=34)
    ke = _payload(34, struct.pack(">HH", 31, 0) + b"\x77" * 32, next_type=40)
    ni = _payload(40, b"\x88" * 16)
    return _ike_header(b"\x01" * 8, b"\xaa" * 8, 33, 34, 0x20, 0, sa + ke + ni)


def build_ikev2_auth():
    idi = _payload(35, struct.pack(">BBBB", 2, 0, 0, 0) + b"client.example.com", next_type=39)
    auth = _payload(39, struct.pack(">BBBB", 2, 0, 0, 0) + b"\x33" * 32, next_type=46)
    sk = _payload(46, b"\x44" * 40)
    return _ike_header(b"\x01" * 8, b"\xaa" * 8, 35, 35, 0x08, 1, idi + auth + sk)


def build_ikev1():
    attrs = b"".join(struct.pack(">HH", 0x8000 | kind, value)
                     for kind, value in ((1, 7), (2, 2), (3, 1), (4, 2)))
    transform = struct.pack(">BBHBBH", 0, 0, 8 + len(attrs), 1, 1, 0) + attrs
    prop = _proposal(1, 1, b"", [transform], last=True)
    sa = _payload(1, struct.pack(">II", 1, 1) + prop)
    return _ike_header_v1(b"\x02" * 8, b"\x00" * 8, 1, 2, 0x08, 0, sa)


def build_esp(seq=1):
    return struct.pack(">II", 0x0A0B0C0D, seq) + b"\x55" * 48


def build_ah(seq=7):
    icv = b"\x66" * 12
    payload_len = (12 + len(icv)) // 4 - 2
    return (struct.pack(">BBH", 6, payload_len, 0)
            + struct.pack(">II", 0x0A0B0C0D, seq) + icv)


def build_pcap(path):
    base = 1700000000.0
    pkts = []

    def add(pkt, dt):
        pkt.time = base + dt
        pkts.append(pkt)

    add(Ether() / IP(src=C_IP, dst=S_IP) / UDP(sport=500, dport=500)
        / Raw(build_ikev2_sa_init()), 0.0)
    add(Ether() / IP(src=S_IP, dst=C_IP) / UDP(sport=500, dport=500)
        / Raw(build_ikev2_sa_init_resp()), 0.01)
    add(Ether() / IP(src=C_IP, dst=S_IP) / UDP(sport=500, dport=500)
        / Raw(build_ikev2_auth()), 0.02)
    add(Ether() / IP(src=C_IP, dst=S_IP, proto=50) / Raw(build_esp(1)), 0.03)
    add(Ether() / IP(src=S_IP, dst=C_IP, proto=50) / Raw(build_esp(2)), 0.04)
    add(Ether() / IP(src=C_IP, dst=S_IP, proto=51) / Raw(build_ah()), 0.05)
    add(Ether() / IP(src=C_IP, dst=S_IP) / UDP(sport=4500, dport=4500)
        / Raw(b"\x00\x00\x00\x00" + build_ikev2_auth()), 0.06)
    add(Ether() / IP(src=S_IP, dst=C_IP) / UDP(sport=4500, dport=4500)
        / Raw(build_esp(3)), 0.07)
    add(Ether() / IP(src=C_IP, dst=S_IP) / UDP(sport=500, dport=500)
        / Raw(build_ikev1()), 0.08)
    wrpcap(path, pkts)
    return path


FAILED = 0


def check(label, ok, detail=""):
    global FAILED
    print("%-50s %s %s" % (label, "PASS" if ok else "FAIL", detail))
    if not ok:
        FAILED += 1


def main():
    tmp = tempfile.mkdtemp(prefix="ipsec_test_")
    path = os.path.join(tmp, "ipsec.pcap")
    build_pcap(path)
    pkts = rdpcap(path)

    kinds = [ip.proto_of(p) for p in pkts]
    check("protocol detection (IKE/ESP/AH/NAT-T)",
          kinds == ["IKE", "IKE", "IKE", "ESP", "ESP", "AH", "IKE-NAT-T",
                    "ESP-NAT-T", "IKE"], str(kinds))

    esp = ip.parse_esp(pkts[3])
    check("ESP: SPI / seq / payload length",
          esp["安全参数索引 SPI"] == "0x0A0B0C0D" and esp["序列号"] == 1
          and esp["加密载荷长度"] == "48 字节", esp["安全参数索引 SPI"])

    ah = ip.parse_ah(pkts[5])
    check("AH: next header / SPI / seq / ICV length",
          ah["下一个头"].startswith("6") and ah["序列号"] == 7
          and ah["ICV 长度"] == "12 字节", ah["ICV 长度"])

    d = ip.parse_ike(bytes(pkts[0][UDP].payload))
    sa_txt = d.get("SA 提议与变换", "")
    check("IKEv2: version / exchange / SPI",
          d["IKE 版本"] == "IKEv2 (2.0)" and "IKE_SA_INIT" in d["交换类型"]
          and d["发起者 SPI"] == "01" * 8, d["交换类型"])
    check("IKEv2: payload chain",
          d["载荷链"].startswith("SA(") and "KE(" in d["载荷链"]
          and "Ni(" in d["载荷链"], d["载荷链"])
    check("IKEv2: two proposals with transforms parsed",
          "提议 #1" in sa_txt and "提议 #2" in sa_txt and "AES-CBC" in sa_txt
          and "HMAC-SHA2-256-128" in sa_txt and "Curve25519" in sa_txt,
          sa_txt.splitlines()[0] if sa_txt else "(empty)")
    check("IKEv2: ESP proposal shows AES-GCM-16 and SPI",
          "AES-GCM-16" in sa_txt and "0a0b0c0d" in sa_txt)
    check("IKEv2: KE payload group + key length",
          "Curve25519" in (d.get("密钥交换 KE") or "")
          and "32 字节" in (d.get("密钥交换 KE") or ""), d.get("密钥交换 KE", ""))
    check("IKEv2: nonce length", "16 字节" in (d.get("Nonce") or ""), d.get("Nonce", ""))

    d2 = ip.parse_ike(bytes(pkts[2][UDP].payload))
    check("IKEv2: IKE_AUTH shows IDi / AUTH / SK note",
          "client.example.com" in (d2.get("身份 ID") or "")
          and "预共享密钥" in (d2.get("认证 AUTH") or "")
          and "SK" in (d2.get("说明") or ""), (d2.get("身份 ID") or "").strip())

    d1 = ip.parse_ike(bytes(pkts[8][UDP].payload))
    check("IKEv1: version / exchange / transforms",
          "IKEv1" in d1["IKE 版本"] and "Identity Protection" in d1["交换类型"]
          and "AES" in (d1.get("SA 提议与变换") or "")
          and "SHA1" in (d1.get("SA 提议与变换") or ""), d1["交换类型"])

    info = ip.packet_info(pkts[0], "IKE")[1]
    check("list summary contains exchange and transforms",
          "IKE_SA_INIT" in info and "AES-CBC" in info and "Curve25519" in info,
          info[:80])

    tree = packet_parser.build_packet_tree(pkts[0])
    sec_key = next((k for k in tree if k.startswith("IPSec")), None)
    check("field tree contains IPSec section",
          sec_key is not None and "载荷链" in tree[sec_key]
          and "SA 提议与变换" in tree[sec_key], "、".join(tree.keys()))

    a = pcap_analysis.analyze_pcap(path)
    protos = [r[4] for r in a["rows"]]
    check("pcap analysis recognises ESP/AH/IKE",
          protos.count("ESP") == 2 and protos.count("AH") == 1
          and protos.count("IKE") >= 3, str(protos))

    flows = ip.ike_flows(pkts)
    sets_ = ip.ike_sets(flows)
    check("IKE flows merged per endpoint (500 and 4500)",
          len(flows) == 2, "flows=%d" % len(flows))
    check("IKE negotiation set generated",
          len(sets_) == 2 and "IPSec IKE 协商" in sets_[0]["label"],
          sets_[0]["label"] if sets_ else "")

    print()
    print("结果：%s" % ("全部通过" if not FAILED else "%d 项失败" % FAILED))
    return 1 if FAILED else 0


def test_ipsec_script_checks_capture_and_field_tree():
    global FAILED
    FAILED = 0
    assert main() == 0


if __name__ == "__main__":
    sys.exit(main())
