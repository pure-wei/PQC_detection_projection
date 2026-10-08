"""Use standard wire formats to check the imported IPsec parser and GUI path."""
import os
import struct
import ipaddress

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication
from scapy.all import IP, IPv6, TCP, UDP, Raw, wrpcap

from main import PcapTab
from modules import ipsec_parser as ip, packet_parser, pcap_analysis, handshake_view, pqc_detect
from test_ipsec_parser import build_ikev2_sa_init, build_ikev2_sa_init_resp, build_esp, _ike_header, _payload, _transform, _proposal


@pytest.mark.parametrize("declared,notice", [(28, "截断"), (100, "截断"), (27, "无效")])
def test_ike_declared_length_bounds_payloads(declared, notice):
    nonce = _payload(40, b"\x44" * 16)
    message = _ike_header(b"\x01" * 8, b"\x00" * 8, 40, 34, 0x08, 0, nonce)
    message = message[:24] + struct.pack(">I", declared) + message[28:]
    parsed = ip.parse_ike(message)
    assert notice in parsed["说明"]
    assert notice in ip.ike_summary(message)
    if declared < len(message):
        assert "Nonce" not in parsed
        assert "Ni" not in ip.ike_summary(message)


@pytest.mark.parametrize("body,notice", [(b"\x00\x00", "截断"), (struct.pack(">BBH", 0, 0, 3), "无效"), (struct.pack(">BBH", 0, 0, 20), "截断")])
def test_ike_malformed_payload_chain_is_reported(body, notice):
    message = _ike_header(b"\x01" * 8, b"\x00" * 8, 40, 34, 0x08, 0, body)
    parsed = ip.parse_ike(message)
    assert notice in parsed["说明"]
    assert "Nonce" not in parsed
    assert notice in ip.ike_summary(message)


@pytest.mark.parametrize("notify,label", [(1, "INVALID_PAYLOAD_TYPE"), (24, "AUTHENTICATION_FAILED")])
def test_ikev1_notify_has_doi_prefix_and_own_type_registry(notify, label):
    body = struct.pack(">IBBH", 1, 1, 0, notify)
    message = bytearray(_ike_header(b"\x01" * 8, b"\xaa" * 8, 11, 5, 0, 1, _payload(11, body)))
    message[17] = 0x10
    text = ip.parse_ike(bytes(message))["通知 Notify"]
    assert label in text
    assert "协议 IKE" in text and "DOI=1" in text
    assert "类型 %d" % notify in text


def test_encrypted_ikev1_summary_does_not_parse_ciphertext():
    message = bytearray(_ike_header(b"\x01" * 8, b"\xaa" * 8, 10, 5, 1, 1, _payload(10, b"\x44" * 16)))
    message[17] = 0x10
    assert "Nonce" not in ip.ike_summary(bytes(message))
    assert "加密" in ip.ike_summary(bytes(message))


@pytest.mark.parametrize("identity,address", [(1, "192.0.2.10"), (5, "2001:db8::10")])
def test_binary_ip_identity_is_displayed_as_an_address(identity, address):
    body = bytes([identity, 0, 0, 0]) + ipaddress.ip_address(address).packed
    message = _ike_header(b"\x01" * 8, b"\xaa" * 8, 35, 35, 0x08, 1, _payload(35, body))
    assert address in ip.parse_ike(message)["身份 ID"]


@pytest.mark.parametrize("kind,identifier,label", [
    (1, 18, "AES-GCM-8"), (1, 19, "AES-GCM-12"), (1, 20, "AES-GCM-16"),
    (1, 23, "CAMELLIA-CBC"), (1, 24, "CAMELLIA-CTR"), (1, 27, "CAMELLIA-CCM-16"),
    (3, 6, "HMAC-MD5-128"), (3, 7, "HMAC-SHA1-160"), (3, 8, "AES-CMAC-96"),
    (3, 9, "AES-128-GMAC"), (3, 10, "AES-192-GMAC"), (3, 11, "AES-256-GMAC"),
    (3, 12, "HMAC-SHA2-256-128"), (3, 13, "HMAC-SHA2-384-192"), (3, 14, "HMAC-SHA2-512-256"),
])
def test_sa_algorithm_ids_match_iana_registry(kind, identifier, label):
    proposal = _proposal(1, 3, b"\x01" * 4, [_transform(kind, identifier, last=True)], last=True)
    message = _ike_header(b"\x01" * 8, b"\xaa" * 8, 33, 36, 0x08, 1, _payload(33, proposal))
    assert label in ip.parse_ike(message)["SA 提议与变换"]


def test_encrypted_ike_payload_does_not_parse_inner_next_payload():
    encrypted = _payload(46, b"\x44" * 32, next_type=35)
    apparent_id = _payload(35, b"\x02\x00\x00\x00forged.example")
    message = _ike_header(b"\x01" * 8, b"\xaa" * 8, 46, 35, 0x08, 1, encrypted + apparent_id)
    parsed = ip.parse_ike(message)
    assert "SK(" in parsed["载荷链"]
    assert "身份 ID" not in parsed
    assert "加密" in parsed["说明"]


@pytest.mark.parametrize("network", [IP, IPv6])
def test_natt_ike_and_esp_have_distinct_headers(network):
    ike = network() / UDP(sport=4500, dport=4500) / Raw(b"\x00" * 4 + build_ikev2_sa_init())
    esp = network() / UDP(sport=4500, dport=4500) / Raw(build_esp(9))
    assert ip.proto_of(ike) == "IKE-NAT-T"
    assert ip.proto_of(esp) == "ESP-NAT-T"
    assert "IKE_SA_INIT" in ip.packet_info(ike, ip.proto_of(ike))[1]
    tree = ip.tree_section(esp)
    assert tree["安全参数索引 SPI"] == "0x0A0B0C0D"
    assert tree["序列号"] == 9


@pytest.mark.parametrize("payload", [b"", b"\xff", b"\x00", b"\x00" * 3])
def test_short_natt_and_keepalive_are_not_ike_handshakes(payload):
    pkt = IP() / UDP(sport=4500, dport=4500) / Raw(payload)
    assert ip.proto_of(pkt) is None
    assert ip.ike_flow_key(pkt) is None


def test_real_sa_chain_and_key_length_attribute():
    fields = ip.parse_ike(build_ikev2_sa_init())
    text = fields["SA 提议与变换"]
    assert "提议 #1" in text and "提议 #2" in text
    assert "AES-CBC" in text and "AES-GCM-16" in text
    assert "HMAC-SHA2-256-128" in text and "Curve25519" in text
    assert "密钥长度 256 位" in text


def test_ike_initiator_is_independent_of_endpoint_sort_order():
    request = IP(src="198.51.100.20", dst="192.0.2.10") / UDP(sport=500, dport=500) / Raw(build_ikev2_sa_init())
    response = IP(src="192.0.2.10", dst="198.51.100.20") / UDP(sport=500, dport=500) / Raw(build_ikev2_sa_init_resp())
    flow = next(iter(ip.ike_flows([response, request]).values()))
    assert flow["client"] == "198.51.100.20:500"
    assert flow["server"] == "192.0.2.10:500"
    events = handshake_view.messages_to_events(flow["messages"], flow["cdir"])
    assert [event["dir"] for event in events] == ["s->c", "c->s"]


def test_tcp_and_ike_streams_with_same_endpoints_do_not_collide():
    hello = pqc_detect.build_client_hello("example.test", groups=[0x001D])
    tcp = IP(src="192.0.2.10", dst="198.51.100.20") / TCP(sport=500, dport=500, flags="PA", seq=1) / Raw(hello)
    udp = IP(src="192.0.2.10", dst="198.51.100.20") / UDP(sport=500, dport=500) / Raw(build_ikev2_sa_init())
    flows = packet_parser.analyze_streams([tcp, udp])
    assert {flow["proto"] for flow in flows.values()} == {"TLS", "IKE"}
    assert packet_parser.flow_key_of(tcp) != packet_parser.flow_key_of(udp)
    assert packet_parser.flow_key_of(udp) in flows


def test_ike_gui_sequence_survives_an_existing_completed_tls_flow(tmp_path):
    app = QApplication.instance() or QApplication([])
    packet = IP(src="192.0.2.10", dst="198.51.100.20") / UDP(sport=500, dport=500) / Raw(build_ikev2_sa_init())
    path = tmp_path / "ike.pcap"
    wrpcap(str(path), [packet])
    assert pcap_analysis.analyze_pcap(str(path))["rows"][0][4] == "IKE"
    assert "IPSec" in packet_parser.build_packet_tree(packet)
    tab = PcapTab()
    try:
        tab.analyze_file(str(path))
        assert tab.flow_combo.count() == 1
        assert "IKE" in tab.flow_combo.itemText(0)
        assert "IKE_SA_INIT" in str(tab.handshake_view._events)
        index = tab.cmb_proto.findText("IKE")
        assert index >= 0
        tab.cmb_proto.setCurrentIndex(index)
        assert tab.table.rowCount() == 1
        tab._streams[("192.0.2.1", 51000, "192.0.2.2", 443)] = {
            "proto": "TLS", "client": "192.0.2.1:51000", "server": "192.0.2.2:443",
            "messages": [{"dir": "A->B", "type": "ClientHello", "fields": {"SNI": "example.test"}, "no": 2},
                         {"dir": "B->A", "type": "Finished", "fields": {"verify_data": "ab"}, "no": 3}],
        }
        tab._populate_flow_combo()
        assert {item["proto"] for item in tab._sets_of()} == {"TLS", "IKE"}
        tls_key = ("192.0.2.1", 51000, "192.0.2.2", 443)
        tab._streams[tls_key]["messages"] = tab._streams[tls_key]["messages"][:1]
        tab._populate_flow_combo()
        assert {item["proto"] for item in tab._sets_of()} == {"TLS", "IKE"}
    finally:
        tab.close()


def test_active_retest_labels_same_connection_certificate():
    text = PcapTab._active_report_text({
        "certificate_same_connection": True, "overall": "双层验证通过",
        "transport": {"verified": True}, "cert": {"sig_algorithm": "ML-DSA-65", "pub_algorithm": "ML-DSA-65"},
    })
    assert "同一次主动握手" in text
    assert "再次连接获取" not in text
