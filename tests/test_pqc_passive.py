"""Passive TLS evidence must stay tied to the captured connection."""

from scapy.all import IP, TCP, Raw

from modules import packet_parser
from modules import pqc_passive, tls_parser


def _server_hello(group, share):
    key_share = group.to_bytes(2, "big") + len(share).to_bytes(2, "big") + share
    extensions = (b"\x00\x2b\x00\x02\x03\x04" +
                  b"\x00\x33" + len(key_share).to_bytes(2, "big") + key_share)
    return (b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x13\x01" +
            b"\x00" + len(extensions).to_bytes(2, "big") + extensions)


def _flow(server_fields):
    return {
        "proto": "TLS", "client": "10.0.0.2:52000", "server": "198.51.100.10:443",
        "messages": [
            {"type": "ClientHello", "fields": {"SNI": "example.test",
                                                   "ext_application_layer_protocol_negotiation (ALPN)": "h2"}},
            {"type": "ServerHello", "fields": server_fields},
        ],
    }


def test_observed_hybrid_group_is_evidence_but_certificate_remains_unknown():
    sh = tls_parser.parse_server_hello(_server_hello(0x11EC, b"\x01" * 1120))
    result = pqc_passive.assess_tls_flow(_flow(sh))

    assert sh["selected_group_id"] == 0x11EC
    assert result["state"] == "pqc_observed"
    assert result["target_host"] == "example.test"
    assert result["target_port"] == 443
    assert "X25519MLKEM768" in result["transport"]
    assert "1120" in result["transport"]
    assert "无法观察" in result["certificate"]


def test_classical_group_only_describes_captured_connection():
    sh = tls_parser.parse_server_hello(_server_hello(0x001D, b"\x01" * 32))
    result = pqc_passive.assess_tls_flow(_flow(sh))

    assert result["state"] == "classic_observed"
    assert "本次连接" in result["transport"]
    assert "不支持" not in result["transport"]


def test_wrong_share_length_is_unknown_evidence():
    sh = tls_parser.parse_server_hello(_server_hello(0x11EC, b"\x01" * 32))
    result = pqc_passive.assess_tls_flow(_flow(sh))

    assert result["state"] == "unknown"
    assert "长度不符" in result["transport"]


def test_unrecognized_group_does_not_become_classical():
    sh = tls_parser.parse_server_hello(_server_hello(0xAAAA, b"\x01" * 32))
    result = pqc_passive.assess_tls_flow(_flow(sh))
    assert result["state"] == "unknown"
    assert "未知组" in result["transport"]


def test_missing_server_hello_never_becomes_classical_verdict():
    flow = _flow({})
    flow["messages"] = flow["messages"][:1]
    result = pqc_passive.assess_tls_flow(flow)

    assert result["state"] == "unknown"
    assert "无法判断" in result["transport"]


def test_visible_older_certificate_is_described_without_claiming_trust():
    flow = _flow({"legacy_version": "TLS 1.2"})
    flow["messages"].append({"type": "Certificate", "fields": {
        "cert_chain_count": 1,
        "cert1_sig_algorithm": "sha256WithRSAEncryption",
        "cert1_pubkey": "RSA 公钥",
    }})
    result = pqc_passive.assess_tls_flow(flow)

    assert "1 张" in result["certificate"]
    assert "RSA" in result["certificate"]
    assert "未验证" in result["certificate"]


def test_reassembled_pcap_flow_reaches_passive_assessment():
    hostname = b"example.test"
    sni = (b"\x00" + len(hostname).to_bytes(2, "big") + hostname)
    sni = len(sni).to_bytes(2, "big") + sni
    extension = b"\x00\x00" + len(sni).to_bytes(2, "big") + sni
    ch_body = (b"\x03\x03" + b"\x01" * 32 + b"\x00" +
               b"\x00\x02\x13\x01" + b"\x01\x00" +
               len(extension).to_bytes(2, "big") + extension)

    def record(kind, body):
        message = bytes([kind]) + len(body).to_bytes(3, "big") + body
        return b"\x16\x03\x03" + len(message).to_bytes(2, "big") + message

    packets = [
        IP(src="10.0.0.2", dst="198.51.100.10") /
        TCP(sport=52000, dport=443, seq=100) / Raw(load=record(1, ch_body)),
        IP(src="198.51.100.10", dst="10.0.0.2") /
        TCP(sport=443, dport=52000, seq=200) /
        Raw(load=record(2, _server_hello(0x11EC, b"\x01" * 1120))),
    ]
    flows = packet_parser.analyze_streams(packets)
    assert len(flows) == 1
    result = pqc_passive.assess_tls_flow(next(iter(flows.values())))
    assert result["target_host"] == "example.test"
    assert result["state"] == "pqc_observed"


def test_handshake_split_across_tls_records_keeps_client_hello():
    body = (b"\x03\x03" + b"\x01" * 32 + b"\x00" +
            b"\x00\x02\x13\x01" + b"\x01\x00")
    message = b"\x01" + len(body).to_bytes(3, "big") + body
    record = lambda part: b"\x16\x03\x03" + len(part).to_bytes(2, "big") + part
    messages = tls_parser._parse_record_stream(record(message[:10]) + record(message[10:]),
                                               "A->B", 100, "TLS")
    assert [message["type"] for message in messages] == ["ClientHello"]
    assert messages[0]["offset"] == 105


def test_key_share_outside_declared_extensions_is_unknown():
    body = _server_hello(0x11EC, b"\x01" * 1120)
    extension_length_offset = 2 + 32 + 1 + 2 + 1
    malformed = (body[:extension_length_offset] + b"\x00\x04" +
                 body[extension_length_offset + 2:])
    parsed = tls_parser.parse_server_hello(malformed)
    result = pqc_passive.assess_tls_flow(_flow(parsed))
    assert parsed.get("extensions_valid") is False
    assert result["state"] == "unknown"


def test_truncated_client_hello_does_not_erase_other_flows():
    def record(kind, body):
        message = bytes([kind]) + len(body).to_bytes(3, "big") + body
        return b"\x16\x03\x03" + len(message).to_bytes(2, "big") + message

    packets = [
        IP(src="10.0.0.2", dst="198.51.100.10") /
        TCP(sport=52000, dport=443, seq=100) / Raw(load=record(1, b"\x03\x03" + b"\x00" * 32)),
        IP(src="10.0.0.3", dst="198.51.100.11") /
        TCP(sport=52001, dport=443, seq=100) /
        Raw(load=record(2, _server_hello(0x11EC, b"\x01" * 1120))),
    ]
    flows = packet_parser.analyze_streams(packets)
    assert len(flows) == 2


def test_syn_direction_is_used_when_client_hello_missing():
    body = _server_hello(0x11EC, b"\x01" * 1120)
    message = b"\x02" + len(body).to_bytes(3, "big") + body
    packets = [
        IP(src="10.0.0.2", dst="198.51.100.10") /
        TCP(sport=52000, dport=443, flags="S", seq=100),
        IP(src="198.51.100.10", dst="10.0.0.2") /
        TCP(sport=443, dport=52000, seq=200) /
        Raw(load=b"\x16\x03\x03" + len(message).to_bytes(2, "big") + message),
    ]
    flows = packet_parser.analyze_streams(packets)
    result = pqc_passive.assess_tls_flow(next(iter(flows.values())))
    assert result["target_host"] == "198.51.100.10"
    assert result["target_port"] == 443


def test_unknown_direction_disables_active_target():
    body = _server_hello(0x11EC, b"\x01" * 1120)
    message = b"\x02" + len(body).to_bytes(3, "big") + body
    packet = (IP(src="198.51.100.10", dst="10.0.0.2") /
              TCP(sport=443, dport=52000, flags="PA", seq=200) /
              Raw(load=b"\x16\x03\x03" + len(message).to_bytes(2, "big") + message))
    flow = next(iter(packet_parser.analyze_streams([packet]).values()))
    assert flow["direction_confident"] is False
    assert pqc_passive.assess_tls_flow(flow)["target_host"] == ""
