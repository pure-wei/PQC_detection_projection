# -*- coding: utf-8 -*-
"""Conservative post-quantum evidence from one captured TLS flow."""

from modules import pqc_detect


def assess_tls_flow(flow: dict) -> dict:
    """Return observations only; never infer server capability from one flow."""
    messages = flow.get("messages") or []
    client_hello = next((m.get("fields") or {} for m in messages
                         if m.get("type") == "ClientHello"), {})
    server_hello = next((m.get("fields") or {} for m in messages
                         if m.get("type") == "ServerHello" and
                         not (m.get("fields") or {}).get("hello_retry_request")), {})
    cert = next((m.get("fields") or {} for m in messages
                 if m.get("type") == "Certificate"), {})
    server = flow.get("server") or ""
    server_host, sep, server_port = server.rpartition(":")
    try:
        port = int(server_port) if sep else 443
    except ValueError:
        port = 443
    host = (client_hello.get("SNI") or (server_host if sep else server)).strip()
    if flow.get("direction_confident") is False:
        host = ""

    state = "unknown"
    group_id = server_hello.get("selected_group_id")
    group_name = ""
    if not server_hello:
        transport = "无法判断：抓包未取得正式 ServerHello。"
    elif server_hello.get("extensions_valid") is False:
        transport = "无法判断：ServerHello 扩展长度无效。"
    elif group_id is None:
        transport = "无法判断：ServerHello 未提供可解析的 key_share。"
    else:
        group_name, is_pqc = pqc_detect.lookup_group(group_id)
        actual = server_hello.get("key_share_bytes", 0)
        expected = pqc_detect.KEY_SHARE_BODY_SIZES.get(group_id)
        if (group_id not in pqc_detect.PQC_GROUP_IDS and
                group_id not in pqc_detect.CLASSICAL_GROUP_IDS):
            transport = "无法判断：ServerHello 使用未知组 0x%04X。" % group_id
        elif server_hello.get("key_share_length_valid") is False or (
                expected is not None and actual + 4 != expected):
            transport = "无法判断：%s (0x%04X) 的 key_share 长度不符。" % (
                group_name, group_id)
        else:
            state = "pqc_observed" if is_pqc else "classic_observed"
            transport = ("本次连接观察到 %s (0x%04X)，服务器 key_share %d 字节；"
                         "仅为抓包证据，未完成密码学校验。" %
                         (group_name, group_id, actual))

    if cert:
        public_key = (cert.get("cert1_pubkey") or
                      cert.get("cert1_pubkey_algorithm") or "未知")
        certificate = ("抓包可见 %s 张证书；首张签名 %s，公钥 %s。"
                       "算法字段可观察，证书链信任与握手签名未验证。" % (
                           cert.get("cert_chain_count", "?"),
                           cert.get("cert1_sig_algorithm") or "未知",
                           str(public_key)[:120]))
    elif "TLS 1.3" in str(server_hello.get("ext_supported_versions", "")):
        certificate = ("TLS 1.3 证书层无法观察：如本次握手发送 Certificate，"
                       "它位于加密部分；当前抓包分析未导入会话密钥。")
    else:
        certificate = "证书层无法判断：抓包没有可解析的 Certificate。"

    return {
        "state": state, "transport": transport, "certificate": certificate,
        "target_host": host, "target_port": port,
        "group_id": group_id, "group_name": group_name,
        "sni": client_hello.get("SNI") or "",
        "alpn": client_hello.get("ext_application_layer_protocol_negotiation (ALPN)") or "",
    }
