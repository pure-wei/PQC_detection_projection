# -*- coding: utf-8 -*-
"""IPSec 协议解析（ESP / AH / IKEv1 / IKEv2，含 NAT-T）。

覆盖范围：
  - **ESP**（IP 协议号 50）：SPI、序列号、载荷长度；载荷为加密数据，需 SA 密钥才能解密；
  - **AH**（IP 协议号 51）：下一个头、载荷长度、SPI、序列号、ICV 长度（按 RFC 4302 计算）；
  - **IKEv2**（UDP 500 / 4500）：头部字段、载荷链、SA 提议与变换
    （加密 / PRF / 完整性 / DH 组 / ESN / 附加密钥交换）、KE、Nonce、ID、AUTH、Notify；
  - **IKEv1**（UDP 500）：头部字段、载荷链、SA 提议与变换（常用变换 ID 给出名称）；
  - **NAT-T**：UDP 4500 上带 4 字节 Non-ESP 标记的 IKE，以及 ESP-in-UDP。

供主程序「协议分析 (pcap)」页使用：表格协议识别与概要、单包字段树、IKE 协商时序视图。
纯逻辑无 GUI 依赖，可独立复用。
"""
import struct
import ipaddress
from collections import OrderedDict

from scapy.all import IP, IPv6, UDP

# ---------------------------------------------------------------- 常量表
ESP_IP_PROTO = 50
AH_IP_PROTO = 51
IKE_PORTS = (500, 4500)

#: IKEv2 交换类型（RFC 7296 / RFC 9370）
IKEV2_EXCHANGE = {
    34: "IKE_SA_INIT", 35: "IKE_AUTH", 36: "CREATE_CHILD_SA", 37: "INFORMATIONAL",
    38: "IKE_SESSION_RESUME",
}

#: IKEv1 交换类型
IKEV1_EXCHANGE = {
    1: "Base", 2: "Identity Protection", 3: "Authentication Only", 4: "Aggressive",
    5: "Informational", 32: "Quick Mode", 36: "New Group Mode",
}

#: IKEv2 载荷类型
IKEV2_PAYLOAD = {
    0: "None", 33: "SA", 34: "KE", 35: "IDi", 36: "IDr", 37: "CERT", 38: "CERTREQ",
    39: "AUTH", 40: "Ni", 41: "N", 42: "D", 43: "V", 44: "TSi", 45: "TSr",
    46: "SK", 47: "CP", 48: "EAP", 49: "GSPM", 53: "SKF",
}

#: IKEv1 载荷类型
IKEV1_PAYLOAD = {
    0: "None", 1: "SA", 2: "Proposal", 3: "Transform", 4: "KE", 5: "ID", 6: "CERT",
    7: "CR", 8: "HASH", 9: "SIG", 10: "Nonce", 11: "N", 12: "D", 13: "VID",
}

#: 变换类型（IKEv2，RFC 7296 / RFC 9370）
TRANSFORM_TYPES = {
    1: "加密算法（Encryption）",
    2: "伪随机函数（PRF）",
    3: "完整性算法（Integrity）",
    4: "密钥交换组（DH Group）",
    5: "扩展序列号（ESN）",
    6: "附加密钥交换（RFC 9370，抗量子混合常用）",
}

#: 加密算法变换 ID（Transform Type 1）
IKE_ENCR = {
    1: "DES-IV64", 2: "DES-CBC", 3: "3DES-CBC", 4: "RC5-CBC", 5: "IDEA-CBC",
    6: "CAST-CBC", 7: "Blowfish-CBC", 8: "3IDEA-CBC", 9: "DES-IV32",
    11: "NULL", 12: "AES-CBC", 13: "AES-CTR", 14: "AES-CCM-8", 15: "AES-CCM-12",
    16: "AES-CCM-16", 18: "AES-GCM-8", 19: "AES-GCM-12", 20: "AES-GCM-16",
    21: "NULL+GMAC", 23: "CAMELLIA-CBC", 24: "CAMELLIA-CTR", 25: "CAMELLIA-CCM-8",
    26: "CAMELLIA-CCM-12", 27: "CAMELLIA-CCM-16", 28: "ChaCha20-Poly1305",
}

#: PRF 变换 ID（Transform Type 2）
IKE_PRF = {
    1: "HMAC-MD5", 2: "HMAC-SHA1", 3: "HMAC-Tiger", 4: "AES128-XCBC",
    5: "HMAC-SHA2-256", 6: "HMAC-SHA2-384", 7: "HMAC-SHA2-512", 8: "AES-CMAC",
}

#: 完整性算法变换 ID（Transform Type 3）
IKE_INTEG = {
    1: "HMAC-MD5-96", 2: "HMAC-SHA1-96", 3: "DES-MAC", 4: "KPDK-MD5",
    5: "AES-XCBC-96", 6: "HMAC-MD5-128", 7: "HMAC-SHA1-160", 8: "AES-CMAC-96",
    9: "AES-128-GMAC", 10: "AES-192-GMAC", 11: "AES-256-GMAC",
    12: "HMAC-SHA2-256-128", 13: "HMAC-SHA2-384-192", 14: "HMAC-SHA2-512-256",
}

#: 密钥交换组（Transform Type 4，DH Group）
IKE_DH = {
    1: "MODP-768", 2: "MODP-1024", 5: "MODP-1536", 14: "MODP-2048", 15: "MODP-3072",
    16: "MODP-4096", 17: "MODP-6144", 18: "MODP-8192", 19: "ECP-256", 20: "ECP-384",
    21: "ECP-521", 22: "MODP-1024-160", 23: "MODP-2048-224", 24: "MODP-2048-256",
    25: "ECP-192", 26: "ECP-224", 27: "BrainpoolP224r1", 28: "BrainpoolP256r1",
    29: "BrainpoolP384r1", 30: "BrainpoolP512r1", 31: "Curve25519", 32: "Curve448",
}

#: IKEv1 ISAKMP 变换属性（加密、哈希、认证、DH 组）。
IKEV1_TRANSFORM = {
    1: {1: "DES", 2: "IDEA", 3: "Blowfish", 4: "RC5", 5: "3DES", 6: "CAST", 7: "AES", 8: "Camellia"},
    2: {1: "MD5", 2: "SHA1", 3: "Tiger", 4: "SHA2-256", 5: "SHA2-384", 6: "SHA2-512"},
    3: {1: "预共享密钥", 2: "DSS 签名", 3: "RSA 签名", 4: "RSA 加密", 5: "修订版 RSA 加密"},
    4: {1: "MODP-768", 2: "MODP-1024", 3: "EC2N-155", 4: "EC2N-185", 5: "MODP-1536", 14: "MODP-2048"},
}

#: 协议 ID（IPSec 协议）
PROTO_ID = {0: "None", 1: "IKE", 2: "AH", 3: "ESP", 4: "IPComp"}

#: ID 类型（IKEv2）
ID_TYPES = {
    1: "ID_IPV4_ADDR", 2: "ID_FQDN", 3: "ID_RFC822_ADDR", 5: "ID_IPV6_ADDR",
    9: "ID_DER_ASN1_DN", 10: "ID_DER_ASN1_GN", 11: "ID_KEY_ID",
}

#: 认证方法（IKEv2）
AUTH_METHODS = {
    1: "RSA 数字签名", 2: "预共享密钥（PSK）", 3: "DSS 数字签名",
    9: "ECDSA(SHA256, P-256)", 10: "ECDSA(SHA384, P-384)", 11: "ECDSA(SHA512, P-521)",
    12: "通用安全密码认证", 13: "NULL 认证", 14: "数字签名（通用）",
}

#: Notify 类型（仅列常用项，其余按编号显示）
NOTIFY_TYPES = {
    1: "UNSUPPORTED_CRITICAL_PAYLOAD", 5: "INVALID_MAJOR_VERSION",
    17: "INVALID_KE_PAYLOAD", 24: "AUTHENTICATION_FAILED",
}

# IKEv1 通知与 IKEv2 的编号含义不同（RFC 2408 §3.14.1）。
IKEV1_NOTIFY_TYPES = {
    1: "INVALID_PAYLOAD_TYPE", 2: "DOI_NOT_SUPPORTED", 3: "SITUATION_NOT_SUPPORTED",
    4: "INVALID_COOKIE", 5: "INVALID_MAJOR_VERSION", 6: "INVALID_MINOR_VERSION",
    14: "NO_PROPOSAL_CHOSEN", 16: "PAYLOAD_MALFORMED", 17: "INVALID_KEY_INFORMATION",
    24: "AUTHENTICATION_FAILED", 25: "INVALID_SIGNATURE", 16384: "CONNECTED",
}


# ---------------------------------------------------------------- 工具
def _hex(b: bytes, limit: int = 32) -> str:
    h = b.hex()
    return h if len(h) <= limit * 2 else h[:limit * 2] + "…（共 %d 字节）" % len(b)


def _ip_of(pkt):
    if IP in pkt:
        return pkt[IP].src, pkt[IP].dst, pkt[IP].proto
    if IPv6 in pkt:
        return pkt[IPv6].src, pkt[IPv6].dst, pkt[IPv6].nh
    return None, None, None


def _udp_ports(pkt):
    if UDP in pkt:
        return int(pkt[UDP].sport), int(pkt[UDP].dport)
    return None, None


def _udp_payload(pkt) -> bytes:
    try:
        return bytes(pkt[UDP].payload)
    except Exception:
        return b""


def _ike_payload(pkt) -> bytes:
    payload = _udp_payload(pkt)
    return payload[4:] if 4500 in _udp_ports(pkt) and payload.startswith(b"\x00" * 4) else payload


def _esp_payload(pkt) -> bytes:
    if UDP in pkt and 4500 in _udp_ports(pkt):
        return _udp_payload(pkt)
    if IP in pkt:
        return bytes(pkt[IP].payload)
    if IPv6 in pkt:
        return bytes(pkt[IPv6].payload)
    return b""


def proto_of(pkt):
    """识别 IPSec 相关协议：ESP / AH / IKE / IKE-NAT-T / ESP-NAT-T，非 IPSec 返回 None。"""
    _src, _dst, ip_proto = _ip_of(pkt)
    if ip_proto == ESP_IP_PROTO:
        return "ESP"
    if ip_proto == AH_IP_PROTO:
        return "AH"
    sp, dp = _udp_ports(pkt)
    if sp in IKE_PORTS or dp in IKE_PORTS:
        payload = _udp_payload(pkt)
        if 4500 in (sp, dp):
            if len(payload) < 4:  # Includes the one-byte NAT keepalive.
                return None
            return "IKE-NAT-T" if payload[:4] == b"\x00" * 4 else "ESP-NAT-T"
        return "IKE"
    return None


# ---------------------------------------------------------------- ESP / AH
def parse_esp(pkt) -> OrderedDict:
    """ESP 头解析（RFC 4303）。载荷为加密数据，无 SA 密钥无法继续解析。"""
    d = OrderedDict()
    raw = _esp_payload(pkt)
    if len(raw) < 8:
        d["说明"] = "ESP 头部不足 8 字节（抓包被截断）"
        return d
    spi, seq = struct.unpack(">II", raw[:8])
    payload_len = max(0, len(raw) - 8)
    d["安全参数索引 SPI"] = "0x%08X" % spi
    d["序列号"] = seq
    d["加密载荷长度"] = "%d 字节" % payload_len
    d["说明"] = ("ESP 载荷已加密（含填充 / 填充长度 / 下一个头 / ICV），"
                 "需对应 SA 的密钥才能解密；本工具只解析到 ESP 头部")
    return d


def parse_ah(pkt) -> OrderedDict:
    """AH 头解析（RFC 4302）。ICV 长度按 Payload Len 字段推算。"""
    d = OrderedDict()
    raw = b""
    if IP in pkt:
        raw = bytes(pkt[IP].payload)
    elif IPv6 in pkt:
        raw = bytes(pkt[IPv6].payload)
    if len(raw) < 12:
        d["说明"] = "AH 头部不足 12 字节（抓包被截断）"
        return d
    next_hdr, payload_len = raw[0], raw[1]
    spi, seq = struct.unpack(">II", raw[4:12])
    hdr_len = (payload_len + 2) * 4              # AH 头总长（含 ICV）
    icv_len = max(0, hdr_len - 12)
    d["下一个头"] = "%d%s" % (next_hdr, "（%s）" % PROTO_ID.get(next_hdr, "") if next_hdr in PROTO_ID else "")
    d["头长度"] = "%d 字节（Payload Len=%d）" % (hdr_len, payload_len)
    d["安全参数索引 SPI"] = "0x%08X" % spi
    d["序列号"] = seq
    d["ICV 长度"] = "%d 字节" % icv_len
    d["ICV 值"] = _hex(raw[12:12 + icv_len], 32) if icv_len else "—"
    d["说明"] = "AH 只提供完整性校验与来源认证，载荷不加密"
    return d


# ---------------------------------------------------------------- IKE
def _parse_attributes(buf: bytes, is_v1=False):
    """解析变换属性：返回 [(显示文本), …]。"""
    out, off = [], 0
    while off + 4 <= len(buf):
        af_type, val = struct.unpack(">HH", buf[off:off + 4])
        kind = af_type & 0x7FFF
        if not af_type & 0x8000:                  # TLV：长度仅包含值
            if off + 4 + val > len(buf):
                break
            value = int.from_bytes(buf[off + 4:off + 4 + val], "big")
            off += 4 + val
        else:                                     # TV：值即 2 字节
            value = val
            off += 4
        if is_v1 and kind in IKEV1_TRANSFORM:
            out.append("%s = %s" % (_IKEV1_TNUM[kind], IKEV1_TRANSFORM[kind].get(value, str(value))))
        elif kind == 14:
            out.append("密钥长度 %d 位" % value)
        else:
            out.append("属性 0x%04X = %d" % (kind, value))
    return out


def _parse_proposal_v2(buf: bytes, names: dict):
    """解析一条 IKEv2 提议（含变换列表）。"""
    if len(buf) < 8:
        return []
    last, _rsv, plen, num, proto_id, spi_size, n_tr = struct.unpack(">BBHBBBB", buf[:8])
    off = 8
    spi = buf[off:off + spi_size]
    off += spi_size
    items = []
    for _ in range(n_tr):
        if off + 8 > len(buf):
            break
        t_last, _r, t_len, ttype, _r2, tid = struct.unpack(">BBHBBH", buf[off:off + 8])
        if t_len < 8 or off + t_len > len(buf):
            break
        attrs = _parse_attributes(buf[off + 8:off + t_len])
        tname = TRANSFORM_TYPES.get(ttype, "变换类型 %d" % ttype)
        if ttype == 1:
            vname = IKE_ENCR.get(tid, "0x%04X" % tid)
        elif ttype == 2:
            vname = IKE_PRF.get(tid, "0x%04X" % tid)
        elif ttype == 3:
            vname = IKE_INTEG.get(tid, "0x%04X" % tid)
        elif ttype == 4:
            vname = IKE_DH.get(tid, "0x%04X（未收录，请对照 IANA 注册表）" % tid)
        elif ttype == 5:
            vname = "是" if tid else "否"
        else:
            vname = "%s（组 0x%04X）" % (IKE_DH.get(tid, "0x%04X" % tid), tid)
        txt = "%s = %s" % (tname, vname)
        if attrs:
            txt += "（%s）" % "，".join(attrs)
        items.append(txt)
        off += t_len
        if t_last == 0:
            break
    head = "提议 #%d：协议 %s" % (num, PROTO_ID.get(proto_id, "协议 %d" % proto_id))
    if spi:
        head += "，SPI=0x%s" % spi.hex()
    return [head] + ["　　" + it for it in items]


def _parse_sa_payload_v2(buf: bytes):
    lines, off = [], 0
    while off + 8 <= len(buf):
        last, _r, plen = struct.unpack(">BBH", buf[off:off + 4])
        if plen < 8 or off + plen > len(buf):
            break
        lines.extend(_parse_proposal_v2(buf[off:off + plen], IKE_DH))
        off += plen
        if last == 0:
            break
    return lines


def _parse_transforms_v1(buf: bytes, proto_id=1):
    """IKEv1 变换号/ID 与 ISAKMP 属性；不将变换号误作属性类别。"""
    lines, off = [], 0
    while off + 8 <= len(buf):
        nxt, _r, tlen, tnum, tid, _r2 = struct.unpack(">BBHBBH", buf[off:off + 8])
        if tlen < 8 or off + tlen > len(buf):
            break
        nm = "KEY_IKE" if proto_id == 1 and tid == 1 else "ID 0x%02X" % tid
        lines.append("　　变换 #%d = %s" % (tnum, nm))
        if proto_id == 1:
            lines.extend("　　　　" + item for item in _parse_attributes(buf[off + 8:off + tlen], is_v1=True))
        off += tlen
        if nxt == 0:
            break
    return lines


_IKEV1_TNUM = {1: "加密算法", 2: "哈希算法", 3: "认证方法", 4: "DH 组"}


def _parse_sa_payload_v1(buf: bytes):
    if len(buf) < 8:
        return []
    doi, situation = struct.unpack(">II", buf[:8])
    lines = ["DOI=%d（%s）" % (doi, "IPSec" if doi == 1 else "未知"),
             "Situation=0x%08X" % situation]
    off = 8
    while off + 8 <= len(buf):
        nxt, _r, plen, num, proto_id, spi_size, n_tr = struct.unpack(">BBHBBBB", buf[off:off + 8])
        if plen < 8 or off + plen > len(buf):
            break
        spi = buf[off + 8:off + 8 + spi_size]
        head = "提议 #%d：协议 %s" % (num, PROTO_ID.get(proto_id, "协议 %d" % proto_id))
        if spi:
            head += "，SPI=0x%s" % spi.hex()
        lines.append(head)
        t_off = off + 8 + spi_size
        if n_tr:
            lines.extend(_parse_transforms_v1(buf[t_off:off + plen], proto_id))
        off += plen
        if nxt == 0:
            break
    return lines


def _ike_message_bounds(payload):
    length = struct.unpack(">I", payload[24:28])[0]
    notes = []
    if length < 28:
        notes.append("IKE 头部声明长度无效（不足 28 字节）")
    elif length > len(payload):
        notes.append("IKE 报文被截断（头部声明长度超过已捕获字节）")
    elif length < len(payload):
        notes.append("忽略 IKE 声明长度之外的 %d 字节" % (len(payload) - length))
    return min(length, len(payload)), notes


def _ike_payloads(payload, end, notes):
    off, cur = 28, payload[16]
    while cur and end >= 28:
        if off + 4 > end:
            notes.append("IKE 载荷链截断（缺少载荷头）")
            break
        p_nxt, _critical, p_len = struct.unpack(">BBH", payload[off:off + 4])
        if p_len < 4:
            notes.append("IKE 载荷长度无效（不足 4 字节）")
            break
        if off + p_len > end:
            notes.append("IKE 载荷链截断（载荷超出报文边界）")
            break
        yield cur, payload[off + 4:off + p_len], p_len
        cur, off = p_nxt, off + p_len


def parse_ike(payload: bytes, proto: str = "IKE"):
    """解析 IKE（v1 / v2）报文，返回 OrderedDict 字段。"""
    d = OrderedDict()
    if len(payload) < 28:
        d["说明"] = "IKE 报文不足 28 字节（抓包被截断）"
        return d
    i_spi = payload[0:8]
    r_spi = payload[8:16]
    nxt, ver, exch, flags, msg_id, length = struct.unpack(">BBBBII", payload[16:28])
    major, minor = (ver >> 4) & 0x0F, ver & 0x0F
    is_v2 = (major == 2)
    d["IKE 版本"] = "IKEv2 (%d.%d)" % (major, minor) if is_v2 else "IKEv1 (%d.%d)" % (major, minor)
    d["交换类型"] = "%s (%d)" % (
        (IKEV2_EXCHANGE if is_v2 else IKEV1_EXCHANGE).get(exch, "未知"), exch)
    d["发起者 SPI"] = i_spi.hex()
    d["响应者 SPI"] = r_spi.hex() if r_spi != b"\x00" * 8 else "（首次协商，尚未分配）"
    d["消息 ID"] = msg_id
    fl = []
    if flags & 0x08:
        fl.append("Initiator")
    if flags & 0x20:
        fl.append("Response")
    if flags & 0x10:
        fl.append("Version")
    d["标志"] = "/".join(fl) + (" (0x%02X)" % flags if fl else "0x%02X" % flags)
    d["报文长度"] = "%d 字节（头部声明 %d）" % (len(payload), length)
    end, notes = _ike_message_bounds(payload)
    if proto == "IKE-NAT-T":
        d["承载方式"] = "UDP 4500 NAT-T"
    if not is_v2 and flags & 0x01:
        notes.append("IKEv1 载荷已加密，无法继续解析")
        d["说明"] = "；".join(notes)
        return d

    # ---- 载荷链
    ptypes = IKEV2_PAYLOAD if is_v2 else IKEV1_PAYLOAD
    chain = []
    sa_lines, ke_lines, auth_lines, id_lines, n_lines, nonce_lines = [], [], [], [], [], []
    for cur, body, p_len in _ike_payloads(payload, end, notes):
        name = ptypes.get(cur, "载荷 %d" % cur)
        chain.append("%s(%d)" % (name, p_len))
        if is_v2 and cur in (46, 53):
            notes.append("该报文含 %s（加密载荷）：需会话密钥解密，不能继续解析内部载荷" % name)
            break

        if cur == 33 and is_v2:
            sa_lines = _parse_sa_payload_v2(body)
        elif cur == 1 and not is_v2:
            sa_lines = _parse_sa_payload_v1(body)
        elif cur == 34 and is_v2:                  # KE
            if len(body) >= 4:
                group, _r = struct.unpack(">HH", body[:4])
                gname = IKE_DH.get(group, "0x%04X（未收录，请对照 IANA 注册表）" % group)
                ke_lines.append("DH 组 = %s，公钥 %d 字节" % (gname, len(body) - 4))
        elif cur == 4 and not is_v2:               # v1 KE
            ke_lines.append("公钥 %d 字节（DH 组由 SA 提议确定）" % len(body))
        elif (is_v2 and cur == 40) or (not is_v2 and cur == 10):  # Nonce
            nonce_lines.append("%s：%d 字节" % (name, len(body)))
        elif cur == 39 and is_v2:                  # AUTH
            if len(body) >= 4:
                auth_lines.append("认证方法 = %s，认证数据 %d 字节" % (
                    AUTH_METHODS.get(body[0], "方法 %d" % body[0]), len(body) - 4))
        elif (is_v2 and cur in (35, 36)) or (not is_v2 and cur == 5):  # ID
            if len(body) >= 4:
                idt = body[0]
                val = body[4:]
                if idt in (1, 5):
                    expected_size = 4 if idt == 1 else 16
                    txt = str(ipaddress.ip_address(val)) if len(val) == expected_size else "地址长度无效：" + _hex(val, 24)
                elif idt in (2, 3):
                    txt = val.decode("utf-8", "replace")
                else:
                    txt = _hex(val, 24)
                id_lines.append("%s = %s（%s）" % (
                    name, ID_TYPES.get(idt, "类型 %d" % idt), txt))
        elif (is_v2 and cur == 41) or (not is_v2 and cur == 11):  # Notify
            prefix = 0 if is_v2 else 4
            if len(body) >= prefix + 4:
                proto_id, spi_size, ntype = struct.unpack(">BBH", body[prefix:prefix + 4])
                if prefix + 4 + spi_size > len(body):
                    notes.append("Notify SPI 被截断")
                else:
                    registry = NOTIFY_TYPES if is_v2 else IKEV1_NOTIFY_TYPES
                    doi_text = "" if is_v2 else "，DOI=%d" % struct.unpack(">I", body[:4])[0]
                    n_lines.append("%s（协议 %s，类型 %d%s）" % (
                        registry.get(ntype, "通知类型 %d" % ntype),
                        PROTO_ID.get(proto_id, str(proto_id)), ntype, doi_text))
            else:
                notes.append("Notify 头部被截断")

    if notes:
        d["说明"] = "；".join(notes)
    d["载荷链"] = " → ".join(chain) if chain else "（无载荷）"
    if sa_lines:
        d["SA 提议与变换"] = "\n".join(sa_lines)
    if ke_lines:
        d["密钥交换 KE"] = "\n".join(ke_lines)
    if nonce_lines:
        d["Nonce"] = "\n".join(nonce_lines)
    if id_lines:
        d["身份 ID"] = "\n".join(id_lines)
    if auth_lines:
        d["认证 AUTH"] = "\n".join(auth_lines)
    if n_lines:
        d["通知 Notify"] = "\n".join(n_lines)
    return d


def ike_summary(payload: bytes) -> str:
    """表格概要列文本（如 'IKE_SA_INIT, SA→KE→Ni, 2 个提议：AES-CBC / HMAC-SHA2-256'）。"""
    if len(payload) < 28:
        return "IKE（截断）"
    nxt, ver, exch = payload[16], payload[17], payload[18]
    major = (ver >> 4) & 0x0F
    is_v2 = (major == 2)
    name = (IKEV2_EXCHANGE if is_v2 else IKEV1_EXCHANGE).get(exch, "类型 %d" % exch)
    text = "%s (%s)" % (name, "IKEv2" if is_v2 else "IKEv1")
    end, notes = _ike_message_bounds(payload)
    if not is_v2 and payload[19] & 0x01:
        notes.append("载荷已加密")
        return text + "，" + "；".join(notes)
    # 载荷链 + SA 摘要
    ptypes = IKEV2_PAYLOAD if is_v2 else IKEV1_PAYLOAD
    chain = []
    enc, integ, dh, n_prop = [], [], [], 0
    for cur, body, p_len in _ike_payloads(payload, end, notes):
        chain.append(ptypes.get(cur, str(cur)))
        if is_v2 and cur in (46, 53):
            break
        if cur == 33 and is_v2:
            b_off = 0
            while b_off + 8 <= len(body):
                last, _r, plen, _num, _pid, spi_sz, n_tr = struct.unpack(">BBHBBBB", body[b_off:b_off + 8])
                if plen < 8 or b_off + plen > len(body):
                    break
                n_prop += 1
                t_off = b_off + 8 + spi_sz
                for _ in range(n_tr):
                    if t_off + 8 > b_off + plen:
                        break
                    _tl, _r2, t_len, ttype, _r3, tid = struct.unpack(">BBHBBH", body[t_off:t_off + 8])
                    if t_len < 8 or t_off + t_len > b_off + plen:
                        break
                    if ttype == 1:
                        enc.append(IKE_ENCR.get(tid, "0x%04X" % tid))
                    elif ttype == 3:
                        integ.append(IKE_INTEG.get(tid, "0x%04X" % tid))
                    elif ttype == 4:
                        dh.append(IKE_DH.get(tid, "0x%04X" % tid))
                    t_off += t_len
                b_off += plen
                if last == 0:
                    break
        elif cur == 34 and is_v2 and len(body) >= 4:
            g = struct.unpack(">H", body[:2])[0]
            dh.append(IKE_DH.get(g, "组 0x%04X" % g))
    if chain:
        text += ", " + "→".join(chain)
    det = []
    if n_prop:
        det.append("%d 个提议" % n_prop)
    if enc:
        det.append("加密 %s" % "/".join(dict.fromkeys(enc)))
    if integ:
        det.append("完整性 %s" % "/".join(dict.fromkeys(integ)))
    if dh:
        det.append("DH %s" % "/".join(dict.fromkeys(dh)))
    if det:
        text += "：" + "，".join(det)
    if notes:
        text += "，" + "；".join(notes)
    return text


def packet_info(pkt, proto: str):
    """供 pcap 表格概要列使用：返回 (协议名, 概要文本)。"""
    if proto == "ESP":
        raw = bytes(pkt[IP].payload) if IP in pkt else bytes(pkt[IPv6].payload)
        if len(raw) >= 8:
            spi, seq = struct.unpack(">II", raw[:8])
            return "ESP", "SPI=0x%08X, Seq=%d, 加密载荷 %d 字节" % (spi, seq, max(0, len(raw) - 8))
        return "ESP", "ESP（截断）"
    if proto == "ESP-NAT-T":
        raw = _esp_payload(pkt)
        if len(raw) >= 8:
            spi, seq = struct.unpack(">II", raw[:8])
            return "ESP-NAT-T", "NAT-T 封装 ESP，SPI=0x%08X, Seq=%d" % (spi, seq)
        return "ESP-NAT-T", "NAT-T 封装 ESP"
    if proto == "AH":
        raw = bytes(pkt[IP].payload) if IP in pkt else bytes(pkt[IPv6].payload)
        if len(raw) >= 12:
            spi, seq = struct.unpack(">II", raw[4:12])
            icv = max(0, (raw[1] + 2) * 4 - 12)
            return "AH", "SPI=0x%08X, Seq=%d, ICV %d 字节, 下一个头=%d" % (spi, seq, icv, raw[0])
        return "AH", "AH（截断）"
    if proto in ("IKE", "IKE-NAT-T"):
        return proto, ike_summary(_ike_payload(pkt))
    return proto, ""


def tree_section(pkt) -> OrderedDict:
    """单包字段树中的「IPSec」分组。"""
    proto = proto_of(pkt)
    if not proto:
        return OrderedDict()
    d = OrderedDict()
    d["协议"] = proto
    if proto == "ESP":
        d.update(parse_esp(pkt))
    elif proto == "ESP-NAT-T":
        d.update(parse_esp(pkt))
        d["承载方式"] = "UDP 4500 中的 ESP（NAT-T 穿越），无 Non-ESP 标记"
    elif proto == "AH":
        d.update(parse_ah(pkt))
    else:
        for k, v in parse_ike(_ike_payload(pkt), proto).items():
            d[k] = v
    return d


# ---------------------------------------------------------------- IKE 流 / 协商集
def ike_flow_key(pkt):
    """IKE 流归一化 key，附 UDP 标识避免与同端点 TCP 流冲突。"""
    if proto_of(pkt) not in ("IKE", "IKE-NAT-T"):
        return None
    src, dst, _p = _ip_of(pkt)
    sp, dp = _udp_ports(pkt)
    if None in (src, dst, sp, dp):
        return None
    if (src, sp) <= (dst, dp):
        return (src, sp, dst, dp, "UDP")
    return (dst, dp, src, sp, "UDP")


def _ike_msg_dict(pkt, no, key, client_endpoint):
    """把一个 IKE 报文转成流消息（供时序图）。"""
    src, _dst, _p = _ip_of(pkt)
    sp, _dp = _udp_ports(pkt)
    direction = "A->B" if (src, sp) == (key[0], key[1]) else "B->A"
    payload = _ike_payload(pkt)
    fields = OrderedDict(tree_section(pkt))
    fields.pop("协议", None)
    hdr = parse_ike(payload)
    return {
        "dir": direction,
        "proto": "IKE",
        "type": (hdr.get("交换类型") or "IKE 报文").split(" (")[0],
        "summary": ike_summary(payload),
        "fields": fields,                 # dict：handshake_view 需要 .items()
        "no": no,
        "ts": float(pkt.time),
    }


def ike_flows(pkts):
    """扫描抓包中的 IKE 流，返回 {flow_key: {client, server, proto, cdir, messages}}。"""
    flows = {}
    for i, pkt in enumerate(pkts):
        key = ike_flow_key(pkt)
        if key is None:
            continue
        fl = flows.get(key)
        if fl is None:
            src, dst, _p = _ip_of(pkt)
            sp, dp = _udp_ports(pkt)
            payload = _ike_payload(pkt)
            sender_is_initiator = len(payload) < 28 or payload[17] >> 4 != 2 or bool(payload[19] & 0x08)
            client, server = ((src, sp), (dst, dp)) if sender_is_initiator else ((dst, dp), (src, sp))
            fl = {"client": "%s:%d" % client, "server": "%s:%d" % server,
                  "proto": "IKE", "cdir": "A->B" if client == key[:2] else "B->A",
                  "stream": len(flows), "messages": []}
            flows[key] = fl
        fl["messages"].append(_ike_msg_dict(pkt, i + 1, key, fl["client"]))
    return flows


def ike_sets(flows):
    """把 IKE 流整理成与 TLS/SSH 一致的「协商集」结构，供会话下拉框与时序图使用。"""
    sets_ = []
    for key, fl in (flows or {}).items():
        if fl.get("proto") != "IKE" or not fl.get("messages"):
            continue
        n_sa_init = sum(1 for m in fl["messages"] if "IKE_SA_INIT" in (m.get("summary") or ""))
        label = "%s ⇄ %s · IPSec IKE 协商（%d 个报文%s）" % (
            fl.get("client"), fl.get("server"), len(fl["messages"]),
            "，含 %d 次 SA_INIT" % n_sa_init if n_sa_init else "")
        sets_.append({
            "label": label, "proto": "IKE",
            "client": fl.get("client"), "server": fl.get("server"),
            "phases": [{"label": "IKE 协商", "key": key,
                        "client": fl.get("client"), "server": fl.get("server")}],
        })
    return sets_
