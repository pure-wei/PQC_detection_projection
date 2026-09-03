"""PDF report generator for PQC-HTTPS project.

Uses fpdf2 with Microsoft YaHei for Chinese text support.
"""

import os
import sys
from datetime import datetime
from fpdf import FPDF

from ..tls_analysis.cipher_suite_parser import parse_cipher_suite_name

# Microsoft YaHei font path
_FONT_PATH = "C:/Windows/Fonts/msyh.ttc"
_FONT_BOLD_PATH = "C:/Windows/Fonts/msyhbd.ttc"
_FONT_AVAILABLE = os.path.exists(_FONT_PATH)


class PQCReport(FPDF):
    """Base PDF report with Chinese font support and consistent styling."""

    def __init__(self):
        super().__init__("P", "mm", "A4")
        if _FONT_AVAILABLE:
            self.add_font("zh", "", _FONT_PATH, uni=True)
            self.add_font("zh", "B", _FONT_BOLD_PATH, uni=True)
            self._zh = True
        else:
            self._zh = False

        self.set_auto_page_break(True, 18)
        self._section_num = 0

    # ── Layout helpers ──

    def title_page(self, title: str, subtitle: str = ""):
        """Add a title block at the top of the first page."""
        self.add_page()
        self.ln(10)
        if self._zh:
            self.set_font("zh", "B", 22)
        else:
            self.set_font("Helvetica", "B", 22)
        self.set_text_color(30, 30, 120)
        self.multi_cell(0, 10, title, align="C")
        self.ln(4)
        if subtitle:
            if self._zh:
                self.set_font("zh", "", 11)
            else:
                self.set_font("Helvetica", "", 11)
            self.set_text_color(100, 100, 100)
            self.multi_cell(0, 6, subtitle, align="C")
        self.ln(6)
        self._draw_line()

    def section(self, title: str):
        """Start a new numbered section."""
        self._section_num += 1
        self.ln(4)
        if self._zh:
            self.set_font("zh", "B", 14)
        else:
            self.set_font("Helvetica", "B", 14)
        self.set_text_color(30, 30, 120)
        self.cell(0, 8, f"{self._section_num}. {title}", new_x="LMARGIN", new_y="NEXT")
        self._draw_line(thin=True)
        self.ln(2)

    def body(self, text: str, bold: bool = False, size: int = 10, indent: int = 0):
        """Add a body paragraph."""
        if self._zh:
            style = "B" if bold else ""
            self.set_font("zh", style, size)
        else:
            style = "B" if bold else ""
            self.set_font("Helvetica", style, size)
        self.set_text_color(40, 40, 40)
        x = self.get_x() + indent
        self.set_x(x)
        self.multi_cell(self.w - self.r_margin - x, 6, text, align="L")

    def key_value(self, key: str, value: str, indent: int = 8):
        """Add a key-value line."""
        if self._zh:
            self.set_font("zh", "B", 9)
        else:
            self.set_font("Helvetica", "B", 9)
        self.set_text_color(60, 60, 60)
        self.set_x(self.l_margin + indent)
        self.cell(62, 6, key + ":")

        if self._zh:
            self.set_font("zh", "", 9)
        else:
            self.set_font("Helvetica", "", 9)
        self.set_text_color(40, 40, 40)
        self.cell(0, 6, str(value), new_x="LMARGIN", new_y="NEXT")

    def table_header(self, cols: list, widths: list = None):
        """Draw a table header row."""
        if widths is None:
            widths = [self.w / len(cols)] * len(cols)
        if self._zh:
            self.set_font("zh", "B", 9)
        else:
            self.set_font("Helvetica", "B", 9)
        self.set_fill_color(40, 50, 120)
        self.set_text_color(255, 255, 255)
        self.set_draw_color(40, 50, 120)
        for i, col in enumerate(cols):
            self.cell(widths[i], 7, col, border=1, fill=True, align="C")
        self.ln()

    def table_row(self, cells: list, widths: list = None, fills: list = None):
        """Draw a table data row."""
        if widths is None:
            widths = [self.w / len(cells)] * len(cells)
        if fills is None:
            fills = [False] * len(cells)
        if self._zh:
            self.set_font("zh", "", 8)
        else:
            self.set_font("Helvetica", "", 8)
        self.set_text_color(40, 40, 40)
        self.set_draw_color(200, 200, 200)
        for i, cell in enumerate(cells):
            if fills[i]:
                self.set_fill_color(245, 245, 255)
            else:
                self.set_fill_color(255, 255, 255)
            self.cell(widths[i], 6, str(cell), border=1, fill=True, align="C")
        self.ln()

    def highlight_box(self, text: str, color: tuple = (235, 245, 255)):
        """Add a highlighted info box."""
        self.ln(2)
        self.set_fill_color(*color)
        self.set_draw_color(180, 190, 210)
        if self._zh:
            self.set_font("zh", "", 9)
        else:
            self.set_font("Helvetica", "", 9)
        self.set_text_color(50, 50, 80)
        x0 = self.get_x()
        y0 = self.get_y()
        self.rect(x0, y0, self.w - self.l_margin - self.r_margin, 10, style="DF")
        self.set_xy(x0 + 3, y0 + 2)
        self.cell(self.w - self.l_margin - self.r_margin - 6, 6, text)
        self.ln(12)

    def warning_box(self, text: str):
        """Add a warning box."""
        self.highlight_box(text, color=(255, 245, 235))

    def success_box(self, text: str):
        """Add a success box."""
        self.highlight_box(text, color=(235, 255, 240))

    def _draw_line(self, thin: bool = False):
        """Draw a horizontal separator line."""
        if thin:
            self.set_draw_color(200, 200, 200)
        else:
            self.set_draw_color(30, 30, 120)
        self.set_line_width(0.3 if thin else 0.6)
        y = self.get_y()
        self.line(self.l_margin, y, self.w - self.r_margin, y)
        self.ln(3)

    def footer(self):
        self.set_y(-15)
        if self._zh:
            self.set_font("zh", "", 7)
        else:
            self.set_font("Helvetica", "", 7)
        self.set_text_color(150, 150, 150)
        self.cell(0, 10, f"PQC-HTTPS Project | {datetime.now().strftime('%Y-%m-%d %H:%M')} | Page {self.page_no()}/{{nb}}", align="C")


# ═══════════════════════════════════════════════════════════════════
# Individual report builders
# ═══════════════════════════════════════════════════════════════════

def build_cert_pdf(result, host: str, port: int, output_path: str):
    """Generate certificate analysis PDF report."""
    pdf = PQCReport()
    pdf.alias_nb_pages()

    pdf.title_page(
        "X.509 证书深度分析报告",
        f"目标: {host}:{port}  |  生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )

    # ── Section 1: Basic Info ──
    pdf.section("基本信息")
    pdf.ln(2)
    pdf.key_value("网站域名 (CN)", result.subject_cn or "未获取到")
    pdf.key_value("CA 颁发者 (CN)", result.issuer_cn or "未获取到")
    if result.issuer_org:
        pdf.key_value("CA 颁发机构", result.issuer_org)
    if result.not_before:
        pdf.key_value("证书有效期", f"{result.not_before[:10]} 至 {result.not_after[:10]}")
    pdf.key_value("SHA-256 指纹", result.fingerprint_sha256[:48] + "...")
    pdf.key_value("DER 编码大小", f"{result.raw_der_size} bytes")

    # ── Section 2: Signature ──
    pdf.section("签名算法")
    pdf.ln(2)
    algo_detail = result.sig_algorithm_name
    if result.sig_is_sm: algo_detail += " [国密标准]"
    if result.sig_is_pqc: algo_detail += " [NIST 抗量子标准]"
    pdf.key_value("算法名称", algo_detail)
    pdf.key_value("算法 OID", result.sig_algorithm_oid)

    # ── Section 3: Public Key ──
    pdf.section("公钥信息")
    pdf.ln(2)
    pk_type = result.pubkey_type
    if result.pubkey_is_pqc: pk_type += " [抗量子]"
    pdf.key_value("公钥类型", pk_type)
    pdf.key_value("公钥长度", f"{result.pubkey_size_bits} bits ({result.pubkey_raw_bytes} bytes DER)")
    if result.pubkey_curve:
        pdf.key_value("椭圆曲线", result.pubkey_curve)

    # ── Section 4: Security ──
    pdf.section("安全评估")
    pdf.ln(2)
    qs_text = "是 (抗量子)" if result.is_quantum_safe else "否 (经典密码)"
    pdf.key_value("抗量子安全", qs_text)
    if result.nist_security_level > 0:
        level_desc = {1: "基础级", 2: "中等级", 3: "高级", 5: "最高级"}.get(
            result.nist_security_level, f"Level {result.nist_security_level}")
        pdf.key_value("NIST 安全级别", f"Level {result.nist_security_level} ({level_desc})")
    if result.sig_is_sm:
        pdf.key_value("国密算法", "是 (SM2/SM3)")

    # ── Section 5: Conclusion ──
    pdf.section("总结")
    pdf.ln(2)
    if result.is_quantum_safe:
        pdf.body(f"该证书使用抗量子密码算法 ({result.sig_algorithm_name})，具备抵御量子计算攻击的能力。")
    else:
        pdf.body(f"该证书使用经典密码算法 ({result.sig_algorithm_name})，不具备抗量子能力。")

    _save_pdf(pdf, output_path)
    return output_path


def build_detect_pdf(result, host: str, port: int, output_path: str):
    """Generate PQC detection PDF report."""
    pdf = PQCReport()
    pdf.alias_nb_pages()

    pdf.title_page(
        "PQC 握手检测报告",
        f"目标: {host}:{port}  |  生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )

    # ── Section 1: Connection ──
    pdf.section("连接信息")
    pdf.ln(2)
    pdf.key_value("TLS 协议版本", result.protocol)
    pdf.key_value("协商密码套件", result.cipher_suite_name)
    cs = parse_cipher_suite_name(result.cipher_suite_name)
    pdf.key_value("  密钥交换", cs.kex_algorithm)
    pdf.key_value("  身份认证", cs.auth_algorithm)
    pdf.key_value("  对称加密", cs.symmetric_algorithm)
    pdf.key_value("  哈希算法", cs.hash_algorithm)
    pdf.key_value("握手发送流量", f"{result.handshake_bytes_sent} bytes (客户端->服务器)")
    pdf.key_value("握手接收流量", f"{result.handshake_bytes_recv} bytes (服务器->客户端)")
    pdf.key_value("连接耗时", f"{result.connect_time_ms:.0f} ms")

    # ── Section 2: PQC Detection ──
    pdf.section("PQC 检测结果")
    pdf.ln(2)
    if result.pqc_supported:
        pdf.key_value("检测结论", "支持抗量子密码 (PQC)")
        pdf.key_value("检测方式", f"{result.method} (直接握手验证)")
        pdf.key_value("PQC 算法", result.pqc_algorithm)
        pdf.key_value("PQC 密钥交换组 ID", result.pqc_group_id)
        pdf.key_value("ServerHello key_share 大小", f"{result.pqc_key_share_size} bytes")
        pdf.key_value("证据", result.evidence)
    else:
        pdf.key_value("检测结论", "不支持抗量子密码")
        pdf.key_value("检测方式", result.method)
        pdf.key_value("证据", result.evidence)

    # ── Section 3: Cipher Suite ──
    pdf.section("密码套件组成")
    pdf.ln(2)
    col_w = [35, 75, 75]
    pdf.table_header(["组成部分", "使用的算法", "是否抗量子"], col_w)
    kex_name = f"PQC ({result.pqc_algorithm})" if result.pqc_supported else "经典 ECDH/X25519"
    kex_pqc = "是" if result.pqc_supported else "否"
    pdf.table_row(["密钥交换", kex_name, kex_pqc], col_w)
    pdf.table_row(["身份认证", "证书签名算法", "取决于证书"], col_w)
    pdf.table_row(["对称加密", result.cipher_suite_name, "是 (AES-256 抗 Grover)"], col_w)

    # ── Section 4: Conclusion ──
    pdf.section("总结")
    pdf.ln(2)
    if result.pqc_supported:
        pdf.body(f"{host} 在 TLS 传输层支持抗量子密码密钥交换 ({result.pqc_algorithm})。")
    else:
        pdf.body(f"{host} 暂不支持抗量子密码密钥交换。")

    _save_pdf(pdf, output_path)
    return output_path


def build_pcap_pdf(cap, host: str, port: int, output_path: str, vresult=None):
    """Generate packet capture PDF report.

    Args:
        vresult: Optional VerificationResult for anti-spoofing section.
    """
    pdf = PQCReport()
    pdf.alias_nb_pages()

    pdf.title_page(
        "TLS 握手抓包报告",
        f"目标: {host}:{port}  |  生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )

    # ── Section 1: Overview ──
    pdf.section("握手概览")
    pdf.ln(2)
    pdf.key_value("TLS 协议版本", cap.protocol)
    pdf.key_value("协商密码套件", cap.cipher_suite)
    cs = parse_cipher_suite_name(cap.cipher_suite)
    pdf.key_value("  密钥交换", cs.kex_algorithm)
    pdf.key_value("  身份认证", cs.auth_algorithm)
    pdf.key_value("  对称加密", cs.symmetric_algorithm)
    pdf.key_value("  哈希算法", cs.hash_algorithm)
    pdf.key_value("抓包方法", cap.capture_method)
    pdf.key_value("总记录数", str(cap.record_count))
    pdf.key_value("客户端发送", f"{cap.total_sent_bytes} bytes")
    pdf.key_value("服务器发送", f"{cap.total_recv_bytes} bytes")
    pdf.key_value("握手总流量", f"{cap.total_bytes} bytes")

    # ── Section 2: Record Analysis ──
    pdf.section("逐条记录")
    pdf.ln(2)

    # Version-aware format reference
    is_tls13 = "TLSv1.3" in cap.protocol if cap.protocol else True
    ver_label = "TLS 1.3" if is_tls13 else "TLS 1.2"

    pdf.set_font("zh", "", 8)
    pdf.set_text_color(80, 80, 80)
    pdf.cell(0, 5, f"本次握手协商的协议版本为 {ver_label}，以下为该版本对应字段结构：", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)

    ref_col_w = [28, 16, 25, 121]
    pdf.set_font("zh", "B", 8)
    pdf.set_fill_color(245, 245, 250)
    pdf.set_text_color(40, 40, 80)
    pdf.set_draw_color(200, 200, 210)
    for col, w in zip(["消息类型", "字段", "字节偏移", "说明"], ref_col_w):
        pdf.cell(w, 6, col, border=1, fill=True, align="C")
    pdf.ln()

    pdf.set_font("zh", "", 7)
    pdf.set_text_color(60, 60, 60)
    pdf.set_draw_color(210, 210, 215)

    def ref_row(msg, fields):
        for j, (fname, off, desc) in enumerate(fields):
            pdf.set_fill_color(255, 255, 255)
            if j == 0:
                pdf.cell(ref_col_w[0], 5, msg, border=1)
            else:
                pdf.cell(ref_col_w[0], 5, "", border=1)
            pdf.cell(ref_col_w[1], 5, fname, border=1, align="C")
            pdf.cell(ref_col_w[2], 5, off, border=1, align="C")
            pdf.cell(ref_col_w[3], 5, desc, border=1)
            pdf.ln()

    # Common to both versions
    ref_row("ClientHello", [
        ("HandshakeType", "Byte 0", "固定 0x01，ClientHello 消息"),
        ("Length", "Byte 1-3", "消息体总长度 (不含这 4 字节握手头)"),
        ("ProtocolVersion", "Byte 4-5", "客户端支持的最高版本。TLS 1.2 写 0x0303，TLS 1.3 在扩展中声明"),
        ("Random", "Byte 6-37", "32 字节客户端随机数，参与后续密钥派生"),
        ("SessionID", "Byte 38+", f"1 字节长度 + 会话 ID ({'TLS 1.3 始终为空 (0x00)，会话恢复改用 PSK 扩展' if is_tls13 else 'TLS 1.2 非空时可尝试会话恢复'})"),
        ("CipherSuites", "变长", f"2 字节长度 + 密码套件列表 ({'TLS 1.3: 0x1301~0x1305' if is_tls13 else 'TLS 1.2: 0xC02B 等 2 字节编码'})"),
        ("Compression", "变长", f"1 字节长度 + 压缩方法 ({'TLS 1.3 固定 0x01 0x00 (仅 null)' if is_tls13 else 'TLS 1.2 通常也是 null'})"),
        ("Extensions", "变长", "2 字节长度 + 扩展列表。含 supported_groups、key_share、signature_algorithms 等"),
    ])

    ref_row("ServerHello", [
        ("HandshakeType", "Byte 0", "固定 0x02，ServerHello 消息"),
        ("Length", "Byte 1-3", "消息体总长度"),
        ("ProtocolVersion", "Byte 4-5", f"服务器选定的版本 ({'TLS 1.3: 0x0303' if is_tls13 else 'TLS 1.2: 如 0x0303'})"),
        ("Random", "Byte 6-37", "32 字节服务器随机数"),
        ("SessionID", "Byte 38+", f"1 字节长度 + 会话 ID ({'TLS 1.3 通常为空' if is_tls13 else 'TLS 1.2 可能非空来恢复会话'})"),
        ("CipherSuite", "变长", f"2 字节 ({'如 0x1302 = TLS_AES_256_GCM_SHA384' if is_tls13 else '如 0xC02B = ECDHE-ECDSA-AES128-GCM-SHA256'})"),
        ("Compression", "变长", "1 字节 (TLS 1.3 固定 0x00)"),
        ("Extensions", "变长", f"2 字节长度。key_share 扩展指明服务器选择的密钥交换组{' (PQC 检测关键字段)' if is_tls13 else ''}"),
    ])

    ref_row("Certificate", [
        ("HandshakeType", "Byte 0", "固定 0x0B"),
        ("Length", "Byte 1-3", "消息体总长度"),
        ("CertChain", "余下字节" if is_tls13 else "Byte 4+",
         f"{'TLS 1.3: 1B 上下文长度 + 3B 证书链长度 + DER 证书数据' if is_tls13 else 'TLS 1.2: 3B 证书链长度 + DER 证书数据 (无 RequestContext 字段)'}"),
    ])

    ref_row("CertificateVerify", [
        ("HandshakeType", "Byte 0", "固定 0x0F"),
        ("Length", "Byte 1-3", "消息体总长度"),
        ("SigAlgorithm", "Byte 4-5", "签名算法标识 (2 字节)"),
        ("Signature", "Byte 6-末尾", f"对握手 transcript 的签名 ({'TLS 1.3 签名覆盖 hash(transcript) + 固定前缀' if is_tls13 else 'TLS 1.2 签名覆盖所有握手消息的 hash'})"),
    ])

    ref_row("Finished", [
        ("HandshakeType", "Byte 0", "固定 0x14"),
        ("Length", "Byte 1-3", "HMAC 数据长度"),
        ("VerifyData", "Byte 4-末尾", f"HMAC 校验值 ({'TLS 1.3: HMAC-SHA256 (通常 32 字节)' if is_tls13 else 'TLS 1.2: 12 字节 (TLS PRF)'})"),
    ])

    if is_tls13:
        ref_row("EncryptedExtensions", [
            ("HandshakeType", "Byte 0", "固定 0x08 (TLS 1.3 新增，TLS 1.2 无此消息)"),
            ("Length", "Byte 1-3", "消息体总长度"),
            ("Extensions", "Byte 4+", "2 字节长度 + 加密扩展列表 (如 ALPN、supported_groups 等)"),
        ])
    else:
        ref_row("ServerKeyExchange (TLS 1.2 特有)", [
            ("HandshakeType", "Byte 0", "固定 0x0C。仅 TLS 1.2 使用，TLS 1.3 已移除此消息"),
            ("Length", "Byte 1-3", "消息体总长度"),
            ("Params", "Byte 4+", "密钥交换参数 (ECDHE 公钥 + 签名参数)"),
        ])
        ref_row("ServerHelloDone (TLS 1.2 特有)", [
            ("HandshakeType", "Byte 0", "固定 0x0E。空消息体，标志服务器握手消息结束"),
            ("Length", "Byte 1-3", "固定 0x000000 (无消息体)"),
        ])

    ref_row("ChangeCipherSpec", [
        ("Value", "Byte 0", f"单字节 0x01 ({'TLS 1.3 中仅作为兼容性标记，实际不是握手消息' if is_tls13 else 'TLS 1.2 中正式切换密钥'})"),
    ])

    ref_row("Alert", [
        ("Level", "Byte 0", "告警级别: 0x01 = Warning, 0x02 = Fatal"),
        ("Description", "Byte 1", "0x00 = close_notify, 0x0A = unexpected_message, 0x28 = handshake_failure"),
    ])

    pdf.ln(3)

    notes = {
        "ClientHello": "客户端声明密码套件和密钥交换参数 (含PQC组)",
        "ServerHello": "服务器选定算法，返回 key_share (PQC检测关键)",
        "Certificate": "服务器 X.509 证书链 (明文DER，可直接解析)",
        "CertificateVerify": "服务器私钥签名，证明持有证书",
        "Finished": "HMAC校验，握手完整性确认",
        "EncryptedExtensions": "加密通道中的额外扩展 (TLS 1.3)",
        "NewSessionTicket": "会话票据 (0-RTT快速恢复)",
        "ChangeCipherSpec": "切换密钥—此后消息加密",
    }

    for i, rec in enumerate(cap.tls_records):
        hs = rec.handshake_type or ""
        direction = "客户端 -> 服务器" if rec.direction == ">>>" else "服务器 -> 客户端"
        note = notes.get(hs, "")

        if pdf.get_y() > pdf.h - 40:
            pdf.add_page()

        # Record header line
        pdf.set_font("zh", "B", 9)
        pdf.set_text_color(30, 30, 120)
        pdf.cell(0, 6, f"记录 {i+1}: {rec.content_type} / {hs or '-'}   [{direction}]   {rec.record_length} bytes   {rec.tls_version}", new_x="LMARGIN", new_y="NEXT")
        if note:
            pdf.set_font("zh", "", 8)
            pdf.set_text_color(80, 80, 80)
            pdf.cell(0, 5, f"  说明: {note}", new_x="LMARGIN", new_y="NEXT")

        # Data format annotation + hex
        hex_str = rec.hex_data.strip()
        if hex_str and hs:
            try:
                raw = bytes.fromhex(hex_str.replace(" ", ""))
                annotation = _annotate_handshake(hs, raw)
                if annotation:
                    pdf.set_font("zh", "", 7)
                    pdf.set_text_color(130, 50, 50)
                    pdf.set_x(pdf.l_margin + 4)
                    pdf.cell(0, 4, f"格式: {annotation}", new_x="LMARGIN", new_y="NEXT")
            except Exception:
                pass

            pdf.set_font("zh", "", 7)
            pdf.set_text_color(100, 100, 100)
            hex_wrapped = [hex_str[j:j+66] for j in range(0, min(len(hex_str), 264), 66)]
            for line in hex_wrapped:
                pdf.set_x(pdf.l_margin + 4)
                pdf.cell(0, 4, f"hex: {line}", new_x="LMARGIN", new_y="NEXT")
        elif hex_str:
            pdf.set_font("zh", "", 7)
            pdf.set_text_color(100, 100, 100)
            hex_wrapped = [hex_str[j:j+66] for j in range(0, min(len(hex_str), 132), 66)]
            for line in hex_wrapped:
                pdf.set_x(pdf.l_margin + 4)
                pdf.cell(0, 4, f"hex: {line}", new_x="LMARGIN", new_y="NEXT")

        pdf.ln(2)

    # ── Anti-spoofing verification section ──
    if vresult:
        pdf.add_page()
        pdf.section("抗伪造验证 (Anti-Spoofing Verification)")

        status_color = {"PASS": (0, 120, 0), "WARN": (180, 120, 0), "FAIL": (180, 0, 0), "SKIP": (100, 100, 100)}

        pdf.ln(2)
        pdf.body("随机数质量检查", bold=True, size=10)
        pdf.ln(1)
        rnd_col = [48, 36, 36, 70]
        pdf.table_header(["字段", "大小", "熵(bits/byte)", "状态"], rnd_col)
        for rd in vresult.randomness:
            pdf.table_row([
                rd.label,
                f"{rd.byte_count}B",
                f"{rd.entropy:.1f}" if rd.entropy > 0 else "-",
                rd.status,
            ], rnd_col)
        pdf.ln(3)

        pdf.body("证书签名验证", bold=True, size=10)
        pdf.ln(1)
        if vresult.cert_sig:
            cs = vresult.cert_sig
            pdf.key_value("声明算法", f"{cs.declared_name} ({cs.declared_oid})" if cs.declared_name else "未获取")
            sig_txt = "有效" if cs.signature_valid else ("无效" if cs.signature_valid is False else "未验证")
            pdf.key_value("密码学验证", sig_txt)
            pdf.key_value("算法/公钥一致性", "一致" if cs.algo_match else "不一致 [可能是伪造!]")
            pdf.key_value("结论", cs.details)
        pdf.ln(3)

        pdf.body("密钥交换一致性", bold=True, size=10)
        pdf.ln(1)
        if vresult.key_share:
            ks = vresult.key_share
            pdf.key_value("声明组", f"{ks.declared_name} ({ks.declared_group_id:#06X})" if ks.declared_name else "未获取")
            if ks.expected_size > 0:
                pdf.key_value("期望大小", f"{ks.expected_size}B")
                pdf.key_value("实际大小", f"{ks.actual_size}B")
                pdf.key_value("匹配", "是" if ks.sizes_match else "否")
            pdf.key_value("结论", ks.details)
        pdf.ln(3)

        pdf.body(f"综合结论: {vresult.overall} ({vresult.failures}严重问题, {vresult.warnings}警告)", bold=True, size=11)

    _save_pdf(pdf, output_path)
    return output_path


def _annotate_handshake(hs_type: str, raw: bytes) -> str:
    """Parse handshake body and return a byte-level annotation string."""
    if len(raw) < 4:
        return ""
    hs_byte = raw[0]
    length = int.from_bytes(raw[1:4], "big")

    # Common: [HandshakeType 1B] [Length 3B]
    if hs_type == "ClientHello" and len(raw) >= 40:
        ver = raw[4:6].hex()
        rand = raw[6:38].hex()[:16] + "..."
        sid_len = raw[38]
        pos = 39 + sid_len
        if pos + 2 <= len(raw):
            cs_len = int.from_bytes(raw[pos:pos+2], "big")
            pos += 2 + cs_len
        if pos + 1 <= len(raw):
            comp_len = raw[pos]; pos += 1 + comp_len
        ext_len = int.from_bytes(raw[pos:pos+2], "big") if pos + 2 <= len(raw) else 0
        return (f"[HandshakeType=0x{hs_byte:02X}] [Len={length}] "
                f"[Version=0x{ver}] [Random=32B] [SessionID={sid_len}B] "
                f"[CipherSuites={cs_len}B] [Compr={comp_len}B] [Extensions={ext_len}B]")

    if hs_type == "ServerHello" and len(raw) >= 40:
        ver = raw[4:6].hex()
        rand = raw[6:38].hex()[:16] + "..."
        sid_len = raw[38]
        pos = 39 + sid_len
        cs = raw[pos:pos+2].hex() if pos + 2 <= len(raw) else "?"
        pos += 2
        comp = raw[pos] if pos < len(raw) else 0; pos += 1
        ext_len = int.from_bytes(raw[pos:pos+2], "big") if pos + 2 <= len(raw) else 0
        return (f"[HandshakeType=0x{hs_byte:02X}] [Len={length}] "
                f"[Version=0x{ver}] [Random=32B] [SessionID={sid_len}B] "
                f"[CipherSuite=0x{cs}] [Compr=0x{comp:02X}] [Extensions={ext_len}B]")

    if hs_type == "Certificate" and len(raw) >= 8:
        ctx_len = int.from_bytes(raw[4:7], "big")
        cert_len = int.from_bytes(raw[7:10], "big") if len(raw) > 10 else 0
        return (f"[HandshakeType=0x{hs_byte:02X}] [Len={length}] "
                f"[CertReqCtx={ctx_len}B] [CertChain={cert_len}B ...]")

    if hs_type == "Finished":
        return f"[HandshakeType=0x{hs_byte:02X}] [Len={length}] [VerifyData={length}B]"

    if hs_type == "EncryptedExtensions" and len(raw) >= 6:
        ext_len = int.from_bytes(raw[4:6], "big")
        return f"[HandshakeType=0x{hs_byte:02X}] [Len={length}] [Extensions={ext_len}B]"

    # Generic handshake
    if length > 0:
        return f"[HandshakeType=0x{hs_byte:02X}] [Len={length}] [Body={length}B]"

    return ""


def _save_pdf(pdf, path: str):
    """Save PDF, suppressing C-level stderr noise from font subsetting."""
    old_stderr = sys.stderr
    sys.stderr = open(os.devnull, "w")
    try:
        pdf.output(path)
    finally:
        sys.stderr.close()
        sys.stderr = old_stderr
