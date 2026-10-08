# -*- coding: utf-8 -*-
"""Generate the initial Word draft describing implemented PQC detection work."""

from pathlib import Path

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor


OUTPUT = Path(__file__).with_name("面向后量子密码的协议检测与算法验证-检测内容初稿.docx")


def configure_document(document):
    section = document.sections[0]
    section.top_margin = Cm(2.4)
    section.bottom_margin = Cm(2.2)
    section.left_margin = Cm(2.6)
    section.right_margin = Cm(2.4)
    normal = document.styles["Normal"]
    normal.font.name = "Times New Roman"
    normal.font.size = Pt(10.5)
    normal._element.rPr.rFonts.set(qn("w:eastAsia"), "宋体")
    normal.paragraph_format.line_spacing = 1.25
    normal.paragraph_format.space_after = Pt(4)
    for name, size in (("Heading 1", 16), ("Heading 2", 13), ("Heading 3", 11.5)):
        style = document.styles[name]
        style.font.name = "Times New Roman"
        style.font.size = Pt(size)
        style.font.bold = True
        style.font.color.rgb = RGBColor(0x1F, 0x3B, 0x73)
        style._element.rPr.rFonts.set(qn("w:eastAsia"), "黑体")
        style.paragraph_format.space_before = Pt(10)
        style.paragraph_format.space_after = Pt(5)


def add_text(document, text, *, style=None, bold=False, align=None):
    paragraph = document.add_paragraph(style=style)
    run = paragraph.add_run(text)
    run.bold = bold
    run.font.name = "Times New Roman"
    run._element.rPr.rFonts.set(qn("w:eastAsia"), "宋体")
    if align is not None:
        paragraph.alignment = align
    return paragraph


def add_table(document, headers, rows):
    table = document.add_table(rows=1, cols=len(headers))
    table.style = "Table Grid"
    table.autofit = True
    for cell, text in zip(table.rows[0].cells, headers):
        cell.text = text
        for run in cell.paragraphs[0].runs:
            run.bold = True
    for row in rows:
        cells = table.add_row().cells
        for cell, text in zip(cells, row):
            cell.text = text
    for row in table.rows:
        for cell in row.cells:
            for paragraph in cell.paragraphs:
                paragraph.paragraph_format.space_after = Pt(0)
                for run in paragraph.runs:
                    run.font.size = Pt(9)
                    run.font.name = "Times New Roman"
                    run._element.rPr.rFonts.set(qn("w:eastAsia"), "宋体")
    return table


def build_document():
    document = Document()
    configure_document(document)
    title = document.add_paragraph()
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = title.add_run("面向后量子密码的协议检测与算法验证分析平台\n检测与验证内容初稿")
    run.bold = True
    run.font.size = Pt(20)
    run.font.color.rgb = RGBColor(0x17, 0x2B, 0x4D)
    run.font.name = "Times New Roman"
    run._element.rPr.rFonts.set(qn("w:eastAsia"), "黑体")
    add_text(document, "版本：初稿 V0.1　　日期：2026年10月8日　　项目：PQC_detection_projection",
             align=WD_ALIGN_PARAGRAPH.CENTER)

    document.add_heading("摘要", level=1)
    add_text(document,
             "本平台围绕后量子密码迁移中的“看得见、测得准、可验证”三个目标，已经实现一套桌面化分析工具。"
             "平台既支持对 pcap/pcapng 抓包文件做离线协议解析和会话还原，也支持主动发起 TLS 1.3 握手，"
             "以本方临时私钥完成混合密钥交换、服务器握手消息解密、CertificateVerify 验签和 Finished 校验。"
             "针对公网站点中普遍存在的“密钥交换已混合化、证书签名仍为经典算法”的情况，平台将传输层与证书层分开判定，"
             "不把单一算法证据误报为完全后量子化。")
    add_text(document,
             "考虑到被动抓包无法获得客户端临时私钥、无法解密 TLS 1.3 服务器飞行、也难以验证签名数据的问题，"
             "本项目进一步建立本地后量子实验站：由本地生成 ML-DSA 根证书与服务器证书，OpenSSL 作为真实服务端，"
             "平台作为客户端发起连接，形成“混合密钥交换 + 后量子证书签名 + 完整 HTTPS/TLS 验证”的闭环。"
             "同时通过篡改证书签名、使用错误主机名、限制仅经典密钥交换等负向实验，证明检测逻辑不是只依赖 OID 或长度标签，"
             "而是能对数据本身进行密码学验证。")

    document.add_heading("一、平台总体设计与已实现内容", level=1)
    add_text(document,
             "平台采用 PySide6 桌面界面，核心逻辑拆分在协议解析、主动检测、算法演示和本地实验站模块中。当前实现已经覆盖：")
    for item in [
        "pcap/pcapng 抓包解析：加载抓包文件，重组 TCP 会话，展示客户端与服务器交互时序、报文列表和字段树。",
        "TLS/TLCP/SSH/CSSH 等安全协议解析：提取协议版本、密码套件、SNI、ALPN、签名算法、密钥交换组、证书与握手消息。",
        "后量子证据识别：识别 ML-KEM、ML-DSA、SLH-DSA、Falcon 及经典—后量子混合方案的 OID、TLS 组标识和参数长度。",
        "主动深度检测：构造含后量子组的 ClientHello，解析 ServerHello，完成密钥派生、加密握手解密、CertificateVerify 和 Finished 验证。",
        "证书详情分析：通过 Python ssl 优先获取证书，失败时回退 openssl s_client -showcerts，解析签名算法、公钥算法、证书链和指纹。",
        "算法验证演示：单独执行 ML-KEM 封装/解封装、ECDH+ML-KEM 混合加密、ML-DSA/SLH-DSA/Falcon 签名验签及混合签名 AND 验证。",
        "本地后量子实验站：自建客户端与服务端，使用真实 OpenSSL TLS、ML-DSA 证书和混合密钥交换，形成可控验证环境。",
        "结果输出：会话列表、时序图、关键字段表、支持矩阵、JSON 导出和逐字段完整报文导出。",
    ]:
        add_text(document, item, style="List Bullet")

    document.add_heading("二、抓包检测内容与被动分析的局限", level=1)
    document.add_heading("2.1 抓包文件可提取的信息", level=2)
    add_text(document,
             "离线抓包模块支持 pcap 与 pcapng。平台先按五元组和 TCP 序列重组会话，再将同一连接中的握手消息归入同一会话视图。"
             "对于 TLS 1.3，可从明文 ClientHello 中提取 supported_versions、supported_groups、key_share、cipher_suites、"
             "signature_algorithms、SNI 和 ALPN；从 ServerHello 中提取服务器最终选择的密码套件和 key_share 组。"
             "对于 TLS 1.2、TLCP、SSH、CSSH 等协议，平台也能展示协商出的密钥交换、签名、摘要、加密和 MAC 算法。")
    add_text(document,
             "如果抓包中存在明文 Certificate 消息，平台可以解析证书链、签名算法 OID、公钥算法 OID、公钥长度、有效期和主体信息；"
             "如果存在 CertificateVerify，则可解析签名方案与签名长度。界面以“客户端—服务器”时序图展示这些字段在协议交互中的位置，"
             "并进一步给出传统算法、后量子算法和混合算法的组合关系。")

    document.add_heading("2.2 被动抓包的边界", level=2)
    for item in [
        "无法计算共享秘密：被动观察者没有客户端临时私钥，也不能解封装服务器返回的 ML-KEM 密文，因此无法直接得到 TLS 1.3 握手密钥。",
        "无法解密服务器飞行：EncryptedExtensions、Certificate、CertificateVerify 和 Finished 在 TLS 1.3 中均加密传输，抓包中通常不可见。",
        "无法验证 CertificateVerify：签名数据缺失时不能验签；即使签名可见，也只验证签名方程，不能证明观察者拥有握手双方私钥。",
        "证书链信任受限于抓包内容：只能分析服务器实际发送的证书，不等于完成公共 CA 信任链、吊销状态或策略校验。",
        "算法标识存在误用可能：仅凭 OID 或组标识判断不够，必须结合参数长度、字节格式和后续密码学结果。",
        "抓包质量影响分析：截断、分片乱序、时间范围不足、应用自定义协议或旧草案组都会降低识别完整性。",
    ]:
        add_text(document, item, style="List Bullet")
    add_text(document,
             "因此，本平台把抓包分析定位为“协议行为与部署证据观察”，把真正的一致性和身份验证放在主动检测与本地实验站中完成。")

    document.add_heading("三、主动发起的后量子 TLS 检测", level=1)
    document.add_heading("3.1 主动 ClientHello 与 ServerHello 证据", level=2)
    add_text(document,
             "主动检测模式由平台生成临时客户端密钥材料，构造 TLS 1.3 ClientHello。默认优先提供混合后量子组，"
             "同时保留经典组作为回退；ClientHello 还显式携带 ML-DSA 与 SLH-DSA 签名算法，"
             "避免仅支持后量子证书的服务器因签名算法不匹配而拒绝握手。服务器返回 ServerHello 后，"
             "平台读取 key_share 扩展，确认服务器实际选择的组、组 ID、密钥份额长度和密码套件。")
    add_table(document, ["TLS 组", "组 ID", "组合方式", "key_share 扩展体长度"], [
        ["X25519MLKEM768", "0x11EC", "X25519 + ML-KEM-768", "32 + 1088 + 4 = 1124 字节"],
        ["SecP256r1MLKEM768", "0x11EB", "P-256 + ML-KEM-768", "65 + 1088 + 4 = 1157 字节"],
        ["SecP384r1MLKEM1024", "0x11ED", "P-384 + ML-KEM-1024", "97 + 1568 + 4 = 1669 字节"],
        ["X25519MLKEM1024", "0x11EE", "X25519 + ML-KEM-1024", "32 + 1568 + 4 = 1604 字节"],
        ["MLKEM512", "0x0200", "纯 ML-KEM-512", "768 + 4 = 772 字节"],
        ["MLKEM768", "0x0201", "纯 ML-KEM-768", "1088 + 4 = 1092 字节"],
        ["MLKEM1024", "0x0202", "纯 ML-KEM-1024", "1568 + 4 = 1572 字节"],
    ])
    add_text(document,
             "注：表中长度为 key_share 扩展体长度，即 group(2 字节)、key_exchange 长度(2 字节)与密钥数据之和。"
             "平台使用该口径与 RFC/IANA/FIPS 参数表交叉校验，避免把标识与数据不一致的响应误判为有效算法。",
             style="Intense Quote")

    document.add_heading("3.2 从“长度验证”到“密钥数据本身验证”", level=2)
    add_text(document,
             "长度校验只是第一层反伪造检查。平台获得组 ID 和长度后，继续按所选组的编码规则拆分服务器 key_share，"
             "并执行真实密钥交换。以 X25519MLKEM768 为例，服务器 key_share 前 1088 字节为 ML-KEM 封装密文，后 32 字节为 X25519 公钥；"
             "P-256/P-384 混合组则按相应顺序拆分 ECDH 点与 ML-KEM 密文。")
    for item in [
        "解析 ServerHello key_share，记录组 ID、密钥长度、协商套件和长度一致性。",
        "使用本方保留的临时 ML-KEM 私钥执行 decapsulation，得到后量子共享秘密。",
        "使用本方 ECDH 私钥与服务器 ECDH 公钥执行 X25519、P-256 或 P-384 交换，得到传统共享秘密。",
        "按混合组规范拼接 ML-KEM 与 ECDH 输出，作为 TLS 1.3 共享秘密。",
        "按 RFC 8446 HKDF-Extract/Expand-Label 派生服务器握手流量密钥和 Finished 密钥。",
        "用 AEAD 密钥解密 EncryptedExtensions、Certificate、CertificateVerify 和 Finished。",
        "用握手转录哈希计算服务器 Finished HMAC，与服务器发送值比对。",
    ]:
        add_text(document, item, style="List Number")
    add_text(document,
             "这一流程验证的是密钥数据本身。如果攻击者只把组 ID 改成后量子组，或构造长度正确但内容错误的 key_share，"
             "平台会在 ECDH 公钥解析、ML-KEM 解封装、AEAD 认证标签或 Finished HMAC 处失败。"
             "特别地，ML-KEM 对异常密文可能产生隐式拒绝秘密，该错误秘密会导致后续 AEAD 解密失败或 Finished 不一致，"
             "因此不会仅因长度正确而判定通过。")

    document.add_heading("3.3 证书、CertificateVerify 与 Finished 验证", level=2)
    add_text(document,
             "深度检测解密服务器飞行后，严格解析 TLS 1.3 Certificate 列表，提取叶子证书 DER 及服务器提供的完整证书链。"
             "随后按 TLS 1.3 规则构造 CertificateVerify 签名内容：64 个空格字节、ASCII 上下文字符串、空字节和截至 Certificate 消息之后的转录哈希。"
             "平台从叶子证书中取得公钥，用该公钥验证 CertificateVerify 签名。")
    add_table(document, ["证书/签名类型", "验证方式", "失败表现"], [
        ["ML-DSA-44/65/87", "校验方案与证书 OID 一致，检查公钥与签名长度，再调用 ML-DSA verify(public, data, signature)", "InvalidSignature，判定 failed"],
        ["ECDSA", "使用证书 EC 公钥按 SHA-256/384/512 验证签名", "签名方程不成立，判定 failed"],
        ["RSA-PSS / RSA-PKCS", "使用证书 RSA 公钥和相应填充及摘要算法验签", "填充或签名不匹配，判定 failed"],
        ["Ed25519 / Ed448", "使用证书公钥验证纯签名", "验签失败，判定 failed"],
        ["未知或未支持方案", "记录方案 ID 与错误原因", "判定 unsupported，不冒充验证通过"],
    ])
    add_text(document,
             "服务器 Finished 使用派生出的 server_finished_key 对完整握手转录做 HMAC。只有 CertificateVerify 与 Finished 均通过，"
             "平台才把该连接标记为“服务器侧握手密码学验证通过”。深度模式不发送客户端 Finished，验证范围明确限定为服务器飞行。")
    add_text(document,
             "证书详情获取与主动握手解密互补：平台优先使用 Python ssl 建立独立连接获取证书；遇到本机库不识别的后量子签名算法时，"
             "回退到 openssl s_client -showcerts。随后解析签名 OID、公钥 OID、公钥长度、签名字节长度、证书链和指纹。"
             "对公网检测，平台明确不宣称完成公共 CA 信任链验证；证书链签名与 CA 信任的完整验证在本地实验站中通过指定实验 CA 完成。")

    document.add_heading("3.4 现网站点的分层结论", level=2)
    add_text(document,
             "当前大量站点已经能选择 X25519MLKEM768 等混合密钥交换组，但证书签名仍多为 ECDSA 或 RSA。"
             "对此，平台输出两个层次：传输层密钥交换为抗量子混合组；证书层身份认证仍为经典算法。"
             "只有当密钥交换与证书签名均满足后量子要求时，才得出“双层后量子”结论。")

    document.add_heading("四、单独后量子算法演示与标准向量验证", level=1)
    document.add_heading("4.1 ML-KEM 封装与解封装", level=2)
    add_text(document,
             "算法演示页支持 ML-KEM-512、ML-KEM-768 和 ML-KEM-1024。每次运行现场生成接收方密钥对，发送方使用公钥封装，"
             "接收方用私钥解封装，并比较双方共享秘密。页面可展开采样向量、矩阵、NTT、压缩编码和隐式拒绝过程，"
             "同时隐藏私钥全文，仅展示必要摘要。平台还修改封装密文后重新解封装，观察秘密变化，说明密文数据本身参与结果计算。")
    add_text(document,
             "ML-KEM 教学实现与 pqcrypto 原生库交叉校验，并使用 NIST ACVP keyGen 与 encapDecap 测试向量验证三个参数集。"
             "若重算结果与原生库或标准向量不一致，演示直接报告失败。")

    document.add_heading("4.2 ECDH + ML-KEM 混合加密", level=2)
    add_text(document,
             "混合演示分别执行 X25519/P-256/P-384 ECDH 和 ML-KEM 封装，将两路秘密拼接后经 HKDF-SHA256 派生 AES-256-GCM 密钥，"
             "完成加密、解密、篡改密文和认证标签校验。该演示用于解释 TLS 混合组中传统算法与后量子算法的组合关系："
             "任何一路秘密错误都会导致派生密钥不同，最终由 AES-GCM 认证失败暴露。")

    document.add_heading("4.3 后量子签名与混合签名", level=2)
    add_text(document,
             "签名演示支持 ML-DSA、SLH-DSA 与 Falcon 参数集，执行密钥生成、签名、原消息验签和篡改消息重验。"
             "混合签名模式同时生成经典签名与后量子签名，并把算法、公钥与消息绑定到同一签名数据结构，接受规则为两份签名均必须通过。"
             "平台分别篡改消息、传统签名和后量子签名，验证对应结果会被拒绝，避免只验证其中一路而误判整体安全。")

    document.add_heading("五、本地后量子实验站：自建客户端与服务端", level=1)
    document.add_heading("5.1 建立原因", level=2)
    add_text(document,
             "公网站点证书签名尚未普遍后量子化，而被动抓包又无法验证加密握手。为了验证“密钥交换和身份认证均后量子化”的完整场景，"
             "平台建立本地实验站，自己生成受控 CA、服务器证书、私钥和 TLS 服务，再由平台作为客户端主动连接。"
             "这样既知道预期身份与预期算法，又能执行负向篡改实验，形成可复核证据。")

    document.add_heading("5.2 证书与服务端构建", level=2)
    for item in [
        "使用支持 PQC 的 OpenSSL 生成 ML-DSA-44/65/87 根证书私钥与自签名根证书。",
        "生成服务器 ML-DSA 私钥和 CSR，再由实验根 CA 签发叶子证书。",
        "证书包含 localhost 与 127.0.0.1 标识，仅用于本机实验，不修改系统信任库。",
        "OpenSSL s_server 以 X25519MLKEM768、SecP256r1MLKEM768 或 SecP384r1MLKEM1024 作为 TLS 1.3 密钥交换组。",
        "服务器仅接受指定的后量子签名算法，并使用 TLS_AES_256_GCM_SHA384 套件。",
        "实验站同时提供本机 HTTP 证据页，展示检测器结果、OpenSSL 会话、证书链和逐项负向实验输出。",
    ]:
        add_text(document, item, style="List Bullet")

    document.add_heading("5.3 双路径验证", level=2)
    add_text(document,
             "实验站使用两条独立路径复核同一服务：第一路是本项目主动检测器，执行混合密钥交换、解密服务器飞行、验证 CertificateVerify 与 Finished；"
             "第二路是 OpenSSL 客户端，显式信任实验根 CA，验证证书链、根自签名、有效期、主机名、服务器用途，并完成 TLS 1.3 会话或完整 HTTPS GET。"
             "HTTPS 模式还逐字节比对返回页面，防止只看到 HTTP 200 就判断内容正确。")
    add_table(document, ["验证项", "具体内容"], [
        ["混合密钥交换", "服务器实际选择指定混合组，key_share 长度与参数规范一致"],
        ["服务器 Finished", "使用握手转录 HMAC 验证，确认派生密钥与服务器飞行一致"],
        ["CertificateVerify", "使用叶子证书 ML-DSA 公钥验证服务器签名，确认服务器持有证书私钥"],
        ["证书链", "OpenSSL 在指定实验 CA 下验证叶子证书与根证书链、自签名和严格 X.509 约束"],
        ["主机名与用途", "验证 localhost/127.0.0.1 匹配及 sslserver 用途"],
        ["完整会话", "TLS 模式验证 TLS 1.3 会话；HTTPS 模式完成 GET 并逐字节比对响应体"],
        ["身份一致性", "比较检测器证书、OpenSSL 会话证书与本地叶子证书的 DER/SHA-256 指纹"],
    ])

    document.add_heading("5.4 负向验证：密钥错误、篡改与降级", level=2)
    add_table(document, ["负向实验", "构造方式", "预期结果"], [
        ["仅经典密钥交换", "客户端从混合组降级为仅 X25519", "服务器握手失败，证明服务端确实限定后量子混合组"],
        ["错误主机名", "用 wrong.invalid 验证同一证书", "OpenSSL 报 hostname mismatch，身份绑定有效"],
        ["证书签名篡改", "翻转 DER 证书最后一个签名字节，保持 OID 和长度不变", "证书链验证报 signature failure，证明不是只看长度/OID"],
        ["消息或签名篡改", "修改签名消息或签名字节后重新验证", "ML-DSA/ECDSA/RSA 等验签失败"],
        ["错误方案/算法不匹配", "用 ML-DSA-44 方案验证 ML-DSA-65 证书与签名", "报方案与证书公钥不一致，判定 failed"],
        ["错误公钥或私钥", "用非对应公钥验签或用错误密钥解密", "签名方程不成立或 AEAD/Finished 校验失败"],
        ["异常 key_share", "构造长度正确但内容错误的 ECDH 点或 ML-KEM 密文", "解析、解封装、AEAD 或 Finished 环节失败"],
    ])
    add_text(document,
             "其中“长度/OID 不变但篡改最后一个签名字节”的实验最直接地说明了平台验证数据本身的方式：算法标识没有变化，"
             "证书长度没有变化，但证书签名的数学验证失败，因此必须被拒绝。同理，在 TLS 深度检测中，错误密钥或错误密文"
             "不会改变可见字段名称，却会导致共享秘密、AEAD 标签或 Finished HMAC 不一致。")

    document.add_heading("六、检测结果与报告内容", level=1)
    add_text(document, "平台当前可将检测结果组织为会话级、算法级和证据级三类信息。报告包括：")
    for item in [
        "通信基本信息：目标主机、端口、会话方向、协议版本、抓包时间或主动检测时间。",
        "ClientHello 内容：SNI、ALPN、支持版本、密码套件、签名算法、supported_groups 和客户端 key_share 组。",
        "ServerHello 内容：实际选择组、组 ID、密码套件、服务器 key_share 长度与规范长度比对结果。",
        "密钥交换结论：经典 ECDH、纯 ML-KEM、经典—后量子混合，以及是否完成服务器侧密码学验证。",
        "证书信息：主体、签发者、有效期、签名算法、公钥算法、公钥长度、签名长度、证书链、指纹和获取方式。",
        "身份验证结论：CertificateVerify 是否通过、Finished 是否通过、服务器是否证明持有证书私钥。",
        "异常与负向结果：长度不一致、OID 与数据不符、未知签名方案、后量子协商失败、协议降级、篡改被拒绝等。",
        "支持矩阵：逐组发起连接，统计服务器对 X25519MLKEM768、SecP256r1MLKEM768、MLKEM768 等组的支持情况。",
        "导出形式：界面摘要、JSON 结构化结果、逐字段说明和完整原始报文文本。",
    ]:
        add_text(document, item, style="List Bullet")

    document.add_heading("七、当前结论与后续扩展", level=1)
    add_text(document,
             "本项目已经形成“抓包观察—主动验证—标准向量演示—本地闭环实验”的完整链路。对于现网站点，"
             "平台能够准确区分混合密钥交换与经典证书签名，避免过度结论；对于可控本地环境，平台能够真实使用"
             "ML-KEM 混合交换与 ML-DSA 证书签名，并通过证书链、主机名、完整会话和篡改实验验证其有效性。")
    for item in [
        "继续扩展 IKEv2/IPSec、SSH 后量子协商字段的专项解析，形成跨协议支持矩阵。",
        "增加更多标准测试向量和实现交叉验证，覆盖不同库版本的 ML-KEM 与 ML-DSA 编码差异。",
        "在获得明确授权和所需密钥材料的条件下，扩展可解密会话的取证分析能力。",
        "增强批量站点扫描与统计图表，按行业、协议、证书类型和混合组部署情况输出迁移态势。",
        "继续跟踪 IETF 混合组、复合证书和 CA 生态标准演进，动态更新 OID 与长度表。",
    ]:
        add_text(document, item, style="List Bullet")

    document.add_heading("附录：主要实现位置", level=1)
    add_table(document, ["功能", "主要文件"], [
        ["桌面主界面与会话/结果展示", "main.py"],
        ["TLS 解析、主动检测与深度验证", "modules/pqc_detect.py"],
        ["抓包与被动 PQC 证据判断", "modules/pqc_passive.py、modules/pcap_analysis.py、modules/tls_parser.py"],
        ["后量子算法演示", "modules/pqc_demo.py、modules/pqc_demo_ui.py、modules/mlkem_trace.py"],
        ["本地实验站管理与服务", "pqc_lab/lab.py、pqc_lab/tls_frontend.py、modules/pqc_lab_ui.py"],
        ["TCP/UDP 签名消息实验", "pqc_lab/signed_messages.py"],
        ["回归测试", "tests/test_pqc_detect.py、tests/test_pqc_authenticity.py、tests/test_pqc_lab_ui.py 等"],
    ])

    document.save(OUTPUT)
    return OUTPUT


if __name__ == "__main__":
    print(build_document())
