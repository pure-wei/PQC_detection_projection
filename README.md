# 密码算法分析工具

基于 Python + PySide6 开发，**跨平台**（Windows / Linux / macOS 均可直接运行），核心算法与界面完全解耦，可脱离 GUI 复用。

本项目已整合 2026-10-07 导入的个人工作：IPsec 抓包解析与 IKE 协商图、后量子检测验证修复、可独立启动的本地 PQC 实验站。合并范围、修复和验证结果见 [个人工作合并分析](docs/2026-10-07-contribution-merge.md)，实验搭建见 [PQC 实验站说明](pqc_lab/README.md)。现有实时抓包、主动复测取消、混合签名和算法计算展示保留。

Linux Conda `code` 环境已更新至 OpenSSL 3.6.5；多协议扩展后完整测试 **351 项通过、无跳过**，包含真实 PQC 握手、HTTPS、TCP/UDP 消息签名、负向验证、并发和实验站界面测试。安装配置见 [code 环境补测记录](docs/2026-10-07-code-pqc-validation.md)，最新实测与截图见 [多协议验证记录](docs/2026-10-07-pqc-multilayer-validation.md)。

**展示本地实验：** 打开主界面，在首页顶部点击「进入本地实验站 →」，然后点击「启动实验并展示网页」。顶部「本地后量子实验站」菜单和「② 本地后量子实验站」页签也可进入。页面支持选择 HTTPS、TLS 握手、TCP/UDP 签名消息、交换组和数字签名，并显示实际通信结果及证据文件，见 [实验站页面说明与截图](docs/2026-10-07-pqc-lab-ui.md)。

## 一、功能介绍

| 页签 | 功能 |
|------|------|
| ① TLS 1.3 后量子检测 | 主动握手探测 HTTPS 站点的密钥交换是否为抗量子算法（X25519MLKEM768 等），并解析证书签名/公钥算法，分层给出结论与总体判定 |
| ② 本地后量子实验站 | HTTPS / TLS 1.3 / TCP / UDP 四种真实实验；3 种混合交换组，17 种后量子消息签名与可选经典混合签名，逐项验证及证据展示 |
| ③ 协议分析与抓包 | 导入或现场抓取 pcap；按 TLS 会话并列展示抓包观察与主动后量子复测；保留协议时序图和报文列表 |
| ④ 后量子算法演示 | 独立 ML-KEM、ECDH + ML-KEM 混合加密、后量子签名，以及传统算法 + 后量子算法的混合签名验签 |
| ⑤ 后量子算法对比 | 对照 X25519、ECDH、Ed25519、ECDSA、RSA-PSS、SM2，展示四类后量子算法的用途、公钥与输出大小、数学基础、标准状态 |
| ⑥ 国密 SM2 / SM3 | SM2密钥对生成、SM3 摘要、SM2 签名（SM3withSM2）、验签、公钥加密 / 私钥解密（C1C3C2），多格式消息与文件导入 |
| ⑦ 常用编码转换 | Base64 / Base64URL / HEX（大小写）/ UTF-8 / URL 编解码，多格式一键互转 |
| ⑧ 证书分析 | 解析 PEM / DER 证书：版本、序列号、签名算法、签发者、有效期、公钥、指纹、自签名判断，兼容国密 SM2 证书 |
| ⑨ 对称加解密 | SM4 / AES（128/192/256），ECB / CBC / CFB / OFB / CTR / GCM，PKCS7 填充，随机密钥/IV 生成 |
| ⑩ 摘要 / HMAC | SM3 / MD5 / SHA-1 / SHA-224/256/384/512 一键全算，HMAC 消息认证码，支持文本 / 文件 |

### ① TLS 1.3 后量子检测
- 输入域名或 URL（也支持 `host:port`），点击「开始检测」即可对站点做一次**主动握手探测**，分两层下结论，不给出笼统的"安全/不安全"：
- **检测模式默认是「深度验证」**：验证服务器侧 TLS 1.3 握手 —— 用本方 ML-KEM 私钥解封装服务器 key_share 里的密文、做 ECDH，拼出混合共享密钥；按 RFC 8446 派生握手流量密钥（HKDF-Extract / HKDF-Expand-Label）；解密服务器的加密飞行（EncryptedExtensions / Certificate / CertificateVerify / Finished）；最后校验 Finished 的 HMAC 与 CertificateVerify 的签名。该模式验证服务器身份，不发送客户端 Finished，因此不建立可用于 HTTP 请求的完整连接。
  若服务器不支持该流程（例如只支持 TLS 1.2、返回 HelloRetryRequest、或用了我们没提供 key_share 的组），会**自动退回快速证据判定**，并在结论里明确标注「未验证」——两种强度不会混为一谈。需要只看证据时，可把模式切到「快速检测（仅读 ServerHello）」。
  - **传输层（密钥交换）**：构造 ClientHello 时把混合抗量子组 `X25519MLKEM768` / `SecP256r1MLKEM768` 排在前面，后面跟 `X25519` / `secp256r1` 兜底；读 ServerHello 的 `key_share` 扩展，看服务器**实际选了哪个组**——这是直接证据，不是推测。再用 IANA/NIST 长度表交叉校验（`X25519MLKEM768` 的 key_share 体必须是 1124 字节），长度对不上即标为"标识与数据不符"。
  - **证书层（身份认证）**：抓取服务器证书并解析**真实字节**——签名算法 OID、公钥算法 OID、公钥与签名的实际长度，与 FIPS 203/204/205 参数表比对。OID 只是标签，长度不符即"可能伪造"（例如 OID 声称 ML-DSA-65 但公钥只有 256 字节）。
- 页面顶部有一条按结论着色的**总体判定横幅**（双层算法与服务器握手已验证 / 部分抗量子 / 本次连接未观察到抗量子协商与认证 / 未能判定），下面再分传输层、证书层两张卡片给出证据，详情见表格。单次探测只描述当前连接，不能证明一个站点的所有入口均不支持某算法。
- **证书层检测为必选项**：界面上不提供开关（该选项已隐藏），每次检测都会自动抓取并分析服务器证书，保证结论始终是两层合一的完整结论。
- 检测在后台线程执行，界面不卡顿；结果表格支持右键复制；可导出 JSON（含分层结论与逐项证据）。
- 页面下方「交互细节」页签只展示**交互框架**：一行一条 TLS 记录，给出方向、记录类型、长度，以及加密记录解密后的长度与所含握手消息名（EncryptedExtensions / Certificate / CertificateVerify / Finished 等），下面是传输层、验证强度、证书层、综合结论的摘要。可与「运行日志」页签切换，两者之间用可拖拽分隔条调整高度。
- **详细报文自动落盘**：每次检测都会把「交互框架 + 原始报文（逐条 TLS 记录 hex dump，加密记录附解密后明文）+ 逐字段说明」写入 `pqc_logs/pqc_detail_<目标>_<时间戳>.txt`（目录已在 `.gitignore` 中忽略），日志里会打印文件路径；也可用工具栏的「导出详细报文」另存到指定位置。导出 JSON 时同时给出 `interaction_raw`（原始字节）与 `interaction_verbose`（逐字段说明）。
- 也可直接把 `.pem / .crt / .cer / .der` 证书文件拖到本页（或点「从证书文件检测…」），只做证书层检测。
- 使用 `pqcrypto==0.3.0` 现场生成真实 ML-KEM 公钥，用 `cryptography` 生成 ECDHE 公钥，不依赖本机 OpenSSL 支持 ML-KEM。`X25519MLKEM768` 的 share 顺序为 ML-KEM 公钥 ‖ X25519 公钥；`SecP256r1MLKEM768` / `SecP384r1MLKEM1024` 为 ECDHE 公钥 ‖ ML-KEM 公钥。旧版 Kyber 草案标识仅用于识别，不参与主动支持矩阵。
- ClientHello 同时提供 **ML-DSA / SLH-DSA 抗量子签名算法**（否则只配了抗量子证书的服务器会直接以 alert 40 拒绝握手）；证书抓取优先用 Python ssl，遇到本机 OpenSSL 3.0 不认识的证书签名算法（如 ML-DSA）时**自动回退到 `openssl s_client -showcerts`**（需 OpenSSL 3.5+，会自动在 PATH 与常见安装路径中查找）。
- 想亲眼看到"完全抗量子"的结论，可以在本机造一个实验服务端（需要 OpenSSL 3.5+）：

  ```bash
  openssl req -x509 -newkey ML-DSA-65 -keyout key.pem -out cert.pem -days 30 -nodes -subj "/CN=pqc.local"
  openssl s_server -accept 8443 -cert cert.pem -key key.pem -groups X25519MLKEM768:x25519 -www
  ```

  然后在页面里检测 `127.0.0.1:8443`，若服务器握手验证通过，应得到「双层抗量子算法与服务器握手已验证」；检测器仍明确标注 CA 信任未验证。

### ② 本地后量子实验站
- 第二个页签可选择 HTTPS、TLS 握手、TCP 签名消息或 UDP 签名消息，以及各模式支持的算法。TLS 支持 3 种混合交换组和 ML-DSA-44/65/87；消息支持 17 种后量子签名，并可组合 5 种经典签名。TCP/UDP 消息为明文，使用本地固定公钥验签；页面明确区分内容加密与数字签名。提供启动、网页展示、重测和停止操作。操作与截图见 [实验站页面说明](docs/2026-10-07-pqc-lab-ui.md)。

### ③ 协议分析与抓包
- 新增 IKEv1 / IKEv2、ESP、AH 与 UDP 4500 NAT-T 的协议识别、概要、字段树和过滤；IKE 会话可查看协商时序图。ESP 和 IKE 加密载荷只显示可见头部，不声称已解密或完成认证。可导入 `samples/ipsec_demo.pcap` 查看合成演示报文。
- 可导入或拖入 pcap / pcapng；也可选择网卡、BPF 过滤条件（默认 `tcp`，留空抓全部协议）和 1–300 秒时长现场抓包。最多 10000 包，可手动停止；结束后保存为 pcap 并自动分析。现场抓包需要系统抓包权限；Windows 还需可用的抓包驱动。
- TLS 会话区列出抓包里可解析的各条 TLS 握手。被动结论只表示**该连接观察到**的 ServerHello 协商组，并核对 `key_share` 长度；缺包、未解析到协商组或长度不符时显示“无法判断”。普通 TLS 1.3 pcap 的证书消息已加密，证书层显示“无法观察”。
- 点击「对该目标主动复测」才会向抓包 SNI（若无 SNI 且能确认连接方向，则向服务器 IP）及原端口发起新的深度探测。主动结果与抓包证据并排保留，并明确标注**另一次连接**；主动检测优先使用同一次深度握手解密取得的证书链；未取得时再单独连接获取，界面和 JSON 会标注来源。完全双层判定要求长度一致、整条提供的证书链使用后量子算法且本次服务器握手验证通过；CA 信任、域名、有效期和证书链签名不属于检测器的验证范围。可点击「停止复测」取消后续探测步骤。
- 「导出后量子证据 JSON」按 TLS 会话分别保存抓包观察和主动复测结果；未复测的会话在 `active_probe` 中为 `null`。
- 两种原有视图继续可用：密钥协商时序图，以及 Wireshark 式报文列表和字段树。对明文证书握手可解析证书，TLS 1.3 的加密证书需要会话密钥才能从 pcap 解读；当前抓包页尚不支持导入密钥日志。

### ④ 后量子算法演示
- 在「① ML-KEM 密钥封装」选择 ML-KEM-512 / 768 / 1024，独立运行密钥生成、封装和解封装。运行后自动打开「参数与计算过程」：左侧选择步骤或变量，右侧显示公式、本轮实际输入输出和计算示例；「执行摘要」保留长度、秘密一致性和篡改结果。此页无需输入消息。
- 计算详情包含 n、q、k、η1 / η2、du / dv、环及编码长度；展示随机种子 d / z / m、SHA3 / SHAKE 派生、矩阵拒绝采样的候选与接受记录、CBD 噪声、每层 NTT / 逆 NTT、向量乘积、压缩和小端编码。矩阵及多项式的全部 256 个系数均可展开，字节以完整十六进制显示。解封装展示消息恢复、重加密密文比对，以及正常与篡改密文的候选秘密、隐式拒绝秘密和最终选择。运算对应 [NIST (2024/08), FIPS 203，算法 5–21](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)。
- 在「② 混合加密」输入 UTF-8 消息，选择 X25519 / P-256 / P-384 与 ML-KEM-512 / 768 / 1024（共 9 种组合），点击一次运行。每次现场生成临时密钥，双方协商的秘密经 HKDF-SHA256 组合为 AES-256-GCM 密钥。分步展示公钥和封装密文长度、解密原文、共享秘密一致性及篡改拒绝结果。这是离线教学流程，不是 TLS 实现或可持久化的文件加密格式。
- 混合加密的「参数与计算过程」复用本轮实际 ML-KEM 运算，再展示 ECDH 秘密与 ML-KEM 秘密拼接得到的 IKM、salt、info、HKDF 的 PRK 与派生 AES 密钥，以及实际 nonce、AAD 和加密结果。HKDF 展开使用 [RFC 5869 (2010/05), §2.2–2.3](https://www.rfc-editor.org/rfc/rfc5869.html#section-2.2) 的规则。
- 在「③ 后量子数字签名」选择现有任意 ML-DSA、SLH 类或 Falcon 参数组，运行后自动打开「参数与计算过程」，展示本轮实际密钥、消息、签名分量及数学验签；「执行摘要」保留长度、原消息和改动消息的验证结论。
- ML-DSA 展示 n / q / k / l / η / τ / β / γ1 / γ2 / ω，解码本轮 ρ、秘密向量、z、h、挑战；逐层 NTT、矩阵乘积、公开密钥关系、由 z−c·s1 重建的实际掩码 y、承诺和挑战比对。公式对应 [NIST (2024/08), FIPS 204，算法 6–8、23–48](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)。
- SLH 类展示本轮种子与随机化值 R、摘要和 FORS 叶索引、秘密叶、完整认证路径、WOTS+ 签名/验签链及各层 XMSS 根；全部 12 组参数均可运行。本项目实际调用 `pqcrypto` 的 SPHINCS+ simple 后端，直接签署原始消息，FORS 索引按低位优先读取；与 FIPS 205 的外部消息格式不同，详情会注明这一点。参见 [PQClean SPHINCS+ 后端源码](https://github.com/PQClean/PQClean/tree/master/crypto_sign) 和 [NIST (2024/08), FIPS 205，表 2、附录 A](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf)。
- Falcon 展示 512 / 1024 维参数、实际 nonce、公开多项式 h、密钥关系、压缩签名 s2、SHAKE256 哈希到点、环乘积、恢复 s1 及平方范数检查，全部系数可查看。[Falcon 实现，codec/common/vrfy](https://falcon-sign.info/impl/)
- 在「④ 混合数字签名」选择 Ed25519、ECDSA-P256 / P384 或 RSA-PSS-2048 / 3072，再选择现有任一后量子签名算法。每次生成两组临时密钥；两份签名共同绑定算法名称、两份公钥和消息，验签时必须**传统签名 AND 后量子签名都通过**。同时展示改动消息、篡改传统签名、篡改后量子签名的独立验签结果，以及两份公钥、签名的字节数和按需展开的 Base64。
- 混合签名详情展示实际的版本、算法名、公钥、消息及 8 字节大端长度前缀，再分别展开两个组件的计算。传统部分包含 Ed25519 种子展开、确定性 nonce 和验签点；ECDSA 的 r / s、摘要、等价 nonce 与验签点；RSA-PSS 的真实盐、MGF1、EM 和摘要比对。最后展示正常与三种篡改下的 AND 结果。[RFC 8032 (2017/01), §5.1](https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1)、[FIPS 186-5 (2023/02), §6](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf)、[RFC 8017 (2016/11), §8.1–9.1](https://www.rfc-editor.org/rfc/rfc8017.html#section-8.1)
- 混合签名采用本项目的离线教学双签名格式；核心接口 `sign_hybrid_message(message, pq_algorithm, classical_algorithm)` 生成公开签名数据，`verify_hybrid_signature(message, signature_data)` 仅用公开数据验签。它与 IETF Composite ML-DSA 的编码格式不同，不能用于该规范的互通测试。标准化组合见 [Composite ML-DSA (2026/04), §2–4](https://www.ietf.org/archive/id/draft-ietf-lamps-pq-composite-sigs-19.html)。
- 混合加密与签名的输入消息限 4096 字节（UTF-8），界面会在运行前提示超限。
- 运行演示时关闭主窗口，会等待当前密码运算完成后自动退出，避免在运算中销毁后台线程。
- 混合加密与签名页的输入区、演示区之间可以拖动分隔条，计算详情的步骤树与数值区也可调整宽度。完整 Base64 公钥、封装密文、加密密文及签名按需展开。
- 计算详情按教学用途显示本轮临时随机种子、私钥中间量与共享秘密；只在内存和界面中保留，不自动保存或写入日志，重试前清除上次详情。签名生成仍由原生库执行，数学重放必须与原生验签一致，不一致即报告失败。
- 详情区明确区分实际解码值、确定性重算值和代数重建值。ML-DSA 的原始 ξ / rnd / ρ′、SPHINCS+ 的 optrand、Falcon 的高斯采样随机流与未接受的重试不由库接口返回，界面不会生成替代值冒充。ECDSA 的等价 nonce 从实际签名和临时私钥反推；RSA-PSS 的实际盐从 EM 中恢复。公开 `sign_hybrid_message` 接口继续只输出公开数据，教学 trace 仅由 demo 接口返回。
- ML-KEM 使用可记录内部运算的 Python 教学实现，结果与 `pqcrypto==0.3.0` 双向交叉校验；不匹配即报告失败。它用于教学展示，不是恒定时间的生产实现。签名仍调用 `pqcrypto`。测试使用固定版本的 [NIST ACVP keyGen 数据](https://github.com/usnistgov/ACVP-Server/blob/15c0f3deeefbfa8cb6cd32a99e1ca3b738c66bf0/gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json) 与 [encapDecap 数据](https://github.com/usnistgov/ACVP-Server/blob/ad33b3d9504491767f1aa76382464f3b3fa2359e/gen-val/json-files/ML-KEM-encapDecap-FIPS203/internalProjection.json) 逐字节验证三个参数集。Falcon 的标准状态参见下方 NIST 资料。

### ⑤ 后量子算法对比
- 共 13 组代表参数：传统算法包括 X25519、ECDH-P256 / P384、Ed25519、ECDSA-P256 / P384、RSA-PSS-2048 / 3072 和 SM2；后量子算法包括 ML-KEM-768、ML-DSA-65、SLH-DSA-SHA2-128s、Falcon-512。对比用途、公钥字节数、封装密文或签名大小、数学基础与标准状态。
- 表格注明编码口径：EC 公钥使用未压缩点；RSA 公钥使用 SPKI DER，指数为 65537；其余公钥为原始字节。ECDSA 同时列出 DER 签名上限和固定长度的 r‖s 表示；RSA-PSS 的签名长度为模数字节数。参见 [Cryptography EC, 签名与序列化](https://cryptography.io/en/46.0.3/hazmat/primitives/asymmetric/ec/)、[Cryptography RSA, 公钥序列化](https://cryptography.io/en/46.0.3/hazmat/primitives/asymmetric/rsa/) 与 [RFC 8017 (2016/11), §8.1](https://www.rfc-editor.org/rfc/rfc8017.html#section-8.1)。
- Falcon 签名长度可变，表中数值为近似量；不同用途的输出大小不直接代表安全强度。后量子参数与标准状态的出处见下方参考资料。
- 参考：[NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)、[FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)、[FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) 和 [NIST 后量子密码标准化状态](https://csrc.nist.gov/projects/post-quantum-cryptography)。

### ⑥ 国密 SM2 / SM3
- **SM2 签名** / **SM2 验签** / **SM2 加解密**。
- 支持一键生成 SM2 密钥对、SM3 摘要、SM2 签名与验签（SM3withSM2，标准国密曲线，可与其他国密实现互通验签）。
- 消息方式可选「消息M」或「Hash(Za‖M)」；编码支持 HEX / UTF-8 / Base64，可导入文件或直接拖拽。
- 签名支持 r‖s 与 DER 多格式自动识别；加解密采用 C1C3C2 输出，公钥加密 / 私钥解密。

### ⑦ 常用编码转换
- 输入格式支持「自动识别」，在本页粘贴任意 Base64 / Base64URL / HEX / UTF-8 / URL 编码串，选择输入/输出格式后一键互转。

### 协议分析的详细视图
- 支持点击「选择 pcap / pcapng 文件」或直接把文件拖到第 ② 页加载（基于 scapy 解析）。
- 两种视图模式：
  - **① 密钥协商过程（客户端 ⇄ 服务端）**：以时序卡片展示抓包可见的 TLS / TLCP / SSH / CSSH 握手交互及加密套件、SNI/ALPN；TLS 1.3 加密的证书和 Finished 不会凭空显示。支持 TLCP **双向身份鉴别**、SSH 展示 KEXINIT 协商的**双端选定算法**（密钥交换/加密/MAC/压缩/主机密钥）；CSSH（国密 SSH）展示完整国密协商过程与 SM2 验签结论（见下）。
  - **② 报文列表（Wireshark 式）**：逐包明细表，点击任意行弹出完整协议字段树（Ethernet / IP / TCP / UDP / ICMP / ARP / DNS / HTTP / SSH / TLS / TLCP），SSH 包自动标注客户端/服务端角色，可查看 TCP 流原文（Hex + ASCII）。
- 支持协议下拉过滤 + 关键字条件搜索、导出 CSV。
- **CSSH 国密 SSH 专项解析（GM/T 0129-2023）**：Wireshark 等工具无法识别 CSSH（只能看到 TCP），本工具直接深入 TCP 负载字节流检索并重组 CSSH 会话，在「① 密钥协商过程」视图中绘制完整国密握手时序：
  - **协商时序**：版本交换 → KEXINIT（Cookie + 算法列表）→ KEX_REQUEST（random-client）→ KEX_REPLY（服务端双证书 + random-server + SM2 签名）→ KEX（enc(K) 加密主密钥）→ NEWKEYS，每张卡片标注真实抓包包号；
  - **双证书解析**：从 KEX_REPLY 按「签名证书 ∥ 加密证书」提取服务端国密双证书（GM/T 0015 / GB/T 35276），卡片内可查看每张证书详情并一键导出 `.cer`；
  - **SM2 验签（密钥协商有效性验证）**：用签名证书公钥对 M = random-client ∥ random-server 做 SM2 验签（GB/T 35276 DER 签名，用户标识 1234567812345678），协商总结与 KEX_REPLY 卡展示签名值、待签名数据、公钥与验签结论；
  - 协商总结中**只对国密算法高亮显示**（SM2-SM3、curvesm2、SM4、CBC-MAC、HMAC-SM3 等），非国密算法保持普通文本。

### ⑧ 证书分析
- 打开或拖拽 PEM / DER 证书文件（或在输入框粘贴 PEM 文本），点击「解析」。
- 输出版本、序列号、签名算法、签发者、有效期、公钥、指纹、自签名判断；兼容国密 SM2证书。
- 分析结果表格支持**右键复制**（复制该值 / 复制该行 / 复制全部）；可以导出分析结果。

### ⑨ 对称加解密 SM4 / AES
- 算法：SM4 / AES；密钥位长 128 / 192 / 256 位。
- 模式：ECB / CBC / CFB / OFB / CTR / GCM（PKCS7 填充），支持随机密钥 / IV 生成，GCM 模式下可配置 Tag / AAD 认证数据。
- 输入编码 HEX / UTF-8 / Base64 可选，可导入文件或拖拽。

### ⑩ 摘要 / HMAC
- 数据来源：文本（HEX / Base64 / UTF-8 自动识别）或文件（原始字节）。
- 点击「计算全部摘要」一次性输出 SM3 / MD5 / SHA-1 / SHA-224 / SHA-256 / SHA-384 / SHA-512 全部结果。
- 支持 HMAC 消息认证码：选择算法 + 输入密钥后计算。
- 结果表格支持**右键复制**（复制该值 / 复制该行 / 复制全部摘要）；HMAC 结果可**右键复制**。

## 二、使用方法

1. 启动程序后，在窗口上方页签栏选择要使用的模块。
2. **输入**：多数模块支持直接在输入区粘贴文本（HEX / UTF-8 / Base64），也可点击「选择文件 / 拖拽导入…」按钮或直接把文件拖入窗口。
3. **计算 / 解析**：点击各页的转换 / 签名 / 验签 / 加密 / 解密 / 解析 / 计算摘要等操作按钮。
4. **结果**：逐字节审查可看输入区下方的「字节数 / 前若干字节」提示；表格结果支持右键复制。
5. 协议分析流程：打开 pcap → 选择视图模式 → ① 模式点「协商过程总结 / 关键参数」查看握手时序与协商算法（CSSH 国密 SSH 抓包会自动识别并展示国密协商过程、双证书与 SM2 验签结论），② 模式点击报文行查看字段树，可用顶部过滤下拉框与搜索框缩小范围。
6. 任意时刻可用各页「清空」按钮复位（协议分析页同时清空统计、表格与物联时序图）。

## 三、不同系统的运行方式

环境要求：**Python 3.9+**与 pip。依赖清单见 `requirements.txt`（PySide6、gmssl、scapy、cryptography、pqcrypto、matplotlib）。

### Windows
- 双击 `run.bat` 一键启动：自动检查 Python 与依赖，首次运行自动 `pip install -r requirements.txt`，随后启动主程序。
- 或手动运行：
  ```bat
  pip install -r requirements.txt
  python main.py
  ```

### Linux（Ubuntu / Debian 等桌面发行版）
- 双击 / 执行 `run.sh` 一键启动（自动检查并安装依赖）：
  ```bash
  chmod +x run.sh
  ./run.sh
  ```
- 或手动运行：
  ```bash
  python3 -m pip install -r requirements.txt
  python3 main.py
  ```
- 注意：需在图形会话（X11 / Wayland）中运行；若报 Qt 缺少系统库，先安装：
  ```bash
  sudo apt install libxcb-cursor0 libxkbcommon-x11-0 libegl1
  ```
- WSL 下若 Linux 没装中文字体，程序会自动尝试加载 `/mnt/c/Windows/Fonts/msyh.ttc`；若该文件不存在，可安装 `fonts-noto-cjk` 后重启程序。

### macOS
- 手动运行（与 Linux 相同）：
  ```bash
  python3 -m pip install -r requirements.txt
  python3 main.py
  ```

### 无显示环境（仅自检 / 服务端）
- Linux 无头环境可加 `QT_QPA_PLATFORM=offscreen` 做启动自检（不做界面显示）：
  ```bash
  QT_QPA_PLATFORM=offscreen python3 main.py
  ```

## 四、目录结构

```
CryptoAnalysisTool/
├── main.py                  # 主程序（PySide6 界面，九个页签）
├── run.bat                  # Windows 一键启动脚本（自检依赖）
├── run.sh                   # Linux 一键启动脚本（自检依赖）
├── requirements.txt         # Python 依赖清单
├── 项目说明文档.md           # 项目说明文档（功能、原理、验证方法与实测数据）
├── tests/
│   ├── test_pqc_detect.py   # 抗量子检测模块离线自检（python tests/test_pqc_detect.py）
│   ├── test_pqc_demo.py     # 后量子演示核心逻辑测试
│   ├── test_hybrid_signature.py # 混合签名、篡改、缺失组件与公钥绑定测试
│   ├── test_mlkem_trace.py  # 官方向量、NTT 环乘积、原生互操作与计算记录测试
│   ├── test_signature_trace.py # 全部签名参数组、实际重放、篡改与 RFC 向量测试
│   ├── fixtures/mlkem_acvp_examples.json # 固定来源的 NIST 测试数据与哈希
│   └── test_pqc_demo_ui.py  # 后量子演示界面离线测试
├── pqc_logs/                # 抗量子检测的详细报文日志（自动生成，已在 .gitignore 忽略）
└── modules/
    ├── sm2_sm3.py           # 国密 SM2 密钥/签名/验签/加解密、SM3 摘要、多格式签名公钥归一化
    ├── codec.py             # 常用编码转换核心逻辑
    ├── sym_crypto.py        # SM4 / AES 对称加解密（ECB/CBC/CFB/OFB/CTR/GCM + PKCS7）
    ├── hash_tools.py        # SM3/SHA 族/MD5 摘要 + HMAC 核心逻辑
    ├── pcap_analysis.py     # pcap 协议分析（包统计/分布/明细、协议过滤搜索、SSH 报文列表反标）
    ├── cert_analysis.py     # X.509 证书分析核心逻辑（兼容国密 SM2 曲线 1.2.156.10197.1.301）
    ├── tls_parser.py        # TLS / TLCP 明文握手深度解析（记录/握手切分、TCP 流按 seq 重组、ClientHello/ServerHello 加密套件与 SNI/ALPN 扩展、证书链含国密 SM2 证书、ServerKeyExchange、Client⇄Server 双向流重组、TLCP 拨号业务通道前置报文跳过）
    ├── cssh_parser.py       # CSSH 国密 SSH（GM/T 0129-2023）解析：TCP 负载识别 CSSH-1.0 会话、传输层分帧重组、KEXINIT/KEX_REQUEST/KEX_REPLY/KEX 解析、服务端双证书提取、SM2 验签（随机数 ∥ 签名值）与国密算法高亮
    ├── handshake_view.py    # 握手时序图：TLS/TLCP/SSH/CSSH 协商事件、协商结果汇总（含 SSH 双端协商算法、CSSH 双证书/验签/国密算法高亮）
    ├── handshake.py         # 握手消息解析辅助
    ├── pqc_detect.py        # 抗量子（PQC）检测：主动握手探测 key_share 组、证书层 OID + FIPS 参数长度校验、结论与 JSON 导出
    ├── pqc_demo.py          # 四类后量子算法演示、混合加密、混合签名与传统/PQC 参数对比
    ├── pqc_demo_ui.py       # 后量子算法演示与对比的 Qt 页面
    ├── mlkem_trace.py       # FIPS 203 教学计算与真实中间量记录
    ├── mlkem_trace_ui.py    # KEM 与签名共用的参数/步骤/完整数值查看器
    ├── ml_dsa_trace.py      # ML-DSA 多项式、签名重建与验签
    ├── slh_dsa_trace.py     # SPHINCS+ simple 的 FORS/WOTS+/超树重放
    ├── falcon_trace.py      # Falcon 压缩解码、环乘积与范数验签
    ├── classical_signature_trace.py # Ed25519/ECDSA/RSA-PSS 教学重放
    └── packet_parser.py     # 单包全层字段树（Ethernet/IP/TCP/UDP/ICMP/DNS/HTTP/SSH/TLS/TLCP）+ 全 TCP 流级解析（含 SSH/CSSH 客户端/服务端方向判定）+ Hex+ASCII 转储
```

## 五、说明

- SM2 采用标准国密曲线，签名算法 SM3withSM2，可与其他国密实现互通验签。
- 核心算法与界面完全解耦，`modules/` 下均为纯 Python 逻辑，可脱离 GUI 复用或二次开发。
- CSSH 国密 SSH 解析依据 GM/T 0129-2023：自动定位 `CSSH-1.0` 会话、按 RFC 4253 分帧重组，提取服务端双证书并完成 SM2 验签（验签依赖 `gmssl`；未安装时结论显示为「未能验签」并提示，不影响其余解析）。
- 本项目以 **GPL-3.0** 协议开源，详见 `LICENSE`；仓库不包含真实抓包测试数据。

## 六、算法对比与混合签名参考资料

- [RFC 7748, 2016/01] IETF. “Elliptic Curves for Security.” [X25519 参数](https://www.rfc-editor.org/rfc/rfc7748.html)。
- [RFC 8032, 2017/01] IETF. “Edwards-Curve Digital Signature Algorithm (EdDSA).” [Ed25519 参数](https://www.rfc-editor.org/rfc/rfc8032.html)。
- [RFC 8017, 2016/11] IETF. “PKCS #1: RSA Cryptography Specifications Version 2.2.” [RSA-PSS](https://www.rfc-editor.org/rfc/rfc8017.html)。
- [GB/T 32918.2, 2016/08] 国家标准委. “信息安全技术 SM2椭圆曲线公钥密码算法 第2部分：数字签名算法.” [标准信息](https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=6F1FAEB62F9668F25F38E0BF0291D4AC)。
- [Cryptography EC] PyCA. “Elliptic curve cryptography.” [ECDH、ECDSA 与编码](https://cryptography.io/en/46.0.3/hazmat/primitives/asymmetric/ec/)。
- [Cryptography RSA] PyCA. “RSA.” [签名与公钥序列化](https://cryptography.io/en/46.0.3/hazmat/primitives/asymmetric/rsa/)。
- [Composite ML-DSA, 2026/04] IETF LAMPS. “Composite Module-Lattice-Based Digital Signature Algorithm (ML-DSA) for use in X.509 Public Key Infrastructure.” [规范草案](https://www.ietf.org/archive/id/draft-ietf-lamps-pq-composite-sigs-19.html)。
- [NIST PQC] NIST. “Post-Quantum Cryptography.” [参数标准及标准化进展](https://csrc.nist.gov/projects/post-quantum-cryptography)。
