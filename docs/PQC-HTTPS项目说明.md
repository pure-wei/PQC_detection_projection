# PQC-HTTPS 项目说明

> 项目目标：抓取网站 TLS 数据，识别加密算法，判断是否具备抗量子（PQC）能力。

---

## 项目结构

```
PQC_detection_projection/
├── README.md                        # 项目简介与快速上手
├── docs/
│   └── PQC-HTTPS项目说明.md          # 详细项目说明（本文件）
├── tools/
│   └── gen_report.py                # 汇报稿 Word 生成（可选）
├── output/                          # 检测结果输出（JSON + PDF，不入库）
├── pyproject.toml
├── requirements.txt
└── src/
    ├── cli/
    │   └── main.py                  # 命令行入口（4 个命令）
    ├── tls_analysis/
    │   ├── scanner.py               # 统一扫描（抓包+算法解析+抗量子判定）
    │   ├── capture.py               # 批量扫描编排（多目标 + DataFrame 汇总）
    │   ├── connection.py            # TLS 连接 + 会话信息采集
    │   ├── packet_capture.py        # 深度抓包（hex dump）
    │   ├── pqc_detector.py          # OQS 直接 PQC 检测
    │   ├── oqs_provider.py          # OQS 环境检查 + TLS 组映射
    │   ├── cert_analyzer.py         # 证书深度解析（X.509 DER）+ NIST 数据校验
    │   ├── cipher_suite_parser.py   # 密码套件名称解析
    │   ├── fingerprint.py           # JA3 指纹
    │   └── verification.py          # 抗伪造验证 + key_share 大小校验
    ├── utils/                       # 日志 / 配置 / 翻译 / PDF 报告
    └── web/                         # Flask Web 界面
```

## 四个核心命令

| 命令 | 功能 | 分析层面 |
|------|------|----------|
| `scan` | 统一安全扫描 — 一次完成抓包/算法解析/抗量子判定 | 综合（三层合一） |
| `pcap` | 深度抓包 — 抓取 TLS 握手全部 hex 原始数据 | 原始包层 |
| `detect` | PQC 握手检测 — 判断网站 TLS 是否支持抗量子密钥交换 | 传输层 |
| `cert` | 证书深度分析 — 识别签名算法、公钥类型、是否抗量子 | 证书层 |

---

## 四个命令的关系

`scan` 是 `pcap` + `detect` + `cert` 的一体化封装，一次调用即可得到分层报告与综合抗量子结论。三个分层命令的关系如下：

```
┌─────────────────────────────────────────────────┐
│                                                 │
│  pcap — 原始数据层                               │
│  抓取所有 TLS 记录的 hex 原始数据                  │
│  （最底层，看到的是电讯信号级别的数据）             │
│                     │                           │
│                     ▼                           │
│  detect — 传输层                                 │
│  分析 ClientHello/ServerHello 的握手参数          │
│  判断密钥交换是否使用了 PQC 算法                   │
│                     │                           │
│                     ▼                           │
│  cert — 证书层                                   │
│  解析 ServerHello 里的 X.509 证书                 │
│  识别签名算法、公钥类型                            │
│  （最上层，看到的是身份和信任体系）                │
│                                                 │
└─────────────────────────────────────────────────┘
```

| 维度 | scan | pcap | detect | cert |
|------|------|------|--------|------|
| 分析对象 | 全流程 | TLS 原始记录 | TLS 握手参数 | X.509 证书 |
| 回答的问题 | 综合抗量子结论 | 握手收发了哪些数据？ | 支不支持 PQC？ | 证书算法/公钥类型？ |
| 数据来源 | 三者合并 | TLS 原始 hex 记录 | key_share 扩展 | X.509 证书 |
| 输出格式 | 分层报告 + 综合结论 | hex dump 逐条解析 | 判断 + 证据 | 结构化分析报告 |
| PQC 检测 | 传输层 + 证书层 | 不直接检测 | 密钥交换层面 | 证书算法层面 |

---

## 命令一：`pcap` — 深度抓包

```bash
python -m src.cli.main pcap cloudflare.com
```

### 执行流程

#### Step 1：检测可用抓包方法

```
检查顺序:
  1. openssl 在 PATH 中？ → openssl_msg  可用 ✅（首选）
  2. 系统是 Win10+？      → pktmon      可用（需管理员）
  3. tcpdump 在 PATH 中？ → tcpdump     可用（Linux/macOS）
```

默认选择 `openssl_msg`，最稳定、不需要管理员权限、跨平台。

#### Step 2：运行 openssl s_client -msg

```bash
openssl s_client \
  -connect cloudflare.com:443 \
  -servername cloudflare.com \
  -msg
```

stdin 发送一个简单的 HTTP GET 请求以触发完整的 TLS 握手和应用数据交换。

`-msg` 标志让 openSSL 打印每一条 TLS 记录的 hex dump：

```
>>> TLS 1.3, Handshake [length 0609], ClientHello
    01 00 06 09 03 03 ab 78 2b 31 cb 67 7b 9d df b7 ...

<<< TLS 1.3, Handshake [length 04b6], ServerHello
    02 00 04 b6 03 03 7c 01 0c 89 e4 6f 8c 65 67 de ...

<<< TLS 1.3, ChangeCipherSpec [length 0001]
    14

<<< TLS 1.3, Handshake [length 0a09], Certificate
    0b 00 0a 09 00 00 0a 05 00 03 d5 30 82 03 d1 ...
```

#### Step 3：逐条解析 TLS 记录

正则匹配每一条记录头：

```
r'(>>>|<<<)\s+TLS\s+[\d.]+\s*,\s*(\S+)\s*\[length\s*(\w+)\](?:,\s*(.+))?'
```

| 捕获组 | 含义 | 示例 |
|--------|------|------|
| 第1组 | 方向 | `>>>` 发送 / `<<<` 接收 |
| 第2组 | 内容类型 | `Handshake` / `ChangeCipherSpec` |
| 第3组 | 记录长度（hex） | `0609` → 1549 bytes |
| 第4组 | 握手标签（可选）| `ClientHello` / `ServerHello` |

收集紧随该行的 hex 数据，拼接成完整 hex 字符串。

#### Step 4：识别每条记录的类型

根据 hex 内容的第一个字节判断握手类型：

| hex首字节 | 握手类型 | 含义 |
|----------|----------|------|
| `0x01` | ClientHello | 客户端声明支持的算法列表、TLS 版本、随机数 |
| `0x02` | ServerHello | 服务器选定算法、随机数、会话 ID |
| `0x0B` | Certificate | 服务器的 X.509 证书链（DER 编码） |
| `0x0F` | CertificateVerify | 服务器用证书私钥签名，证明拥有对应私钥 |
| `0x14` | Finished | 握手完整性验证（HMAC over 所有握手消息） |

外层内容类型（从记录头提取）：

| 类型 | 含义 |
|------|------|
| `Handshake (0x16)` | TLS 握手消息 |
| `ChangeCipherSpec (0x14)` | 通知对方切换加密密钥 |
| `ApplicationData (0x17)` | 加密的应用层数据 |
| `Alert (0x15)` | 警告或错误通知 |

#### Step 5：统计汇总

- 统计总收发字节数
- 提取协商的密码套件名（从 `Cipher is XXX`）
- 提取 TLS 协议版本（从 `New, TLSv1.X`）
- 关键记录（ClientHello、ServerHello、Certificate）展示前 120 个 hex 字符

### 输出示例

```
============================================================
TLS Handshake Capture: cloudflare.com:443
Method: openssl_msg
Records: 20 (1607B sent, 4407B recv)
Total: 6014B
Cipher: TLS_AES_256_GCM_SHA384
Protocol: TLSv1.3
------------------------------------------------------------
   1. >>> ClientHello         [1549B]  TLS 1.3
   2. <<< ServerHello         [1210B]  TLS 1.3
   3. <<< ChangeCipherSpec    [   1B]  TLS 1.3
   5. <<< EncryptedExtensions [  10B]  TLS 1.3
   6. <<< Certificate         [2573B]  TLS 1.3  ← 证书链
   7. <<< CertificateVerify   [  79B]  TLS 1.3
   8. <<< Finished            [  52B]  TLS 1.3  ← 握手结束
   9. >>> ChangeCipherSpec    [   1B]  TLS 1.3
  11. >>> Finished            [  52B]  TLS 1.3
  14. <<< NewSessionTicket    [ 238B]  TLS 1.3
  18. <<< Alert (close_notify)[   2B]  TLS 1.3  ← 正常关闭
============================================================

TLS Record Details:
------------------------------------------------------------
  Record 1: >>> Handshake (ClientHello) [1549B] TLS 1.3
    Hex: 01 00 06 09 03 03 ab 78 2b 31 cb 67 7b 9d df b7 ...

  Record 2: <<< Handshake (ServerHello) [1210B] TLS 1.3
    Hex: 02 00 04 b6 03 03 7c 01 0c 89 e4 6f 8c 65 67 de ...

  Record 6: <<< Handshake (Certificate) [2573B] TLS 1.3
    Hex: 0b 00 0a 09 00 00 0a 05 00 03 d5 30 82 03 d1 ...
```

---

## 命令二：`detect` — PQC 握手检测

```bash
python -m src.cli.main detect cloudflare.com
python -m src.cli.main detect baidu.com
python -m src.cli.main detect cloudflare.com --force-fallback   # 强制 CDN 推测模式
```

### 检测原理

分为两层，自动选择：

```
           ┌─────────────────────┐
           │  检查 OQS 是否安装？  │
           └─────────┬───────────┘
                     │
        ┌────────────┴────────────┐
        │ 已安装                   │ 未安装
        ▼                         ▼
   Layer 1: OQS 实测          Layer 2: CDN 推测
   (openssl 主动声明          (Python ssl 连接
    PQC 组，解析               后检查 HTTP 头)
   ServerHello)
        │                         │
        ▼                         ▼
   直接证据                  间接证据
   "key_share: 0x11EC"       "Cloudflare CDN → 支持 PQC"
```

---

### Layer 1：OQS Provider 直接实测（OQS 已安装时）

#### Step 1：发起带 PQC 组的 TLS 握手

```bash
openssl s_client \
  -connect cloudflare.com:443 \
  -servername cloudflare.com \
  -groups x25519_mlkem768:x25519:secp256r1 \
  -msg \
  -tlsextdebug
```

`-groups x25519_mlkem768:x25519:secp256r1` 是关键参数。它在 ClientHello 中告诉服务器：

> "我能用以下三种密钥交换算法，请选择一种：
>  ① X25519MLKEM768（抗量子混合，最优先）
>  ② x25519（经典椭圆曲线）
>  ③ secp256r1（经典 P-256）"

#### Step 2：解析 ServerHello 的 key_share 扩展

从 `-msg` 输出的 hex 数据中，定位 ServerHello 消息体，按照 TLS 1.3 协议结构逐层解析：

```
ServerHello 结构（RFC 8446）:

[Handshake 头]  type(1B) + length(3B)           → 跳过
[legacy_version] 2 bytes                         → 跳过
[random]         32 bytes                        → 跳过
[session_id]     1B len + N bytes                → 跳过
[cipher_suite]   2 bytes                         → 跳过
[compression]    1 byte   (固定 0x00)             → 跳过
[extensions_len] 2 bytes                         → 从这里开始扫描扩展
  ┌─ extension 1:
  │   [type]   2 bytes
  │   [length] 2 bytes
  │   [data]   N bytes
  │     ...如果 type == 0x0033 (key_share):
  │       [group]    2 bytes  ← 服务器选的密钥交换组！
  │       [ke_len]   2 bytes
  │       [ke_data]  N bytes
  └─ extension 2: ...
```

核心代码逻辑：

```python
while pos < end_of_extensions:
    ext_type = read_2_bytes()
    ext_len  = read_2_bytes()

    if ext_type == 0x0033:          # 找到 key_share 扩展
        group_id = read_2_bytes()   # 读服务器选的组 ID
        ke_len   = read_2_bytes()   # 读密钥交换数据长度
        if group_id in PQC_GROUP_IDS:
            return "PQC! " + PQC_GROUP_IDS[group_id]
        else:
            return "Non-PQC: " + hex(group_id)

    pos += ext_len
```

#### Step 3：查表判断

```python
PQC_GROUP_IDS = {
    0x11EB: "X25519MLKEM512",      # IETF 标准 PQC 混合组
    0x11EC: "X25519MLKEM768",      # ← 最常用！Cloudflare 等
    0x11ED: "X25519MLKEM1024",
    0x0239: "Kyber512",             # NIST 原始名称
    0x023A: "Kyber768",
    0x023C: "Kyber1024",
    0x023D: "MLKEM512",            # FIPS 203 标准名称
    0x023E: "MLKEM768",
    0x023F: "MLKEM1024",
    0x2F39: "FrodoKEM-640-AES",    # 备选 PQC 算法
    0x2F3A: "FrodoKEM-976-AES",
    0x2F3C: "FrodoKEM-1344-AES",
}
```

判断逻辑：

| ServerHello key_share group | 含义 | 结论 |
|------------------------------|------|------|
| `0x11EC` | 服务器选了 X25519MLKEM768 | ✅ PQC 支持！直接证据 |
| `0x11EB` | 服务器选了 X25519MLKEM512 | ✅ PQC 支持！ |
| `0x001D` | 服务器选了 x25519 | ✗ 不支持 PQC（选了经典） |
| `0x0017` | 服务器选了 secp256r1 | ✗ 不支持 PQC |

**关键点**：客户端明确提供了 PQC 选项，服务器如选了经典组 = 它不（或不愿）用 PQC。如果选了 PQC 组 = 无可辩驳的直接证据。

---

### Layer 2：CDN 推测（OQS 未安装时的降级方案）

#### Step 1：Python ssl 连接

```python
context = ssl.create_default_context()
with socket.create_connection((host, 443)) as sock:
    with context.wrap_socket(sock, server_hostname=host) as ssock:
        cipher = ssock.cipher()   # 拿到密码套件名
        # → TLS_AES_256_GCM_SHA384
```

#### Step 2：发 HTTP 请求，检查响应头

```python
ssock.sendall(b"GET / HTTP/1.1\r\nHost: cloudflare.com\r\n...")
response = ssock.recv(4096)
# 解析 HTTP 响应头
```

#### Step 3：CDN 识别

| 检测到 | 来源 | 结论 |
|--------|------|------|
| `cf-ray` 头 | Cloudflare CDN | ✅ PQC 支持（2022年起默认启用 X25519MLKEM768） |
| `server: cloudflare` | Cloudflare CDN | ✅ PQC 支持 |
| `x-cache` + `fastly` | Fastly CDN | ✅ PQC 支持（早期采用者） |
| 以上均无 | 未知 | ✗ 未检测到 PQC 支持 |

**注意**：此方法是间接推测，不如 Layer 1 的直接握手验证可靠。

---

### 输出示例

**Layer 2（当前环境，OQS 未安装）：**

```
PQC Detection Result: cloudflare.com:443
============================================================
  Protocol:      TLSv1.3
  Cipher Suite:  TLS_AES_256_GCM_SHA384
  PQC (CDN):     ✓ YES
  CDN Provider:  Cloudflare
  Cert Subject:  cloudflare.com
  Cert Issuer:   Google Trust Services
============================================================
```

**Layer 1（安装 OQS 后）：**

```
PQC Detection Result: cloudflare.com:443
============================================================
  Connection:     ✓ Success
  Protocol:       TLSv1.3
  Cipher Suite:   TLS_AES_256_GCM_SHA384
  PQC Supported:  ✓ YES
  PQC Algorithm:  X25519MLKEM768
  PQC Group ID:   0x11EC
  Key Share Size: 1120 bytes
  Evidence:       ServerHello key_share: 0x11EC (X25519MLKEM768, 1120 bytes)
  Handshake:      1549B sent, 4407B recv
============================================================
```

---

## 命令三：`cert` — 证书深度分析

```bash
python -m src.cli.main cert cloudflare.com
python -m src.cli.main cert cloudflare.com --detailed   # 显示扩展域 OID 详情
```

### 执行流程

#### Step 1：TLS 连接，获取 DER 证书

```
Python ssl 模块
  → socket.create_connection(host, 443)
  → context.wrap_socket()
  → TLS 握手完成
  → ssock.getpeercert(binary_form=True)
  → 得到 DER 编码的 X.509 证书（二进制字节）
```

此处只完成 TLS 握手拿到证书，**不发送 HTTP 请求**，速度快。

#### Step 2：解析 DER 证书结构

使用 `cryptography` 库加载 DER 证书：

```python
cert = x509.load_der_x509_certificate(der_bytes)
```

提取以下字段：

| 字段 | 含义 | 示例 |
|------|------|------|
| `cert.subject` | 证书使用者 | `CN=cloudflare.com` |
| `cert.issuer` | 证书颁发者 | `CN=WE1, O=Google Trust Services` |
| `cert.not_valid_before` | 有效期起始 | `2026-07-08` |
| `cert.not_valid_after` | 有效期截止 | `2026-10-06` |
| `cert.serial_number` | 证书序列号 | |
| `cert.signature_algorithm_oid` | 签名算法 OID | `1.2.840.10045.4.3.2` |
| `cert.public_key()` | 公钥对象 | |
| `cert.extensions` | 扩展域列表 | |

#### Step 3：签名算法识别

拿到 OID 字符串（如 `1.2.840.10045.4.3.2`），查询内置 OID 映射表：

| OID | 算法 | 类型 |
|-----|------|------|
| `1.2.840.113549.1.1.11` | RSA-SHA256 | 经典 |
| `1.2.840.10045.4.3.2` | ECDSA-SHA256 | 经典 |
| `1.2.840.10045.4.3.3` | ECDSA-SHA384 | 经典 |
| `1.2.156.10197.1.301` | SM2-with-SM3 | 国密 |
| `1.3.6.1.4.1.2.267.7.4.4` | ML-DSA-44 (Dilithium2) | 抗量子 |
| `1.3.6.1.4.1.2.267.7.6.5` | ML-DSA-65 (Dilithium3) | 抗量子 |
| `1.3.6.1.4.1.2.267.7.8.7` | ML-DSA-87 (Dilithium5) | 抗量子 |
| `1.3.9999.3.1` | Falcon-512 | 抗量子 |
| `1.3.9999.3.4` | Falcon-1024 | 抗量子 |
| `1.3.9999.6.4.1` | SPHINCS+-SHA2-128s | 抗量子 |

OID 前缀判断规则：
- 以 `1.2.156.10197` 开头 → **国密算法**（SM2 / SM3）
- 以 `1.3.6.1.4.1.2.267` 或 `1.3.9999` 开头 → **抗量子算法**（PQC）

#### Step 4：公钥类型和长度识别

```python
pubkey = cert.public_key()
```

判断公钥类别：

| Python 类型 | 公钥类型 | 长度 | 示例 |
|------------|---------|------|------|
| `rsa.RSAPublicKey` | RSA | 2048 / 4096 bits | 百度 |
| `ec.EllipticCurvePublicKey` | EC (ECDSA) | 256 / 384 / 521 bits | Cloudflare |
| `ed25519.Ed25519PublicKey` | Ed25519 | 256 bits | Google |
| `ed448.Ed448PublicKey` | Ed448 | 456 bits | 少见 |
| 其他 | Unknown（可能是 PQC 公钥） | — | 未来 |

对 EC 公钥，进一步提取椭圆曲线名称：

| 曲线 OID | 曲线名 |
|----------|--------|
| `1.2.840.10045.3.1.7` | secp256r1 (P-256) |
| `1.3.132.0.34` | secp384r1 (P-384) |
| `1.3.132.0.35` | secp521r1 (P-521) |
| `1.2.156.10197.1.301` | SM2 (curveSM2) |

#### Step 5：扩展域检查

遍历证书的所有扩展，分为两类：

**已知扩展**（查表匹配）：

| OID | 名称 | 含义 |
|-----|------|------|
| `2.5.29.15` | Key Usage | 公钥用途 |
| `2.5.29.37` | Extended Key Usage | 扩展用途 |
| `2.5.29.17` | Subject Alternative Name | 域名列表 |
| `2.5.29.19` | Basic Constraints | CA/终端证书 |
| `2.5.29.31` | CRL Distribution Points | 吊销列表地址 |
| `1.3.6.1.5.5.7.1.1` | Authority Info Access | OCSP/CA 地址 |

**自定义扩展**（不在表中的 OID）→ 标记计数：
- OID 前缀属于 PQC 范围 → `pqc_extension_count += 1`
- OID 前缀属于国密范围 → `sm_extension_count += 1`

#### Step 6：安全评估

```
is_quantum_safe = (签名是PQC) 或 (公钥是PQC) 或 (有PQC扩展)

NIST 安全级别估算:
  Dilithium2 / ML-DSA-44  → Level 2
  Dilithium3 / ML-DSA-65  → Level 3
  Dilithium5 / ML-DSA-87  → Level 5
  Falcon-512             → Level 1
  Falcon-1024            → Level 5
  RSA-2048               → Level 1（仅经典计算机有效）
  ECDSA-P256             → Level 1（仅经典计算机有效）
```

### 输出示例

```
==============================================================
  证书深度分析: cloudflare.com:443
==============================================================

  📋 基本信息
     使用者 (CN):    cloudflare.com
     颁发者 (CN):    WE1
     颁发机构:       Google Trust Services
     有效期:         2026-07-08 ~ 2026-10-06
     指纹 (SHA256):  6a704185...

  ✍️ 签名算法
     ECDSA-SHA256
     OID: 1.2.840.10045.4.3.2

  🔑 公钥信息
     类型:           EC
     长度:           256 bits (91 bytes DER)

  🛡️ 安全评估
     抗量子安全:     ✗ 经典 (非抗量子)
     NIST 安全级别:  Level 1
     ℹ️  经典密码 ECDSA-SHA256: 无法抵抗量子计算机攻击
     ℹ️  经典 NIST Level 1 仅对经典计算机有效，量子计算机下不安全

  📎 证书扩展 (共 10 个)
     ✓ Key Usage ⚠️关键
     ✓ Extended Key Usage
     ✓ Basic Constraints ⚠️关键
     ✓ Subject Key Identifier
     ✓ Authority Key Identifier
     ✓ Authority Info Access
     ✓ Subject Alternative Name
     ✓ Certificate Policies
     ✓ CRL Distribution Points
     ✓ Custom OID 1.3.6.1.4.1.11129.2.4.2

     🔍 自定义扩展: 1 个 (可能含 PQC 标识)

  ─────────────────────────────────────────────
  ℹ️  此证书使用经典密码算法，尚无抗量子能力
==============================================================
```

---

## 命令四：`scan` — 统一安全扫描

```bash
python -m src.cli.main scan cloudflare.com
```

`scan` 命令将 `pcap`、`detect`、`cert` 三个命令的分析结果合并为一次调用，输出分层报告与综合抗量子结论。执行流程：

1. 解析 ServerHello 的 `key_share` 扩展，得到实际协商的密钥交换组（组 ID + 组名 + 是否抗量子）；
2. 分解密码套件名，得到密钥交换 / 身份认证 / 对称加密 / 哈希算法；
3. 解析 X.509 证书的签名算法与公钥类型；
4. 综合传输层与证书层，输出抗量子结论。

### 综合结论判定

| 传输层（密钥交换） | 证书层（签名/公钥） | 综合结论 |
|:---:|:---:|---------|
| 抗量子 | 抗量子 | 完全抗量子 |
| 抗量子 | 经典 | 部分抗量子（仅 TLS 密钥交换层） |
| 经典 | 抗量子 | 部分抗量子（仅证书层） |
| 经典 | 经典 | 不抗量子 |

### 输出示例

```
============================================================
  统一安全扫描 【Unified PQC Scan】
  cloudflare.com:443
============================================================
  TLS 协议:      TLSv1.3
  密码套件:      TLS_AES_256_GCM_SHA384
  ── 传输层 (密钥交换) ──
    实际协商组:  X25519MLKEM768 (ID 0x11EC)
    抗量子:      是 (抗量子)
  ── 证书层 (签名/公钥) ──
    签名算法:    ECDSA-SHA256
    公钥类型:    EC
    抗量子:      否 (经典)
  ── 综合结论 ──
    部分抗量子 (仅 TLS 密钥交换层，证书仍为经典)
============================================================
```

---

## 数据驱动校验（对照 NIST）

算法识别不依赖单一标识符，而是用真实数据与 NIST 标准参数交叉校验，避免仅凭组 ID 或 OID 查表就下结论。

### 密钥交换层

`ServerHello` 的 `key_share` 扩展包含组 ID（标签）与密钥交换数据（真实数据）。校验方式：组 ID 对应算法的密钥交换数据长度必须与规范一致。

| 组 ID | 算法 | 密钥交换数据 | 扩展体（组ID+长度+数据） | 抗量子 |
|-------|------|:---:|:---:|:---:|
| `0x11EC` | X25519MLKEM768 | 1120B (32+1088) | 1124B | ✅ |
| `0x11EB` | X25519MLKEM512 | 800B (32+768) | 804B | ✅ |
| `0x11ED` | X25519MLKEM1024 | 1600B (32+1568) | 1604B | ✅ |
| `0x023E` | MLKEM768 | 1088B | 1092B | ✅ |
| `0x001D` | X25519 | 32B | 36B | ❌ |
| `0x0017` | secp256r1 (P-256) | 65B | 69B | ❌ |

### 证书层

证书的签名算法 OID 是标签，实际签名长度与公钥长度是真实数据。校验方式：OID 声明的算法，其公钥/签名长度必须等于 NIST 规定的值，否则标记为「标识与数据不符，可能伪造」。

| 算法 | 公钥长度 | 签名/密文长度 | NIST 级别 | 标准 |
|------|:---:|:---:|:---:|------|
| ML-KEM-512 | 800B | 768B | 1 | FIPS 203 |
| ML-KEM-768 | 1184B | 1088B | 3 | FIPS 203 |
| ML-KEM-1024 | 1568B | 1568B | 5 | FIPS 203 |
| ML-DSA-44 (Dilithium2) | 1312B | 2420B | 2 | FIPS 204 |
| ML-DSA-65 (Dilithium3) | 1952B | 3309B | 3 | FIPS 204 |
| ML-DSA-87 (Dilithium5) | 2592B | 4627B | 5 | FIPS 204 |
| SPHINCS+-SHA2-128s | 32B | 7856B | 1 | FIPS 205 |
| SPHINCS+-SHA2-192s | 48B | 16224B | 3 | FIPS 205 |
| SPHINCS+-SHA2-256s | 64B | 29792B | 5 | FIPS 205 |
| Falcon-512 | 897B | 666B | 1 | Round 4 决选 |
| Falcon-1024 | 1793B | 1280B | 5 | Round 4 决选 |

经典算法（RSA/ECDSA）不查此表，改用 `verification.py` 的真实密码学验签：用上级 CA 公钥逐级验证证书链签名，而非仅比对 OID。

### 参考文档

- **FIPS 203** — ML-KEM（模块格密钥封装机制）标准
- **FIPS 204** — ML-DSA（模块格数字签名）标准
- **FIPS 205** — SLH-DSA / SPHINCS+（无状态哈希签名）标准
- **draft-ietf-tls-hybrid-design / draft-kwiatkowski-tls-ecdhe-mlkem** — 混合后量子密钥交换组 ID

---

## PQC 检测完整矩阵

结合 `pcap` + `detect` + `cert`，可以多维度判断一个网站的 PQC 状态：

| detect 结果 | cert 结果 | 含义 |
|-------------|-----------|------|
| ❌ 不支持 | 经典证书 (RSA/ECDSA) | 普通网站，无任何 PQC |
| ✅ CDN推测 | 经典证书 | Cloudflare 类网站（TLS 层 PQC，证书尚未升级） |
| ✅ OQS实测 | 经典证书 | 同上，直接证据确认 |
| ✅ OQS实测 | PQC 证书 | 完全抗量子（未来形态） |

### 当前实测数据（2026年8月）

| 网站 | TLS 版本 | 实际协商组 | 密码套件 | PQC (传输层) | 证书签名 | 证书公钥 | 综合结论 |
|------|----------|-----------|----------|-------------|----------|----------|----------|
| cloudflare.com | TLSv1.3 | X25519MLKEM768 (0x11EC) | AES-256-GCM | ✅ 直接实测 | ECDSA-SHA256 | EC P-256 | 部分（仅传输层） |
| nist.gov | TLSv1.3 | X25519MLKEM768 (0x11EC) | AES-256-GCM | ✅ 直接实测 | ECDSA-SHA256 | EC P-256 | 部分（仅传输层） |
| baidu.com | TLSv1.2 | —（TLS 1.2 无 key_share） | AES-128-GCM | ❌ | RSA-SHA256 | RSA 2048 | 不抗量子 |

---

## OQS Provider 安装（可选，用于 Layer 1 直接检测）

安装 OQS Provider 后，`detect` 命令将从 "CDN 推测" 升级为 "直接握手验证"。

MSYS2（Windows 推荐）：
```bash
pacman -S mingw-w64-x86_64-liboqs mingw-w64-x86_64-oqs-provider
```

或从源码编译：
```bash
# 1. 编译 liboqs
git clone https://github.com/open-quantum-safe/liboqs
cd liboqs && mkdir build && cd build
cmake .. -G "Ninja" && ninja && ninja install

# 2. 编译 oqsprovider
git clone https://github.com/open-quantum-safe/oqs-provider
cd oqs-provider && mkdir build && cd build
cmake .. -G "Ninja" && ninja && ninja install

# 3. 配置 openssl.cnf，激活 oqsprovider
```

安装后测试：
```bash
openssl s_client -connect cloudflare.com:443 \
  -groups X25519MLKEM768:x25519:secp256r1 -msg
# 如果看到 ServerHello 中 key_share 选择 0x11EC → 成功
```

---

## 备注

- 项目依赖：Python 3.10+，`cryptography`、`pandas`、`flask`、`fpdf2`、`python-docx`、`pyyaml`，`openssl` 命令行工具
- 安装依赖：`pip install -r requirements.txt`
- OpenSSL 3.5 及以上版本内置 ML-KEM 抗量子算法，无需单独安装 OQS Provider；较低版本需按上文安装 OQS Provider
- TLS 1.3 的密码套件名不包含密钥交换算法，密钥交换算法以 ServerHello `key_share` 扩展中的实际协商组为准
- 所有检测结果自动保存为 JSON 文件到 `output/` 目录
- 当前大部分网站使用经典证书（ECDSA/RSA），PQC 证书仍处于标准制定和试点阶段
- OID 映射表已覆盖 RSA/ECDSA/SM2/Dilithium/Falcon/SPHINCS+ 等主流算法，PQC 证书一旦部署即可自动识别
