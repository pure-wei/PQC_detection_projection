"""
Technology terms → Chinese translation map.
Used across the project to annotate output with Chinese.
Format: { English: Chinese }
"""

# Protocol versions
PROTOCOL_CN = {
    "TLSv1.3": "TLS 1.3 协议",
    "TLSv1.2": "TLS 1.2 协议",
    "TLSv1.1": "TLS 1.1 协议",
    "TLSv1.0": "TLS 1.0 协议",
    "SSLv3": "SSL 3.0 协议",
}

# Key exchange algorithms
KEX_CN = {
    "ECDHE": "椭圆曲线迪菲-赫尔曼密钥交换",
    "DHE": "迪菲-赫尔曼密钥交换",
    "ECDH": "椭圆曲线密钥交换",
    "DH": "迪菲-赫尔曼密钥交换",
    "RSA": "RSA 密钥交换",
    "X25519+ML-KEM-768 (PQC Hybrid)": "X25519+ML-KEM-768 混合后量子密钥交换",
    "X25519+Kyber-768 (PQC Hybrid)": "X25519+Kyber-768 混合后量子密钥交换",
    "ML-KEM-1024 (PQC-only)": "ML-KEM-1024 纯后量子密钥交换",
}

# Authentication algorithms
AUTH_CN = {
    "RSA": "RSA 签名认证",
    "RSA/ECDSA": "RSA/ECDSA 签名认证",
    "ECDSA": "椭圆曲线数字签名",
    "DSS": "数字签名标准",
    "ML-DSA / Dilithium": "ML-DSA/Dilithium 后量子签名",
}

# Symmetric encryption
SYM_CN = {
    "AES-256-GCM": "AES-256 伽罗瓦/计数器模式",
    "AES-128-GCM": "AES-128 伽罗瓦/计数器模式",
    "AES-128-CCM": "AES-128 CBC-MAC 计数器模式",
    "AES-128-CCM-8": "AES-128 CCM-8 模式",
    "CHACHA20-POLY1305": "ChaCha20-Poly1305 流密码",
    "AES-256-CBC": "AES-256 密码块链接模式",
    "AES-128-CBC": "AES-128 密码块链接模式",
}

# Hash algorithms
HASH_CN = {
    "SHA-384": "SHA-384 哈希",
    "SHA-256": "SHA-256 哈希",
    "SHA-512": "SHA-512 哈希",
}

# PQC algorithms
PQC_CN = {
    "Kyber512": "ML-KEM-512 (后量子密钥封装)",
    "Kyber768": "ML-KEM-768 (后量子密钥封装)",
    "Kyber1024": "ML-KEM-1024 (后量子密钥封装)",
    "Dilithium2": "ML-DSA-44 (后量子数字签名)",
    "Dilithium3": "ML-DSA-65 (后量子数字签名)",
    "Dilithium5": "ML-DSA-87 (后量子数字签名)",
}

# Comparison metrics
METRIC_CN = {
    "NIST Security Level": "NIST 安全等级",
    "Quantum Resistant": "抗量子能力",
    "Forward Secrecy": "前向安全性",
    "KEX Algorithm": "密钥交换算法",
    "KEX Public Key Size": "密钥交换公钥大小",
    "KEX Ciphertext Size": "密钥交换密文大小",
    "Shared Secret Size": "共享密钥大小",
    "Auth Algorithm": "认证签名算法",
    "Auth Public Key Size": "认证公钥大小",
    "Auth Signature Size": "认证签名大小",
    "Certificate Size": "证书大小",
    "ClientHello Size": "ClientHello 大小",
    "ServerHello Size": "ServerHello 大小",
    "Total Handshake Bytes": "握手总字节数",
    "Total Handshake Time": "握手总耗时",
    "KeyGen Time": "密钥生成耗时",
    "KEX Op Time": "密钥交换操作耗时",
    "Sign Time": "签名耗时",
    "Verify Time": "验签耗时",
}

# CDN providers
CDN_CN = {
    "Cloudflare": "Cloudflare CDN",
    "Fastly": "Fastly CDN",
}

# PQC evidence
PQC_EVIDENCE_CN = {
    "Cloudflare CDN detected (PQC enabled by default since 2022)": "检测到 Cloudflare CDN (自2022年起默认开启PQC)",
    "Fastly CDN detected (PQC early adopter)": "检测到 Fastly CDN (PQC早期采用者)",
    "PQC cipher suite negotiated": "已协商PQC密码套件",
}


def cn(label_map: dict, key: str, default: str = "") -> str:
    """Look up Chinese translation. Returns empty string if not found."""
    return label_map.get(key, default)


def annotate(en_text: str, cn_text: str) -> str:
    """Format: 'English (Chinese)' if Chinese available, else just English."""
    if cn_text:
        return f"{en_text} ({cn_text})"
    return en_text


def lookup_annotate(label_map: dict, key: str, fallback: str = None) -> str:
    """Look up Chinese for key, return annotated string."""
    cn_text = label_map.get(key, "")
    display = key if fallback is None else fallback
    return annotate(display, cn_text)
