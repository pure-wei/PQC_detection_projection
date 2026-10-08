"""Validated experiment profiles, shared by the CLI and desktop report reader."""
from dataclasses import asdict, dataclass
from modules.pqc_demo import SIGNATURE_VARIANTS, CLASSICAL_SIGNATURE_VARIANTS

PROTOCOLS = {"https": "HTTPS / TLS 1.3", "tls": "TLS 1.3 握手",
             "tcp": "TCP 签名消息", "udp": "UDP 签名消息"}
TLS_GROUPS = {"X25519MLKEM768": 0x11EC, "SecP256r1MLKEM768": 0x11EB,
              "SecP384r1MLKEM1024": 0x11ED}
TLS_SIGNATURES = {
    "ML-DSA-44": {"openssl": "mldsa44", "scheme": "0x0904", "oid": "2.16.840.1.101.3.4.3.17"},
    "ML-DSA-65": {"openssl": "mldsa65", "scheme": "0x0905", "oid": "2.16.840.1.101.3.4.3.18"},
    "ML-DSA-87": {"openssl": "mldsa87", "scheme": "0x0906", "oid": "2.16.840.1.101.3.4.3.19"},
}


@dataclass(frozen=True)
class LabProfile:
    protocol: str = "https"
    group: str = "X25519MLKEM768"
    signature: str = "ML-DSA-65"
    classical_signature: str = ""

    def __post_init__(self):
        if self.protocol not in PROTOCOLS or self.group not in TLS_GROUPS:
            raise ValueError("不支持的实验协议或密钥交换组")
        if self.signature not in SIGNATURE_VARIANTS:
            raise ValueError("不支持的数字签名算法")
        if self.classical_signature and self.classical_signature not in CLASSICAL_SIGNATURE_VARIANTS:
            raise ValueError("不支持的经典混合签名算法")
        if self.is_tls and (self.signature not in TLS_SIGNATURES or self.classical_signature):
            raise ValueError("TLS 握手支持 ML-DSA-44/65/87；应用混合签名用于 TCP/UDP 消息")

    @property
    def is_tls(self):
        return self.protocol in ("https", "tls")

    def as_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, value):
        if not isinstance(value, dict):
            raise ValueError("无效实验配置")
        return cls(**value)


def success_matches_profile(data):
    """Check semantics, in addition to the caller's timestamp/check/target checks."""
    summary = data.get("summary", {})
    try:
        profile = LabProfile.from_dict(data["profile"]) if "profile" in data else LabProfile()
        ids = {item.get("id") for item in data.get("checks", []) if item.get("passed") is True}
        if profile.is_tls:
            valid = (summary.get("finished_verified") is True
                     and summary.get("certificate_verify_verified") is True
                     and summary.get("group_name") in (profile.group, profile.group + "（混合）")
                     and summary.get("protocol") in ("TLS 1.3", "TLSv1.3")
                     and summary.get("certificate_algorithm") == profile.signature)
            if "profile" in data:
                valid = valid and ("https_get" if profile.protocol == "https" else "tls_session") in ids
            return valid
        return (summary.get("protocol") == profile.protocol.upper()
                and summary.get("signature_algorithm") == profile.signature
                and summary.get("classical_signature_algorithm", "") == profile.classical_signature
                and summary.get("message_signature_verified") is True
                and summary.get("pq_signature_verified") is True
                and (not profile.classical_signature or summary.get("classical_signature_verified") is True)
                and summary.get("transport_confidentiality") is False
                and {"message_exchange", "message_signature", "reject_replay"} <= ids)
    except (ValueError, TypeError, AttributeError, KeyError):
        return False
