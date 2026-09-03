"""Configuration loader."""
import os
import yaml


DEFAULT_CONFIG = {
    "algorithms": {
        "kem": ["Kyber512", "Kyber768", "Kyber1024"],
        "signature": ["Dilithium2", "Dilithium3", "Dilithium5"],
    },
    "target_urls": [
        "google.com",
        "github.com",
        "cloudflare.com",
        "microsoft.com",
        "baidu.com",
        "nist.gov",
        "wikipedia.org",
        "stackoverflow.com",
        "apple.com",
        "amazon.com",
    ],
    "benchmark": {
        "iterations": 100,
        "warmup_iterations": 5,
    },
    "simulation": {
        "kem_variant": "Kyber768",
        "sig_variant": "Dilithium3",
        "symmetric_cipher": "AES-256-GCM",
        "hash_algorithm": "SHA384",
    },
    "output": {
        "dir": "output",
        "report_format": "html",
    },
}


def load_config(path: str = None) -> dict:
    """Load configuration from YAML file, falling back to defaults."""
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            user_config = yaml.safe_load(f) or {}
        return {**DEFAULT_CONFIG, **user_config}
    return DEFAULT_CONFIG.copy()
