"""Offline checks for the four real post-quantum algorithm demonstrations."""

import base64
import hashlib

import pytest

from modules import pqc_demo


@pytest.mark.parametrize("algorithm,public_bytes,ciphertext_bytes", [
    ("ML-KEM-512", 800, 768),
    ("ML-KEM-768", 1184, 1088),
    ("ML-KEM-1024", 1568, 1568),
])
def test_standalone_kem_encapsulates_and_decapsulates(algorithm, public_bytes, ciphertext_bytes):
    result = pqc_demo.run_kem_demo(algorithm)

    assert result["algorithm"] == algorithm
    assert result["public_key_bytes"] == public_bytes
    assert len(base64.b64decode(result["public_key_base64"])) == public_bytes
    assert result["ciphertext_bytes"] == ciphertext_bytes
    assert len(base64.b64decode(result["ciphertext_base64"])) == ciphertext_bytes
    assert result["shared_secret_bytes"] == 32
    assert result["shared_secret_matches"] is True
    assert result["changed_ciphertext_changes_secret"] is True
    assert result["sender_fingerprint"] == result["receiver_fingerprint"]


def test_standalone_kem_rejects_unknown_parameter_set():
    with pytest.raises(ValueError, match="不支持"):
        pqc_demo.run_kem_demo("ML-KEM-999")


def test_hybrid_encryption_recovers_utf8_and_rejects_tampering():
    message = "后量子混合加密 demo".encode("utf-8")
    result = pqc_demo.run_hybrid_demo(message)

    assert result["recovered"] == message
    assert result["kem_shared_secret_matches"] is True
    assert result["ecdh_shared_secret_matches"] is True
    assert result["tamper_rejected"] is True
    assert result["kem_public_key_bytes"] == 1184
    assert result["kem_ciphertext_bytes"] == 1088
    assert result["x25519_public_key_bytes"] == 32
    assert base64.b64decode(result["ciphertext_base64"]) != message


@pytest.mark.parametrize("kem_name,public_bytes,ct_bytes", [
    ("ML-KEM-512", 800, 768),
    ("ML-KEM-768", 1184, 1088),
    ("ML-KEM-1024", 1568, 1568),
])
@pytest.mark.parametrize("classical_name,classical_bytes", [
    ("X25519", 32), ("P-256", 65), ("P-384", 97),
])
def test_hybrid_demo_supports_selected_key_parameter_sets(
        kem_name, public_bytes, ct_bytes, classical_name, classical_bytes):
    result = pqc_demo.run_hybrid_demo(b"parameter test", kem_name, classical_name)

    assert result["recovered"] == b"parameter test"
    assert result["kem_algorithm"] == kem_name
    assert result["classical_algorithm"] == classical_name
    assert result["kem_public_key_bytes"] == public_bytes
    assert len(base64.b64decode(result["kem_public_key_base64"])) == public_bytes
    assert result["kem_ciphertext_bytes"] == ct_bytes
    assert result["classical_public_key_bytes"] == classical_bytes
    assert result["kem_shared_secret_matches"] is True
    assert result["ecdh_shared_secret_matches"] is True


@pytest.mark.parametrize("kem_name,classical_name", [
    ("ML-KEM-999", "X25519"), ("ML-KEM-768", "P-999"),
])
def test_hybrid_demo_rejects_unknown_parameter_set(kem_name, classical_name):
    with pytest.raises(ValueError, match="不支持"):
        pqc_demo.run_hybrid_demo(b"x", kem_name, classical_name)


@pytest.mark.parametrize("algorithm", ["ML-DSA-65", "SLH-DSA-SHA2-128s", "Falcon-512"])
def test_real_signature_verifies_original_but_not_changed_message(algorithm):
    result = pqc_demo.run_signature_demo(b"signed message", algorithm)

    assert result["verified"] is True
    assert result["altered_verified"] is False
    assert result["signature_bytes"] == len(base64.b64decode(result["signature_base64"]))
    assert result["public_key_bytes"] > 0


@pytest.mark.parametrize("algorithm", [
    "ML-DSA-44", "ML-DSA-87",
    "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
    "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f",
    "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
    "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f",
    "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f", "Falcon-1024",
])
def test_additional_signature_parameter_sets_verify_real_signatures(algorithm):
    result = pqc_demo.run_signature_demo(b"parameter test", algorithm)
    assert result["verified"] is True
    assert result["altered_verified"] is False
    assert result["signature_bytes"] > 0


def test_signature_rejects_unknown_algorithm():
    with pytest.raises(ValueError, match="不支持"):
        pqc_demo.run_signature_demo(b"x", "unknown")


def test_comparison_covers_four_pqc_families_and_classical_counterparts():
    rows = pqc_demo.comparison_rows()
    names = {row["name"] for row in rows}

    assert {"ML-KEM-768", "ML-DSA-65", "SLH-DSA-SHA2-128s", "Falcon-512",
            "X25519", "Ed25519"} <= names
    falcon = next(row for row in rows if row["name"] == "Falcon-512")
    assert "制定中" in falcon["standard"]
    assert "可变" in falcon["output_size"]


def _trace_steps(entries):
    for entry in entries:
        yield entry
        yield from _trace_steps(entry.get("children", []))


def test_kem_trace_contains_the_actual_public_key_ciphertext_and_shared_secret():
    result = pqc_demo.run_kem_demo("ML-KEM-768")
    trace = result["calculation_trace"]
    values = [step["values"] for step in _trace_steps(trace["steps"])]
    public = base64.b64decode(result["public_key_base64"])
    ciphertext = base64.b64decode(result["ciphertext_base64"])
    assert any(value.get("ek") == public for value in values)
    assert any(value.get("c") == ciphertext for value in values)
    shared = next(value["K"] for value in values if "K" in value)
    assert hashlib.sha256(shared).hexdigest()[:16] == result["sender_fingerprint"]
    assert trace["parameters"]["k"] == 3
    assert trace["parameters"]["q"] == 3329


def test_hybrid_trace_connects_mlkem_to_the_actual_hkdf_and_aes_ciphertext():
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    result = pqc_demo.run_hybrid_demo(b"actual hybrid calculation", "ML-KEM-1024", "P-384")
    values = [step["values"] for step in _trace_steps(result["calculation_trace"]["steps"])]
    shared = next(value["K"] for value in values if "K" in value)
    hkdf = next(value for value in values if "IKM" in value)
    assert hkdf["IKM"] == hkdf["ecdh_secret"] + shared
    assert HKDF(algorithm=hashes.SHA256(), length=32, salt=hkdf["salt"],
                info=hkdf["info"]).derive(hkdf["IKM"]) == hkdf["AES_key"]
    aes = next(value for value in values if "aes_ciphertext" in value)
    assert aes["aes_ciphertext"] == base64.b64decode(result["ciphertext_base64"])
    assert AESGCM(hkdf["AES_key"]).decrypt(aes["nonce"], aes["aes_ciphertext"], aes["AAD"]) == result["recovered"]


@pytest.mark.parametrize("algorithm", ["ML-DSA-44", "SLH-DSA-SHAKE-128f", "Falcon-1024"])
def test_signature_demo_trace_contains_the_actual_message_and_signature(algorithm):
    result = pqc_demo.run_signature_demo(b"signature trace input", algorithm)
    trace = result["calculation_trace"]
    values = [step["values"] for step in _trace_steps(trace["steps"])]
    signature = base64.b64decode(result["signature_base64"])
    assert trace["algorithm"] == algorithm
    assert any(value.get("signature") == signature for value in values)
    assert any(value.get("message") == b"signature trace input" for value in values)
    assert any(value.get("replay_verified") is True for value in values)
    assert trace["parameters"]["public_key_bytes"] == result["public_key_bytes"]
