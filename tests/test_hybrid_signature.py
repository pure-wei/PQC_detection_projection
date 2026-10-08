"""Real dual-signature verification, including rejection of partial signatures."""

import base64

import pytest

from modules import pqc_demo


@pytest.mark.parametrize("classical,public_size,signature_size", [
    ("Ed25519", 32, 64),
    ("ECDSA-P256", 65, 72),
    ("ECDSA-P384", 97, 104),
    ("RSA-PSS-2048", 294, 256),
    ("RSA-PSS-3072", 422, 384),
])
@pytest.mark.parametrize("pq_algorithm,pq_public_size,pq_signature_size", [
    ("ML-DSA-44", 1312, 2420),
    ("ML-DSA-65", 1952, 3309),
    ("ML-DSA-87", 2592, 4627),
])
def test_hybrid_signature_roundtrip_and_encoded_sizes(
        classical, public_size, signature_size,
        pq_algorithm, pq_public_size, pq_signature_size):
    message = "混合签名测试".encode("utf-8")
    signed = pqc_demo.sign_hybrid_message(message, pq_algorithm, classical)

    assert signed["pq_algorithm"] == pq_algorithm
    assert signed["classical_algorithm"] == classical
    assert len(base64.b64decode(signed["classical_public_key_base64"])) == public_size
    assert len(base64.b64decode(signed["pq_public_key_base64"])) == pq_public_size
    classical_signature_size = len(base64.b64decode(signed["classical_signature_base64"]))
    if classical.startswith("ECDSA"):
        assert 0 < classical_signature_size <= signature_size
    else:
        assert classical_signature_size == signature_size
    assert len(base64.b64decode(signed["pq_signature_base64"])) == pq_signature_size
    assert signed["public_key_bytes"] == public_size + pq_public_size
    assert signed["signature_bytes"] == classical_signature_size + pq_signature_size
    assert pqc_demo.verify_hybrid_signature(message, signed) == {
        "classical_verified": True, "pq_verified": True, "verified": True,
    }
    assert pqc_demo.verify_hybrid_signature(message + b"!", signed) == {
        "classical_verified": False, "pq_verified": False, "verified": False,
    }


@pytest.fixture
def signed_message():
    return pqc_demo.sign_hybrid_message(b"bound message")


@pytest.mark.parametrize("field,unchanged_component", [
    ("classical_signature_base64", "pq_verified"),
    ("pq_signature_base64", "classical_verified"),
])
@pytest.mark.parametrize("mutation", ["flip", "empty", "truncate"])
def test_each_component_is_required_even_when_other_signature_is_valid(
        signed_message, field, unchanged_component, mutation):
    changed = dict(signed_message)
    signature = base64.b64decode(changed[field])
    if mutation == "flip":
        signature = bytes([signature[0] ^ 1]) + signature[1:]
    elif mutation == "empty":
        signature = b""
    else:
        signature = signature[:-1]
    changed[field] = base64.b64encode(signature).decode("ascii")
    verification = pqc_demo.verify_hybrid_signature(b"bound message", changed)

    assert verification[unchanged_component] is True
    assert verification["verified"] is False
    assert verification["classical_verified"] != verification["pq_verified"]


@pytest.mark.parametrize("component", ["classical", "pq"])
def test_valid_halves_from_different_key_pairs_cannot_be_spliced(signed_message, component):
    other = pqc_demo.sign_hybrid_message(b"bound message")
    changed = dict(signed_message)
    for suffix in ("public_key_base64", "signature_base64"):
        field = component + "_" + suffix
        changed[field] = other[field]

    assert pqc_demo.verify_hybrid_signature(b"bound message", changed) == {
        "classical_verified": False, "pq_verified": False, "verified": False,
    }


@pytest.mark.parametrize("field,value", [
    ("pq_algorithm", "ML-DSA-999"),
    ("classical_algorithm", "RSA-PSS-1024"),
    ("pq_public_key_base64", "!!!invalid!!!"),
    ("classical_public_key_base64", "AA=="),
    ("pq_public_key_base64", "AA=="),
    ("pq_signature_base64", None),
])
def test_malformed_hybrid_artifacts_are_rejected(signed_message, field, value):
    changed = dict(signed_message)
    changed[field] = value
    assert pqc_demo.verify_hybrid_signature(b"bound message", changed)["verified"] is False


def test_missing_component_is_rejected(signed_message):
    del signed_message["pq_signature_base64"]
    assert pqc_demo.verify_hybrid_signature(b"bound message", signed_message)["verified"] is False


@pytest.mark.parametrize("pq_algorithm,classical", [
    ("SLH-DSA-SHA2-128s", "Ed25519"),
    ("SLH-DSA-SHAKE-128f", "ECDSA-P256"),
    ("Falcon-512", "RSA-PSS-2048"),
])
def test_hybrid_demo_supports_existing_pqc_families(pq_algorithm, classical):
    result = pqc_demo.run_hybrid_signature_demo(b"demo", pq_algorithm, classical)
    checks = result["checks"]

    assert checks["original"]["verified"] is True
    assert checks["changed_message"]["verified"] is False
    assert checks["changed_classical_signature"]["verified"] is False
    assert checks["changed_classical_signature"]["pq_verified"] is True
    assert checks["changed_pq_signature"]["verified"] is False
    assert checks["changed_pq_signature"]["classical_verified"] is True
    assert not any("private" in key or "secret" in key for key in result)


@pytest.mark.parametrize("message", [b"", b"\x00\xff\x80"])
def test_hybrid_signature_accepts_empty_and_binary_messages(message):
    signed = pqc_demo.sign_hybrid_message(message)
    assert pqc_demo.verify_hybrid_signature(message, signed)["verified"] is True


@pytest.mark.parametrize("pq_algorithm,classical", [
    ("unknown", "Ed25519"), ("ML-DSA-65", "unknown"),
])
def test_hybrid_signing_rejects_unknown_algorithms(pq_algorithm, classical):
    with pytest.raises(ValueError, match="不支持"):
        pqc_demo.sign_hybrid_message(b"x", pq_algorithm, classical)


def test_hybrid_signing_requires_byte_messages():
    with pytest.raises(TypeError, match="bytes"):
        pqc_demo.sign_hybrid_message("text")


def test_classical_comparison_includes_size_encoding_and_usage():
    rows = {row["name"]: row for row in pqc_demo.comparison_rows()}
    assert {"X25519", "Ed25519", "ECDH-P256", "ECDH-P384", "ECDSA-P256",
            "ECDSA-P384", "RSA-PSS-2048", "RSA-PSS-3072", "SM2"} <= rows.keys()
    assert "SPKI DER" in rows["RSA-PSS-2048"]["public_size"]
    assert "294" in rows["RSA-PSS-2048"]["public_size"]
    assert "256 字节签名" in rows["RSA-PSS-2048"]["output_size"]
    assert "DER" in rows["ECDSA-P256"]["output_size"]
    assert "共享秘密" in rows["ECDH-P256"]["output_size"]
    assert "签名" in rows["SM2"]["kind"]


def _trace_steps(entries):
    for entry in entries:
        yield entry
        yield from _trace_steps(entry.get("children", []))


def test_public_signing_api_does_not_export_teaching_private_intermediates():
    signed = pqc_demo.sign_hybrid_message(b"public signing artifact")
    assert "calculation_trace" not in signed


@pytest.mark.parametrize("classical", pqc_demo.CLASSICAL_SIGNATURE_VARIANTS)
def test_hybrid_trace_uses_actual_bound_data_and_both_signatures(classical):
    message = b"hybrid traced calculation"
    result = pqc_demo.run_hybrid_signature_demo(message, "ML-DSA-44", classical)
    trace = result["calculation_trace"]
    values = [step["values"] for step in _trace_steps(trace["steps"])]
    public_pq = base64.b64decode(result["pq_public_key_base64"])
    public_classical = base64.b64decode(result["classical_public_key_base64"])
    actual_data = pqc_demo._hybrid_signing_data(message, "ML-DSA-44", classical, public_pq, public_classical)
    binding = next(value for value in values if "signed_data" in value)
    assert binding["signed_data"] == actual_data
    assert binding["message"] == message
    assert any(value.get("signature") == base64.b64decode(result["pq_signature_base64"]) for value in values)
    assert any(value.get("signature") == base64.b64decode(result["classical_signature_base64"]) for value in values)
    checks = next(value for value in values if "AND_result" in value)
    assert checks["AND_result"] is True
    assert checks["changed_pq_signature"]["classical_verified"] is True
    assert checks["changed_pq_signature"]["verified"] is False
