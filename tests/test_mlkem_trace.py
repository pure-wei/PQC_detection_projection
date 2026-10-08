"""Independent arithmetic checks and official final-FIPS ML-KEM examples."""

import hashlib
import json
from pathlib import Path

import pytest

from modules import mlkem_trace


def _steps(entries):
    for entry in entries:
        yield entry
        yield from _steps(entry.get("children", []))


def test_ntt_roundtrip_and_multiplication_match_ring_convolution():
    q = 3329
    a = [(17 * i + 3) % q for i in range(256)]
    b = [(i * i + 7) % q for i in range(256)]
    assert mlkem_trace.inverse_ntt(mlkem_trace.ntt(a)) == a
    expected = [0] * 256
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            position = i + j
            expected[position % 256] += x * y * (1 if position < 256 else -1)
    expected = [x % q for x in expected]
    product = mlkem_trace.multiply_ntt(mlkem_trace.ntt(a), mlkem_trace.ntt(b))
    assert mlkem_trace.inverse_ntt(product) == expected


def test_byte_encoding_is_little_endian_and_checks_modulus():
    coefficients = [1, 2] + [0] * 254
    encoded = mlkem_trace.byte_encode(coefficients, 12)
    assert encoded[:3] == bytes.fromhex("012000")
    assert len(encoded) == 384
    assert mlkem_trace.byte_decode(encoded, 12) == coefficients
    # ByteDecode12 reduces modulo q, so the modulus check must re-encode.
    invalid = bytes.fromhex("ff0f00") + b"\x00" * 381
    assert mlkem_trace.byte_decode(invalid, 12)[0] == 766


def test_compression_rounding_and_wraparound():
    # For d=1, rounding boundaries are q/4 and 3q/4, not q/2.
    assert [mlkem_trace.compress(x, 1) for x in (0, 832, 833, 1664, 2496, 2497, 3328)] == [0, 0, 1, 1, 1, 0, 0]
    assert [mlkem_trace.decompress(x, 1) for x in (0, 1)] == [0, 1665]
    assert mlkem_trace.compress(3328, 10) == 0


@pytest.fixture(scope="module")
def acvp():
    return json.loads((Path(__file__).parent / "fixtures" / "mlkem_acvp_examples.json").read_text())


@pytest.mark.parametrize("algorithm", ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"])
def test_key_generation_matches_official_final_fips_vector(acvp, algorithm):
    case = acvp["keygen"][algorithm]
    public, secret = mlkem_trace.MLKEM(algorithm).keygen(
        bytes.fromhex(case["d"]), bytes.fromhex(case["z"]))
    assert public.hex().upper() == case["ek"].upper()
    assert secret.hex().upper() == case["dk"].upper()


@pytest.mark.parametrize("algorithm", ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"])
def test_encapsulation_matches_official_final_fips_vector(acvp, algorithm):
    case = acvp["encapsulation"][algorithm]
    ciphertext, key = mlkem_trace.MLKEM(algorithm).encaps(
        bytes.fromhex(case["ek"]), bytes.fromhex(case["m"]))
    assert ciphertext.hex().upper() == case["c"].upper()
    assert key.hex().upper() == case["k"].upper()


@pytest.mark.parametrize("algorithm", ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"])
def test_decapsulation_matches_official_final_fips_vector(acvp, algorithm):
    case = acvp["decapsulation"][algorithm]
    key = mlkem_trace.MLKEM(algorithm).decaps(bytes.fromhex(case["dk"]), bytes.fromhex(case["c"]))
    assert key.hex().upper() == case["k"].upper()


@pytest.mark.parametrize("algorithm,module_name", [
    ("ML-KEM-512", "ml_kem_512"), ("ML-KEM-768", "ml_kem_768"), ("ML-KEM-1024", "ml_kem_1024"),
])
def test_traced_calculation_uses_actual_seeds_and_native_interoperability(
        monkeypatch, algorithm, module_name):
    import importlib

    native = importlib.import_module("pqcrypto.kem." + module_name)
    seeds = [bytes(range(32)), bytes(range(32, 64)), bytes(range(64, 96))]
    iterator = iter(seeds)
    monkeypatch.setattr(mlkem_trace.os, "urandom", lambda size: next(iterator))
    result = mlkem_trace.run_calculation(algorithm, native)
    entries = list(_steps(result["trace"]["steps"]))
    randomness = next(entry["values"] for entry in entries if "d" in entry["values"])
    assert randomness["d"] == seeds[0]
    assert randomness["z"] == seeds[1]
    assert randomness["m"] == seeds[2]
    expected_key = hashlib.sha3_512(seeds[2] + hashlib.sha3_256(result["public_key"]).digest()).digest()[:32]
    assert result["sender_shared"] == result["receiver_shared"] == expected_key
    assert result["changed_shared"] != expected_key
    assert result["native_verified"] is True
    assert any(entry["values"].get("c") == result["ciphertext"] for entry in entries)
    assert any("input_coefficients" in entry["values"] and
               len(entry["values"]["output_coefficients"]) == 256 for entry in entries)
    assert any("candidate_decisions" in entry["values"] for entry in entries)
    assert any("K_reject" in entry["values"] and entry["values"]["ciphertext_matches"] is False
               for entry in entries)


def test_encapsulation_rejects_noncanonical_public_key():
    engine = mlkem_trace.MLKEM("ML-KEM-512")
    public, _ = engine.keygen(b"d" * 32, b"z" * 32)
    invalid = bytes.fromhex("ff0f") + public[2:]
    with pytest.raises(ValueError, match="公钥"):
        engine.encaps(invalid, b"m" * 32)


def test_decapsulation_checks_lengths_and_private_key_hash():
    engine = mlkem_trace.MLKEM("ML-KEM-512")
    public, secret = engine.keygen(b"d" * 32, b"z" * 32)
    ciphertext, key = engine.encaps(public, b"m" * 32)
    assert engine.decaps(secret, ciphertext) == key
    with pytest.raises(ValueError):
        engine.decaps(secret, ciphertext[:-1])
    with pytest.raises(ValueError):
        engine.decaps(secret[:-1], ciphertext)
    changed = bytearray(secret)
    changed[-33] ^= 1
    with pytest.raises(ValueError, match="哈希"):
        engine.decaps(bytes(changed), ciphertext)


@pytest.mark.parametrize("d,z", [(b"x" * 31, b"z" * 32), (b"d" * 32, b"z" * 33)])
def test_key_generation_requires_32_byte_seeds(d, z):
    with pytest.raises(ValueError):
        mlkem_trace.MLKEM("ML-KEM-512").keygen(d, z)


def test_unsupported_parameter_set_is_rejected():
    with pytest.raises(ValueError):
        mlkem_trace.MLKEM("ML-KEM-999")


def test_native_disagreement_fails_instead_of_showing_a_successful_trace():
    from types import SimpleNamespace
    from pqcrypto.kem import ml_kem_512

    incompatible = SimpleNamespace(encrypt=ml_kem_512.encrypt,
                                   decrypt=lambda secret, ciphertext: b"wrong native secret")
    with pytest.raises(RuntimeError, match="交叉校验失败"):
        mlkem_trace.run_calculation("ML-KEM-512", incompatible)
