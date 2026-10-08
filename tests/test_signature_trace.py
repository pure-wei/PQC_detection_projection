"""Replay actual native signatures, independently checking displayed arithmetic."""

import hashlib
import importlib

import pytest

from modules.mlkem_trace import Trace


def steps(entries):
    for entry in entries:
        yield entry
        yield from steps(entry.get("children", []))


@pytest.mark.parametrize("algorithm", ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"])
def test_ml_dsa_replay_checks_actual_signing_values_and_rejects_changed_message(algorithm):
    from modules import ml_dsa_trace

    native = importlib.import_module("pqcrypto.sign." + algorithm.lower().replace("-", "_"))
    public, secret = native.generate_keypair()
    message = b"actual signature replay"
    signature = native.sign(secret, message)
    trace = Trace()
    assert ml_dsa_trace.calculate(algorithm, message, public, signature, trace, secret)
    assert ml_dsa_trace.verify(algorithm, message, public, signature)
    assert not ml_dsa_trace.verify(algorithm, message + b"!", public, signature)
    assert not ml_dsa_trace.verify(algorithm, message, public, signature[:-1])
    values = [entry["values"] for entry in steps(trace.steps)]
    assert any(value.get("signature") == signature for value in values)
    assert any(value.get("key_relation_matches") is True for value in values)
    assert any("y_reconstructed" in value for value in values)
    assert any(value.get("challenge_matches") is True for value in values)
    assert any("input_coefficients" in value and "output_coefficients" in value for value in values)


def test_ml_dsa_ntt_product_matches_independent_negacyclic_convolution():
    from modules import ml_dsa_trace

    q = 8380417
    a = [(i * 37 + 11) % q for i in range(256)]
    b = [(i * i + 3) % q for i in range(256)]
    expected = [0] * 256
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            expected[(i + j) % 256] += x * y * (1 if i + j < 256 else -1)
    product = [x * y % q for x, y in zip(ml_dsa_trace.ntt(a), ml_dsa_trace.ntt(b))]
    assert ml_dsa_trace.inverse_ntt(product) == [x % q for x in expected]
    assert ml_dsa_trace.inverse_ntt(ml_dsa_trace.ntt(a)) == a


@pytest.mark.parametrize("hash_name", ["SHA2", "SHAKE"])
@pytest.mark.parametrize("variant", ["128s", "128f", "192s", "192f", "256s", "256f"])
def test_slh_backend_replay_reconstructs_every_layer_and_public_root(hash_name, variant):
    from modules import slh_dsa_trace

    algorithm = f"SLH-DSA-{hash_name}-{variant}"
    native = importlib.import_module(f"pqcrypto.sign.sphincs_{hash_name.lower()}_{variant}_simple")
    public, secret = native.generate_keypair()
    message = b"real hash paths"
    signature = native.sign(secret, message)
    trace = Trace()
    assert slh_dsa_trace.calculate(algorithm, message, public, signature, trace, secret)
    assert not slh_dsa_trace.verify(algorithm, message + b"!", public, signature)
    assert not slh_dsa_trace.verify(algorithm, message, public, signature[:-1])
    values = [entry["values"] for entry in steps(trace.steps)]
    n = slh_dsa_trace.parameters(algorithm)["n"]
    assert any(value.get("R") == signature[:n] for value in values)
    assert any(value.get("computed_root") == public[n:] and value.get("root_matches") is True
               for value in values)
    assert sum("xmss_layer" in value for value in values) == slh_dsa_trace.parameters(algorithm)["d"]
    assert any("chain_values" in value for value in values)


@pytest.mark.parametrize("algorithm", ["Falcon-512", "Falcon-1024"])
def test_falcon_replay_recovers_short_vector_and_checks_the_signature(algorithm):
    from modules import falcon_trace

    native = importlib.import_module("pqcrypto.sign." + algorithm.lower().replace("-", "_"))
    public, secret = native.generate_keypair()
    message = b"falcon calculation"
    signature = native.sign(secret, message)
    trace = Trace()
    assert falcon_trace.calculate(algorithm, message, public, signature, trace, secret)
    assert not falcon_trace.verify(algorithm, message + b"!", public, signature)
    assert not falcon_trace.verify(algorithm, message, public, signature[:-1])
    assert not falcon_trace.verify(algorithm, message, public, b"\x00" + signature[1:])
    values = [entry["values"] for entry in steps(trace.steps)]
    assert any(value.get("nonce") == signature[1:41] for value in values)
    norms = next(value for value in values if "squared_norm" in value)
    assert norms["squared_norm"] == sum(x*x for x in norms["s1"]) + sum(x*x for x in norms["s2"])
    assert norms["squared_norm"] <= norms["norm_bound"]


@pytest.mark.parametrize("algorithm", ["Ed25519", "ECDSA-P256", "ECDSA-P384", "RSA-PSS-2048", "RSA-PSS-3072"])
def test_classical_replay_matches_actual_native_signature(algorithm):
    from modules import classical_signature_trace, pqc_demo

    private, public, _ = pqc_demo._classical_signing_key(algorithm)
    message = b"actual classical signing"
    signature = private.sign(message, *pqc_demo._classical_signature_arguments(algorithm))
    trace = Trace()
    assert classical_signature_trace.calculate(algorithm, message, public, signature, trace, private)
    assert not classical_signature_trace.verify(algorithm, message + b"!", public, signature)
    assert not classical_signature_trace.verify(algorithm, message, public, signature[:-1])
    values = [entry["values"] for entry in steps(trace.steps)]
    assert any(value.get("signature") == signature for value in values)
    if algorithm.startswith("RSA"):
        pss = next(value for value in values if "salt" in value)
        assert len(pss["salt"]) == 32
        assert hashlib.sha256(b"\x00"*8 + hashlib.sha256(message).digest() + pss["salt"]).digest() == pss["H_prime"]
    elif algorithm.startswith("ECDSA"):
        assert any(value.get("nonce_relation_matches") is True for value in values)
    else:
        assert any(value.get("reconstructed_signature") == signature for value in values)


def test_ed25519_rfc8032_empty_message_example():
    from modules import classical_signature_trace
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    public = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    signature = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f"
                              "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    assert classical_signature_trace.calculate("Ed25519", b"", public, signature, Trace(),
                                              Ed25519PrivateKey.from_private_bytes(seed))
