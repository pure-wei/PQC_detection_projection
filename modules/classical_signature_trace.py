"""Inspectable classical signing/verification equations for hybrid demos."""

import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, utils

from modules.mlkem_trace import _record

ED_P = 2**255-19
ED_L = 2**252+27742317777372353535851937790883648493
ED_D = -121665*pow(121666, -1, ED_P) % ED_P
EC_PRIMES = {"ECDSA-P256": 2**256-2**224+2**192+2**96-1,
             "ECDSA-P384": 2**384-2**128-2**96+2**32-1}
EC_ORDERS = {"ECDSA-P256": int("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16),
             "ECDSA-P384": int("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973", 16)}


def parameters(algorithm):
    if algorithm == "Ed25519":
        return dict(curve="Edwards25519", p=hex(ED_P), order_L=hex(ED_L),
                    private_seed_bytes=32, public_key_bytes=32, signature_bytes=64,
                    hash="SHA512", signing="确定性 nonce r；签名为 R || S，小端编码")
    if algorithm in EC_PRIMES:
        return dict(curve="P-256" if algorithm.endswith("256") else "P-384",
                    p=hex(EC_PRIMES[algorithm]), order_n=hex(EC_ORDERS[algorithm]),
                    a="−3 mod p", hash="SHA256" if algorithm.endswith("256") else "SHA384",
                    public_key_bytes=65 if algorithm.endswith("256") else 97,
                    signature_encoding="DER SEQUENCE(INTEGER r, INTEGER s)",
                    nonce_note="由本次 d/r/s 与摘要反推等价 k；不声称原生库返回了原始随机源。")
    if algorithm in ("RSA-PSS-2048", "RSA-PSS-3072"):
        bits = int(algorithm.rsplit("-", 1)[1])
        return dict(modulus_bits=bits, public_exponent=65537, signature_bytes=bits//8,
                    public_key_encoding="SPKI DER", hash="SHA256", mgf="MGF1-SHA256",
                    salt_bytes=32, trailer="0xbc", em_bits=bits-1,
                    randomness_note="盐从本次签名恢复；原生素数生成候选和随机流不返回。")
    raise ValueError("不支持的传统签名算法")


def _ed_add(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    aa, bb = (y1-x1)*(y2-x2) % ED_P, (y1+x1)*(y2+x2) % ED_P
    cc, dd = 2*ED_D*t1*t2 % ED_P, 2*z1*z2 % ED_P
    e, f, g, h = (bb-aa) % ED_P, (dd-cc) % ED_P, (dd+cc) % ED_P, (bb+aa) % ED_P
    return e*f % ED_P, g*h % ED_P, f*g % ED_P, e*h % ED_P


def _ed_multiply(scalar, point):
    result = (0, 1, 1, 0)
    while scalar:
        if scalar & 1:
            result = _ed_add(result, point)
        point = _ed_add(point, point)
        scalar >>= 1
    return result


def _ed_decode(data):
    if len(data) != 32:
        raise ValueError("Ed25519 点长度不符")
    value = int.from_bytes(data, "little")
    sign, y = value >> 255, value & ((1 << 255)-1)
    if y >= ED_P:
        raise ValueError("Ed25519 非规范点")
    x2 = (y*y-1)*pow(ED_D*y*y+1, -1, ED_P) % ED_P
    x = pow(x2, (ED_P+3)//8, ED_P)
    if x*x % ED_P != x2:
        x = x*pow(2, (ED_P-1)//4, ED_P) % ED_P
    if x*x % ED_P != x2 or (x == 0 and sign):
        raise ValueError("Ed25519 点不在曲线上")
    if (x & 1) != sign:
        x = ED_P-x
    return x, y, 1, x*y % ED_P


def _ed_encode(point):
    x, y, z, _ = point
    inverse = pow(z, -1, ED_P)
    x, y = x*inverse % ED_P, y*inverse % ED_P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _ed_base():
    return _ed_decode((4*pow(5, -1, ED_P) % ED_P).to_bytes(32, "little"))


def _ed_calculate(message, public, signature, trace, private):
    if len(public) != 32 or len(signature) != 64:
        return False
    A, R = _ed_decode(public), _ed_decode(signature[:32])
    s = int.from_bytes(signature[32:], "little")
    if s >= ED_L or _ed_encode(_ed_multiply(8, A)) == b"\x01"+b"\x00"*31:
        return False
    material = signature[:32]+public+message
    digest = hashlib.sha512(material).digest()
    challenge = int.from_bytes(digest, "little") % ED_L
    if private is not None:
        seed = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        expanded = hashlib.sha512(seed).digest()
        clamped = bytearray(expanded[:32])
        clamped[0] &= 248
        clamped[31] = (clamped[31] & 63) | 64
        a = int.from_bytes(clamped, "little")
        r_digest = hashlib.sha512(expanded[32:]+message).digest()
        r = int.from_bytes(r_digest, "little") % ED_L
        generated_R = _ed_encode(_ed_multiply(r, _ed_base()))
        generated_s = (r+challenge*a) % ED_L
        reconstructed = generated_R+generated_s.to_bytes(32, "little")
        _record(trace, "Ed25519 种子展开与实际签名计算", "h=SHA512(seed)；a=clamp(h[:32])；r=SHA512(h[32:] || M) mod L；R=[r]B；S=r+k·a mod L", {
            "seed": seed, "expanded_seed": expanded, "clamped_scalar_bytes": bytes(clamped),
            "prefix": expanded[32:], "r_hash_input": expanded[32:]+message, "r_hash": r_digest,
            "a": hex(a), "r": hex(r), "k": hex(challenge), "R": generated_R, "S": hex(generated_s),
            "reconstructed_signature": reconstructed}, "RFC 8032，§5.1.5–5.1.6")
        if reconstructed != signature or _ed_encode(_ed_multiply(a, _ed_base())) != public:
            raise RuntimeError("Ed25519 签名重建不一致")
    lhs = _ed_encode(_ed_multiply(s, _ed_base()))
    rhs = _ed_encode(_ed_add(R, _ed_multiply(challenge, A)))
    valid = lhs == rhs
    _record(trace, "Ed25519 挑战哈希与验签点", "k=SHA512(R || A || M) mod L；检查 [S]B=R+[k]A", {
        "public_key": public, "signature": signature, "challenge_hash_input": material,
        "challenge_hash": digest, "k": hex(challenge), "S": hex(s),
        "S_times_B": lhs, "R_plus_kA": rhs, "verified": valid}, "RFC 8032，§5.1.7")
    return valid


def _ec_add(a, b, prime):
    if a is None:
        return b
    if b is None:
        return a
    x, y = a
    u, v = b
    if x == u and (y+v) % prime == 0:
        return None
    slope = ((3*x*x-3)*pow(2*y, -1, prime) if a == b else (v-y)*pow(u-x, -1, prime)) % prime
    nx = (slope*slope-x-u) % prime
    return nx, (slope*(x-nx)-y) % prime


def _ec_multiply(scalar, point, prime):
    result = None
    while scalar:
        if scalar & 1:
            result = _ec_add(result, point, prime)
        point = _ec_add(point, point, prime)
        scalar >>= 1
    return result


def _point(point):
    return {"x": hex(point[0]), "y": hex(point[1])} if point is not None else "无穷远点"


def _ec_calculate(algorithm, message, public, signature, trace, private):
    curve = ec.SECP256R1() if algorithm == "ECDSA-P256" else ec.SECP384R1()
    key = ec.EllipticCurvePublicKey.from_encoded_point(curve, public)
    numbers = key.public_numbers()
    r, s = utils.decode_dss_signature(signature)
    order, prime = EC_ORDERS[algorithm], EC_PRIMES[algorithm]
    if not (0 < r < order and 0 < s < order):
        return False
    digest = (hashlib.sha256 if algorithm == "ECDSA-P256" else hashlib.sha384)(message).digest()
    e = int.from_bytes(digest, "big")
    generator = ec.derive_private_key(1, curve).public_key().public_numbers()
    G, public_point = (generator.x, generator.y), (numbers.x, numbers.y)
    if private is not None:
        d = private.private_numbers().private_value
        k = (e+r*d)*pow(s, -1, order) % order
        nonce_point = _ec_multiply(k, G, prime)
        matches = nonce_point is not None and nonce_point[0] % order == r and _ec_multiply(d, G, prime) == public_point
        _record(trace, "ECDSA 还原本次等价 nonce", "r=x([k]G) mod n；s=k⁻¹(e+r·d) mod n → k=(e+r·d)·s⁻¹ mod n", {
            "d": hex(d), "digest": digest, "e": hex(e), "r": hex(r), "s": hex(s),
            "k_equivalent": hex(k), "nonce_point": _point(nonce_point), "nonce_relation_matches": matches},
            "FIPS 186-5，§6.3",
            "k 从本次签名与临时私钥代数反推；若后端对 s 作归一化，它可能对应等价的相反 nonce，不代表原始随机源。")
        if not matches:
            raise RuntimeError("ECDSA nonce/密钥关系重建不一致")
    inverse = pow(s, -1, order)
    u1, u2 = e*inverse % order, r*inverse % order
    point1, point2 = _ec_multiply(u1, G, prime), _ec_multiply(u2, public_point, prime)
    result = _ec_add(point1, point2, prime)
    valid = result is not None and result[0] % order == r
    _record(trace, "ECDSA 验签标量与点运算", "w=s⁻¹ mod n；u₁=e·w；u₂=r·w；X=[u₁]G+[u₂]Q；检查 X.x mod n=r", {
        "public_key": public, "signature": signature, "message_digest": digest,
        "r": hex(r), "s": hex(s), "w": hex(inverse), "u1": hex(u1), "u2": hex(u2),
        "generator": _point(G), "public_point": _point(public_point),
        "u1G": _point(point1), "u2Q": _point(point2), "verification_point": _point(result),
        "verified": valid}, "FIPS 186-5，§6.4；SP 800-186，P-256/P-384")
    return valid


def _rsa_calculate(algorithm, message, public, signature, trace, private):
    key = serialization.load_der_public_key(public)
    bits = int(algorithm.rsplit("-", 1)[1])
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size != bits or len(signature) != bits//8:
        return False
    numbers = key.public_numbers()
    n, exponent, s = numbers.n, numbers.e, int.from_bytes(signature, "big")
    if exponent != 65537 or s >= n:
        return False
    em_bits, size = n.bit_length()-1, (n.bit_length()-1+7)//8
    encoded = pow(s, exponent, n).to_bytes(size, "big")
    masked, H = encoded[:-33], encoded[-33:-1]
    unused = 8*size-em_bits
    if encoded[-1] != 0xbc or masked[0] >> (8-unused):
        return False
    blocks = [hashlib.sha256(H+i.to_bytes(4, "big")).digest() for i in range((len(masked)+31)//32)]
    mask = b"".join(blocks)[:len(masked)]
    db = bytearray(a ^ b for a, b in zip(masked, mask))
    db[0] &= 0xff >> unused
    if bytes(db[:-33]) != b"\x00"*(len(db)-33) or db[-33] != 1:
        return False
    salt = bytes(db[-32:])
    digest = hashlib.sha256(message).digest()
    material = b"\x00"*8+digest+salt
    recomputed = hashlib.sha256(material).digest()
    _record(trace, "RSA 公钥运算恢复 EM", "s=OS2IP(signature)；EM=I2OSP(s^e mod n,emLen)", {
        "public_key": public, "signature": signature, "n": hex(n), "e": exponent,
        "signature_integer": hex(s), "EM": encoded, "em_bits": em_bits}, "RFC 8017，§8.1.2、§5.2.2")
    _record(trace, "PSS 掩码、真实盐与摘要比对", "dbMask=MGF1(H)；DB=maskedDB XOR dbMask；提取 salt；H′=SHA256(0^8 || SHA256(M) || salt)", {
        "masked_DB": masked, "H": H, "mgf1_blocks": blocks, "db_mask": mask, "DB": bytes(db),
        "salt": salt, "message_digest": digest, "H_prime_input": material, "H_prime": recomputed,
        "hash_matches": recomputed == H, "verified": recomputed == H}, "RFC 8017，§9.1.2、附录 B.2.1",
        "MGF1 每个块为 SHA256(H || counter)，counter 按 4 字节大端编码；本轮盐从实际 EM 中恢复。")
    if private is not None:
        priv = private.private_numbers()
        recreated = pow(int.from_bytes(encoded, "big"), priv.d, n).to_bytes(bits//8, "big")
        _record(trace, "RSA 私钥关系与本次签名重建", "n=p·q；signature=I2OSP(OS2IP(EM)^d mod n,k)", {
            "p": hex(priv.p), "q": hex(priv.q), "d": hex(priv.d),
            "reconstructed_signature": recreated, "signature_matches": recreated == signature}, "RFC 8017，§8.1.1、§5.2.1",
            "显示本轮实际素数与私钥指数；原生素数生成的候选和随机流未返回。")
        if recreated != signature or priv.public_numbers != numbers:
            raise RuntimeError("RSA 签名/密钥关系重建不一致")
    return recomputed == H


def calculate(algorithm, message, public, signature, trace, secret=None):
    parameters(algorithm)
    try:
        if algorithm == "Ed25519":
            return _ed_calculate(message, public, signature, trace, secret)
        if algorithm.startswith("ECDSA"):
            return _ec_calculate(algorithm, message, public, signature, trace, secret)
        return _rsa_calculate(algorithm, message, public, signature, trace, secret)
    except (ValueError, IndexError, OverflowError):
        return False


def verify(algorithm, message, public, signature, trace=None):
    return calculate(algorithm, message, public, signature, trace)
