"""Decode and replay real Falcon signatures using public verification math."""

import hashlib

from modules.mlkem_trace import _record

SOURCE = "https://falcon-sign.info/impl/"
Q = 12289


def parameters(algorithm):
    if algorithm not in ("Falcon-512", "Falcon-1024"):
        raise ValueError("不支持的 Falcon 参数集")
    n = int(algorithm.split("-")[-1])
    return dict(n=n, q=Q, log_n=n.bit_length()-1, nonce_bytes=40,
                nist_security_category=1 if n == 512 else 5,
                squared_norm_bound=34034726 if n == 512 else 70265242,
                public_key_bytes=1+14*n//8, secret_key_bytes=1281 if n == 512 else 2305,
                signature_encoding="头字节 || 40 字节 nonce || 压缩 s₂（长度可变）",
                public_encoding="头字节 || n 个 14 位大端系数 h",
                hash="SHAKE256(nonce || M)；拒绝采样映射至 Z_12289",
                ring=f"Z_q[X]/(X^{n}+1)",
                randomness_note="nonce 从本次签名读取；原生库未返回高斯采样随机源和拒绝尝试。s₁/s₂ 是本轮实际签名对应的短向量。")


def _bits(data, width, count, signed=False):
    packed, total = int.from_bytes(data, "big"), len(data)*8
    values = []
    for i in range(count):
        value = (packed >> (total-width*(i+1))) & ((1 << width)-1)
        if signed and value & (1 << (width-1)):
            value -= 1 << width
        values.append(value)
    return values


def _decode_signature(data, n):
    bits = "".join(f"{byte:08b}" for byte in data)
    offset, result = 0, []
    for _ in range(n):
        if offset+8 > len(bits):
            raise ValueError("Falcon 压缩签名被截断")
        sign, value = int(bits[offset]), int(bits[offset+1:offset+8], 2)
        offset += 8
        while True:
            if offset == len(bits):
                raise ValueError("缺少压缩系数结束位")
            bit = bits[offset]
            offset += 1
            if bit == "1":
                break
            value += 128
            if value > 2047:
                raise ValueError("压缩系数超界")
        if sign and value == 0:
            raise ValueError("不允许负零编码")
        result.append(-value if sign else value)
    if len(bits)-offset >= 8 or "1" in bits[offset:]:
        raise ValueError("压缩签名含多余数据或非零填充")
    return result


def ring_multiply(a, b):
    n = len(a)
    result = [0]*n
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            position = i+j
            result[position % n] += x*y*(1 if position < n else -1)
    return [x % Q for x in result]


def _hash_point(nonce, message, n, trace):
    material = nonce+message
    stream, offset, point, decisions = hashlib.shake_256(material).digest(4*n), 0, [], []
    while len(point) < n:
        if offset+2 > len(stream):
            stream = hashlib.shake_256(material).digest(2*len(stream))
        candidate = int.from_bytes(stream[offset:offset+2], "big")
        offset += 2
        accepted = candidate < 5*Q
        decisions.append(dict(candidate=candidate, accepted=accepted))
        if accepted:
            point.append(candidate % Q)
    _record(trace, "哈希到点 c", "SHAKE256(nonce || M)，读取大端 16 位候选；接受 <5q 的值，再模 q", {
        "nonce": nonce, "message": message, "xof_input": material,
        "consumed_xof_bytes": stream[:offset], "candidate_decisions": decisions, "c": point},
        "Falcon common.c，hash_to_point_vartime")
    return point


def calculate(algorithm, message, public, signature, trace, secret=None):
    p = parameters(algorithm)
    n, log_n = p["n"], p["log_n"]
    if len(public) != p["public_key_bytes"] or not public or public[0] != log_n:
        return False
    if len(signature) < 42 or signature[0] != 0x30+log_n:
        return False
    h = _bits(public[1:], 14, n)
    if any(x >= Q for x in h):
        return False
    try:
        s2 = _decode_signature(signature[41:], n)
    except ValueError:
        return False
    _record(trace, "解码本次 Falcon 公钥与签名", "pk 解码为 h；σ 解码为 nonce、压缩短向量 s₂", {
        "public_key": public, "signature": signature, "nonce": signature[1:41],
        "h": h, "s2": s2}, "Falcon codec.c，modq_decode、comp_decode")
    if secret is not None:
        if len(secret) != p["secret_key_bytes"] or secret[0] != 0x50+log_n:
            raise ValueError("Falcon 临时私钥编码不符")
        width = 6 if n == 512 else 5
        size = width*n//8
        f = _bits(secret[1:1+size], width, n, True)
        g = _bits(secret[1+size:1+2*size], width, n, True)
        F = _bits(secret[1+2*size:], 8, n, True)
        relation = ring_multiply(f, h)
        matches = relation == [x % Q for x in g]
        _record(trace, "本轮 NTRU 密钥关系", "h=g/f mod (X^n+1,q)；验证 f·h=g mod q", {
            "f": f, "g": g, "F": F, "f_times_h": relation,
            "key_relation_matches": matches,
            "unavailable_randomness": "原生密钥生成与高斯采样的随机流未返回；显示本轮密钥和签名对应的确定值。"}, "Falcon complete_private、compute_public")
        if not matches:
            raise RuntimeError("Falcon 密钥关系重建失败")
    c = _hash_point(signature[1:41], message, n, trace)
    product = ring_multiply(s2, h)
    s1 = [(x-y) % Q for x, y in zip(c, product)]
    s1 = [x-Q if x > Q//2 else x for x in s1]
    _record(trace, "环乘积与恢复 s₁", "s₁=c−s₂·h mod (X^n+1,q)，再取中心代表；s₁+s₂·h=c mod q", {
        "s2": s2, "h": h, "ring_product": product, "c": c, "s1": s1}, "Falcon vrfy.c，verify_raw",
        f"乘积第 0 项 = s₂[0]·h[0]−Σ_(j=1..{n-1}) s₂[j]·h[{n}−j] mod q = {product[0]}；s₁[0]=center({c[0]}−{product[0]})={s1[0]}")
    norm = sum(x*x for x in s1)+sum(x*x for x in s2)
    valid = norm <= p["squared_norm_bound"]
    _record(trace, "短向量范数检查", "||s₁||²+||s₂||² ≤ 参数集的平方范数上界", {
        "s1": s1, "s2": s2, "squared_norm": norm, "norm_bound": p["squared_norm_bound"],
        "verified": valid}, "Falcon common.c，is_short")
    return valid


def verify(algorithm, message, public, signature, trace=None):
    try:
        return calculate(algorithm, message, public, signature, trace)
    except (ValueError, IndexError):
        return False
