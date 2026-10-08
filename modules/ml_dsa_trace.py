"""FIPS 204 arithmetic replay of an actual native ML-DSA signature.

Signing masks are algebraically reconstructed from z and the ephemeral key.
Unexposed native RNG inputs and rejected attempts are not invented.
"""

import hashlib

from modules.mlkem_trace import _record

SOURCE = "https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf"
Q = 8380417
SETS = {"ML-DSA-44": (4, 4, 2, 39, 78, 1 << 17, (Q-1)//88, 80, 32, 2),
        "ML-DSA-65": (6, 5, 4, 49, 196, 1 << 19, (Q-1)//32, 55, 48, 3),
        "ML-DSA-87": (8, 7, 2, 60, 120, 1 << 19, (Q-1)//32, 75, 64, 5)}


def parameters(algorithm):
    if algorithm not in SETS:
        raise ValueError("不支持的 ML-DSA 参数集")
    k, l, eta, tau, beta, gamma1, gamma2, omega, challenge_bytes, category = SETS[algorithm]
    eta_bits = 3 if eta == 2 else 4
    z_bits = gamma1.bit_length()
    return dict(n=256, q=Q, k=k, l=l, eta=eta, tau=tau, beta=beta,
                gamma1=gamma1, gamma2=gamma2, omega=omega, d=13, zeta=1753,
                nist_security_category=category, challenge_bytes=challenge_bytes,
                public_key_bytes=32+320*k, secret_key_bytes=128+32*eta_bits*(l+k)+416*k,
                signature_bytes=challenge_bytes+32*z_bits*l+omega+k,
                ring="Z_q[X]/(X^256+1)", hash="SHAKE256", matrix_xof="SHAKE128",
                context="空上下文；M′ = 0x00 || 0x00 || M",
                randomness_note="ρ/K 来自本轮密钥；y 从本轮签名反推。原生库不返回初始 ξ、rnd、ρ′ 或被拒绝的采样尝试。")


def ntt(coefficients, trace=None, label="NTT"):
    return _transform(coefficients, False, trace, label)


def inverse_ntt(coefficients, trace=None, label="逆 NTT"):
    return _transform(coefficients, True, trace, label)


def _transform(coefficients, inverse, trace, label):
    f = [x % Q for x in coefficients]
    scope = _record(trace, label, "ζ_i=1753^BitRev8(i) mod q；逆变换最后乘 256⁻¹ mod q", {
        "input_coefficients": f[:]}, "FIPS 204，算法 41–42")
    index, length = (255, 1) if inverse else (1, 128)
    while 1 <= length <= 128:
        before, zetas = f[:], []
        example = ""
        for start in range(0, 256, 2*length):
            zeta = pow(1753, int(f"{index:08b}"[::-1], 2), Q)
            zetas.append(zeta)
            index += -1 if inverse else 1
            for j in range(start, start+length):
                a, b = f[j], f[j+length]
                if inverse:
                    f[j], f[j+length] = (a+b) % Q, zeta*(b-a) % Q
                else:
                    t = zeta*b % Q
                    f[j], f[j+length] = (a+t) % Q, (a-t) % Q
                if not example:
                    example = f"j={j}，a={a}，b={b}，ζ_i={zeta} → ({f[j]},{f[j+length]})"
        _record(scope, f"{'逆' if inverse else ''}蝶形层 length={length}",
                "(a,b)→(a+b,ζ_i·(b−a)) mod q" if inverse else "t=ζ_i·b；(a,b)→(a+t,a−t) mod q",
                {"block_zetas": zetas, "input_coefficients": before, "output_coefficients": f[:]},
                "FIPS 204，算法 41–42", example)
        length = length*2 if inverse else length//2
    if inverse:
        before = f[:]
        f = [x*8347681 % Q for x in f]
        _record(scope, "逆变换归一化", "f[i]=f[i]·8347681 mod q", {
            "input_coefficients": before, "output_coefficients": f[:]}, "FIPS 204，算法 42")
    if scope is not None:
        scope.values["output_coefficients"] = f[:]
    return f


def _unpack(data, width):
    value = int.from_bytes(data, "little")
    return [(value >> (width*i)) & ((1 << width)-1) for i in range(256)]


def _pack(poly, width):
    return sum(x << (width*i) for i, x in enumerate(poly)).to_bytes(32*width, "little")


def _decode(p, public, signature):
    if len(public) != p["public_key_bytes"] or len(signature) != p["signature_bytes"]:
        raise ValueError("公钥或签名长度不符")
    k, l, omega = p["k"], p["l"], p["omega"]
    t1 = [_unpack(public[32+320*i:32+320*(i+1)], 10) for i in range(k)]
    cb, width = p["challenge_bytes"], p["gamma1"].bit_length()
    ctilde = signature[:cb]
    z = [[p["gamma1"]-x for x in _unpack(signature[cb+32*width*i:cb+32*width*(i+1)], width)] for i in range(l)]
    packed_h = signature[cb+32*width*l:]
    hints, previous = [], 0
    for i in range(k):
        end = packed_h[omega+i]
        if end < previous or end > omega:
            raise ValueError("提示计数编码不合法")
        indices = list(packed_h[previous:end])
        if indices != sorted(set(indices)):
            raise ValueError("提示索引必须严格递增")
        hints.append([int(j in indices) for j in range(256)])
        previous = end
    if any(packed_h[previous:omega]):
        raise ValueError("提示填充不为零")
    return public[:32], t1, ctilde, z, hints


def _matrix(p, rho, trace):
    scope = _record(trace, "由 ρ 展开矩阵 Â", "Â[i,j]=RejNTTPoly(SHAKE128(ρ || byte(j) || byte(i)))", {
        "rho": rho}, "FIPS 204，算法 30、32")
    matrix = []
    for i in range(p["k"]):
        row = []
        for j in range(p["l"]):
            seed = rho+bytes((j, i))
            stream, offset, poly, decisions = hashlib.shake_128(seed).digest(1024), 0, [], []
            while len(poly) < 256:
                if offset+3 > len(stream):
                    stream = hashlib.shake_128(seed).digest(len(stream)*2)
                candidate = int.from_bytes(stream[offset:offset+3], "little") & 0x7fffff
                decisions.append(dict(candidate=candidate, accepted=candidate < Q))
                if candidate < Q:
                    poly.append(candidate)
                offset += 3
            row.append(poly)
            _record(scope, f"Â[{i},{j}] 拒绝采样", "读取小端 23 位整数；仅接受候选值 < q，直到 256 项", {
                "xof_input": seed, "consumed_xof_bytes": stream[:offset],
                "candidate_decisions": decisions, "output_coefficients": poly}, "FIPS 204，算法 30")
        matrix.append(row)
    return matrix


def _challenge(seed, tau, trace):
    stream, offset = hashlib.shake_256(seed).digest(512), 8
    signs = int.from_bytes(stream[:8], "little")
    c, decisions = [0]*256, []
    for i in range(256-tau, 256):
        while True:
            if offset == len(stream):
                stream = hashlib.shake_256(seed).digest(len(stream)*2)
            j = stream[offset]
            offset += 1
            decisions.append(dict(i=i, candidate=j, accepted=j <= i))
            if j <= i:
                break
        c[i], c[j] = c[j], 1-2*(signs & 1)
        signs >>= 1
    _record(trace, "从承诺哈希采样挑战 c", "SampleInBall(c̃)：SHAKE256；τ 个非零系数，取值 ±1", {
        "c_tilde": seed, "consumed_xof_bytes": stream[:offset],
        "candidate_decisions": decisions, "c": c}, "FIPS 204，算法 29")
    return c


def _mat_vec(matrix, vector, trace, label):
    scope = _record(trace, label, "NTT⁻¹(Σ_j Â[i,j] ⊙ NTT(v[j]))；⊙ 为逐系数乘法", {}, "FIPS 204，算法 44–48")
    vhat = [ntt(poly, scope, f"NTT(v[{j}])") for j, poly in enumerate(vector)]
    result = []
    for i, row in enumerate(matrix):
        products = [[a*b % Q for a, b in zip(ahat, b)] for ahat, b in zip(row, vhat)]
        accumulated = [sum(values) % Q for values in zip(*products)]
        _record(scope, f"第 {i} 行 NTT 域乘积与求和", "Σ_j Â_ij ⊙ v̂_j mod q", {
            "products": products, "output_coefficients": accumulated}, "FIPS 204，算法 44–48")
        result.append(inverse_ntt(accumulated, scope, f"第 {i} 行逆 NTT"))
    return result


def _multiply(a, b):
    return inverse_ntt([x*y % Q for x, y in zip(ntt(a), ntt(b))])


def _center(x):
    x %= Q
    return x-Q if x > Q//2 else x


def _decompose(x, gamma2):
    x %= Q
    low = x % (2*gamma2)
    if low > gamma2:
        low -= 2*gamma2
    if x-low == Q-1:
        return 0, low-1
    return (x-low)//(2*gamma2), low


def _hint(h, x, gamma2):
    high, low = _decompose(x, gamma2)
    return (high + (1 if low > 0 else -1)) % ((Q-1)//(2*gamma2)) if h else high


def _compute(algorithm, message, public, signature, trace=None, context=b""):
    p = parameters(algorithm)
    rho, t1, ctilde, z, hints = _decode(p, public, signature)
    if len(context) > 255:
        raise ValueError("上下文超过 255 字节")
    formatted = b"\x00"+bytes((len(context),))+context+message
    tr = hashlib.shake_256(public).digest(64)
    mu = hashlib.shake_256(tr+formatted).digest(64)
    _record(trace, "解码本次公钥与签名", "pk=(ρ,t₁)；σ=(c̃,z,h)", {
        "public_key": public, "signature": signature, "rho": rho,
        "t1": t1, "c_tilde": ctilde, "z": z, "h": hints}, "FIPS 204，算法 23、27")
    _record(trace, "格式化消息与计算 μ", "M′=0x00 || byte(len(ctx)) || ctx || M；tr=SHAKE256(pk,64)；μ=SHAKE256(tr || M′,64)", {
        "message": message, "context": context, "formatted_message": formatted,
        "tr": tr, "mu_input": tr+formatted, "mu": mu}, "FIPS 204，算法 3、8")
    matrix = _matrix(p, rho, trace)
    c = _challenge(ctilde, p["tau"], trace)
    az = _mat_vec(matrix, z, trace, "验签：计算 A·z")
    r, w1 = [], []
    for i in range(p["k"]):
        ct = _multiply(c, [x << 13 for x in t1[i]])
        row = [(a-b) % Q for a, b in zip(az[i], ct)]
        high = [_hint(h, x, p["gamma2"]) for h, x in zip(hints[i], row)]
        r.append(row)
        w1.append(high)
        _record(trace, f"恢复承诺 w₁′[{i}]", "r=A·z−c·t₁·2^d mod q；w₁′=UseHint(h,r)", {
            "Az": az[i], "c_t1_2d": ct, "r": row, "h": hints[i], "w1_prime": high},
            "FIPS 204，算法 8、36、40", f"r[0]=({az[i][0]}−{ct[0]}) mod q={row[0]} → w₁′[0]={high[0]}")
    encoded = b"".join(_pack(poly, 6 if p["gamma2"] == (Q-1)//88 else 4) for poly in w1)
    recomputed = hashlib.shake_256(mu+encoded).digest(p["challenge_bytes"])
    norm = max(abs(x) for poly in z for x in poly)
    valid = norm < p["gamma1"]-p["beta"] and recomputed == ctilde
    _record(trace, "挑战与范数检查", "c̃′=SHAKE256(μ || w1Encode(w₁′),λ/4)；要求 c̃′=c̃ 且 ||z||∞<γ₁−β", {
        "encoded_w1": encoded, "challenge_hash_input": mu+encoded,
        "challenge_recomputed": recomputed, "challenge_original": ctilde,
        "challenge_matches": recomputed == ctilde, "z_norm": norm,
        "z_norm_bound": p["gamma1"]-p["beta"], "hint_weight": sum(map(sum, hints)),
        "verified": valid}, "FIPS 204，算法 8")
    return valid, dict(p=p, rho=rho, t1=t1, c=c, z=z, matrix=matrix, mu=mu, hints=hints, w1=w1)


def verify(algorithm, message, public, signature, trace=None, context=b""):
    try:
        return _compute(algorithm, message, public, signature, trace, context)[0]
    except (ValueError, IndexError):
        return False


def calculate(algorithm, message, public, signature, trace, secret=None):
    valid, state = _compute(algorithm, message, public, signature, trace)
    if secret is None or not valid:
        return valid
    p = state["p"]
    if len(secret) != p["secret_key_bytes"]:
        raise ValueError("ML-DSA 私钥长度不符")
    eta, width, offset = p["eta"], 3 if p["eta"] == 2 else 4, 128
    s1, s2, t0 = [], [], []
    for count, destination in ((p["l"], s1), (p["k"], s2)):
        for _ in range(count):
            destination.append([eta-x for x in _unpack(secret[offset:offset+32*width], width)])
            offset += 32*width
    for _ in range(p["k"]):
        t0.append([4096-x for x in _unpack(secret[offset:offset+416], 13)])
        offset += 416
    scope = _record(trace, "密钥与本次签名的计算重建", "从本轮临时私钥解码秘密向量；由 z=y+c·s₁ 还原实际被接受的 y", {
        "rho": secret[:32], "K": secret[32:64], "tr": secret[64:128],
        "s1": s1, "s2": s2, "t0": t0,
        "unavailable_randomness": "原生库未返回 ξ/rnd/ρ′ 或拒绝次数；以下 y 是本次被接受签名的代数重建。"}, "FIPS 204，算法 6–7、25")
    product = _mat_vec(state["matrix"], s1, scope, "密钥关系：A·s₁")
    t = [[(x+y) % Q for x, y in zip(row, error)] for row, error in zip(product, s2)]
    expected = [[(hi*8192+lo) % Q for hi, lo in zip(high, low)] for high, low in zip(state["t1"], t0)]
    key_matches = t == expected and secret[:32] == public[:32] and secret[64:128] == hashlib.shake_256(public).digest(64)
    _record(scope, "检验公开密钥关系", "t=A·s₁+s₂；Power2Round(t)=(t₁,t₀)；t=t₁·2^13+t₀ mod q", {
        "computed_t": t, "encoded_key_t": expected, "key_relation_matches": key_matches}, "FIPS 204，算法 6、35")
    cs1 = [_multiply(state["c"], poly) for poly in s1]
    y = [[_center(a-b) for a, b in zip(row, product)] for row, product in zip(state["z"], cs1)]
    _record(scope, "还原本次实际掩码 y", "y=z−c·s₁（在 R_q 中运算后取中心代表）", {
        "z": state["z"], "c_s1": cs1, "y_reconstructed": y}, "FIPS 204，算法 7 中 z=y+c·s₁",
        "这是从本次签名和临时私钥反推的被接受掩码，不是另一次随机采样。")
    w = _mat_vec(state["matrix"], y, scope, "签名承诺：w=A·y")
    w1 = [[_decompose(x, p["gamma2"])[0] for x in row] for row in w]
    encoded = b"".join(_pack(row, 6 if p["gamma2"] == (Q-1)//88 else 4) for row in w1)
    commitment_matches = hashlib.shake_256(state["mu"]+encoded).digest(p["challenge_bytes"]) == signature[:p["challenge_bytes"]]
    _record(scope, "重建签名承诺并与实际挑战比对", "w₁=HighBits(A·y)；c̃=SHAKE256(μ || w1Encode(w₁),λ/4)", {
        "w": w, "w1": w1, "encoded_w1": encoded,
        "signing_commitment_matches": commitment_matches,
        "mask_norm": max(abs(x) for row in y for x in row), "mask_bound": p["gamma1"]}, "FIPS 204，算法 7、28、37")
    if not key_matches or not commitment_matches:
        raise RuntimeError("ML-DSA 签名计算重建与本次密钥/签名不一致")
    return valid
