"""Inspectable final-FIPS-203 ML-KEM for teaching, not constant-time production use.

Every recorded value is an input or intermediate of the operation being performed.
The demo also checks interoperability with the installed native pqcrypto backend.
Source: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
"""

import hashlib
import os

Q = 3329
N = 256
PARAMETERS = {
    "ML-KEM-512": (2, 3, 2, 10, 4),
    "ML-KEM-768": (3, 2, 2, 10, 4),
    "ML-KEM-1024": (4, 2, 2, 11, 5),
}


class Trace:
    def __init__(self, steps=None, values=None):
        self.steps = [] if steps is None else steps
        self.values = {} if values is None else values

    def add(self, title, formula, values, reference, example=""):
        entry = dict(title=title, formula=formula, values=values,
                     reference=reference, example=example, children=[])
        self.steps.append(entry)
        return Trace(entry["children"], entry["values"])


def _record(trace, title, formula, values, reference, example=""):
    if trace is not None:
        return trace.add(title, formula, values, reference, example)
    return None


def _bitrev7(value):
    return int(f"{value:07b}"[::-1], 2)


def ntt(coefficients, trace=None, label="NTT"):
    f = [x % Q for x in coefficients]
    scope = _record(trace, label, "ζ = 17；ζ_i = ζ^BitRev7(i) mod q", {
        "input_coefficients": f[:]}, "FIPS 203，算法 9")
    index = 1
    length = 128
    while length >= 2:
        before = f[:]
        zetas = []
        example = ""
        for start in range(0, N, 2 * length):
            zeta = pow(17, _bitrev7(index), Q)
            zetas.append(zeta)
            index += 1
            for j in range(start, start + length):
                low, high = f[j], f[j + length]
                t = zeta * high % Q
                f[j] = (low + t) % Q
                f[j + length] = (low - t) % Q
                if not example:
                    example = (f"j={j}：t={zeta}×{high} mod {Q}={t}；"
                               f"({low}+{t}) mod q={f[j]}；"
                               f"({low}−{t}) mod q={f[j + length]}")
        _record(scope, f"蝶形层 length={length}",
                "t=ζ_i·f[j+length]；(f[j],f[j+length])=(f[j]+t,f[j]−t) mod q",
                {"block_zetas": zetas, "input_coefficients": before,
                 "output_coefficients": f[:]}, "FIPS 203，算法 9", example)
        length //= 2
    if scope is not None:
        scope.values["output_coefficients"] = f[:]
    return f


def inverse_ntt(coefficients, trace=None, label="逆 NTT"):
    f = [x % Q for x in coefficients]
    scope = _record(trace, label, "逆蝶形变换后乘 128⁻¹ mod q = 3303", {
        "input_coefficients": f[:]}, "FIPS 203，算法 10")
    index = 127
    length = 2
    while length <= 128:
        before = f[:]
        zetas = []
        example = ""
        for start in range(0, N, 2 * length):
            zeta = pow(17, _bitrev7(index), Q)
            zetas.append(zeta)
            index -= 1
            for j in range(start, start + length):
                low, high = f[j], f[j + length]
                f[j] = (low + high) % Q
                f[j + length] = zeta * (high - low) % Q
                if not example:
                    example = (f"j={j}：({low}+{high}) mod q={f[j]}；"
                               f"{zeta}×({high}−{low}) mod q={f[j + length]}")
        _record(scope, f"逆蝶形层 length={length}",
                "(a,b) → (a+b,ζ_i·(b−a)) mod q", {
                    "block_zetas": zetas, "input_coefficients": before,
                    "output_coefficients": f[:]}, "FIPS 203，算法 10", example)
        length *= 2
    before = f[:]
    f = [x * 3303 % Q for x in f]
    _record(scope, "归一化", "f[i] = f[i]·3303 mod q", {
        "scale": 3303, "input_coefficients": before, "output_coefficients": f[:]},
        "FIPS 203，算法 10", f"f[0]={before[0]}×3303 mod q={f[0]}")
    if scope is not None:
        scope.values["output_coefficients"] = f[:]
    return f


def multiply_ntt(a, b, trace=None, label="NTT 域乘法"):
    output = []
    gammas = []
    for i in range(128):
        gamma = pow(17, 2 * _bitrev7(i) + 1, Q)
        gammas.append(gamma)
        a0, a1 = a[2 * i:2 * i + 2]
        b0, b1 = b[2 * i:2 * i + 2]
        output.extend(((a0 * b0 + a1 * b1 * gamma) % Q,
                       (a0 * b1 + a1 * b0) % Q))
    _record(trace, label,
            "γ_i=17^(2·BitRev7(i)+1)；h[2i]=a₀b₀+γ_i·a₁b₁；h[2i+1]=a₀b₁+a₁b₀ mod q",
            {"a": a[:], "b": b[:], "gammas": gammas, "output_coefficients": output[:]},
            "FIPS 203，算法 11–12",
            f"h[0]=({a[0]}×{b[0]}+{gammas[0]}×{a[1]}×{b[1]}) mod q={output[0]}；"
            f"h[1]=({a[0]}×{b[1]}+{a[1]}×{b[0]}) mod q={output[1]}")
    return output


def byte_encode(coefficients, width):
    packed = sum((x % (Q if width == 12 else 1 << width)) << (width * i)
                 for i, x in enumerate(coefficients))
    return packed.to_bytes(len(coefficients) * width // 8, "little")


def byte_decode(encoded, width):
    packed = int.from_bytes(encoded, "little")
    mask = (1 << width) - 1
    modulus = Q if width == 12 else 1 << width
    return [((packed >> (width * i)) & mask) % modulus for i in range(N)]


def compress(value, width):
    return (((value % Q) * (1 << width) + Q // 2) // Q) % (1 << width)


def decompress(value, width):
    return (Q * value + (1 << (width - 1))) >> width


def _add(*polynomials):
    return [sum(xs) % Q for xs in zip(*polynomials)]


def _dot(a, b, trace=None, label="向量内积"):
    scope = _record(trace, label, "Σ_j MultiplyNTTs(a_j,b_j) mod q", {},
                    "FIPS 203，算法 11、13–15")
    products = [multiply_ntt(x, y, scope, f"第 {i} 个乘积") for i, (x, y) in enumerate(zip(a, b))]
    result = _add(*products)
    if scope is not None:
        scope.values["output_coefficients"] = result[:]
    return result


class MLKEM:
    def __init__(self, algorithm):
        if algorithm not in PARAMETERS:
            raise ValueError(f"不支持的 ML-KEM 参数集：{algorithm}")
        self.algorithm = algorithm
        self.k, self.eta1, self.eta2, self.du, self.dv = PARAMETERS[algorithm]
        self.pk_size = 384 * self.k + 32
        self.sk_size = 768 * self.k + 96
        self.ct_size = 32 * (self.du * self.k + self.dv)

    def parameters(self):
        return dict(n=N, q=Q, k=self.k, eta1=self.eta1, eta2=self.eta2,
                    du=self.du, dv=self.dv, ring="Z_q[X]/(X^256+1)", zeta=17,
                    nist_security_category={2: 1, 3: 3, 4: 5}[self.k],
                    inverse_ntt_scale=3303, public_key_bytes=self.pk_size,
                    secret_key_bytes=self.sk_size, ciphertext_bytes=self.ct_size,
                    shared_secret_bytes=32, seed_bytes=32,
                    H="SHA3-256", G="SHA3-512", J="SHAKE256（输出 32 字节）",
                    XOF="SHAKE128", PRF="SHAKE256（输出 64·η 字节）")

    def _matrix(self, rho, trace):
        scope = _record(trace, "生成矩阵 Â", "Â[i,j]=SampleNTT(SHAKE128(ρ || byte(j) || byte(i)))",
                        {"rho": rho}, "FIPS 203，算法 7、13–14")
        matrix = []
        for i in range(self.k):
            row = []
            for j in range(self.k):
                xof_input = rho + bytes((j, i))
                length = 768
                stream = hashlib.shake_128(xof_input).digest(length)
                offset = 0
                coefficients = []
                decisions = []
                while len(coefficients) < N:
                    if offset + 3 > len(stream):
                        length *= 2
                        stream = hashlib.shake_128(xof_input).digest(length)
                    c0, c1, c2 = stream[offset:offset + 3]
                    candidates = (c0 + 256 * (c1 % 16), c1 // 16 + 16 * c2)
                    for candidate in candidates:
                        accepted = candidate < Q
                        decisions.append(dict(byte_offset=offset, candidate=candidate, accepted=accepted))
                        if accepted:
                            coefficients.append(candidate)
                        if len(coefficients) == N:
                            break
                    offset += 3
                row.append(coefficients)
                _record(scope, f"Â[{i},{j}]：拒绝采样",
                        "d₁=C₀+256·(C₁ mod 16)；d₂=⌊C₁/16⌋+16·C₂；仅接受 d<q，直到 256 项",
                        {"xof_input": xof_input, "consumed_xof_bytes": stream[:offset],
                         "candidate_decisions": decisions, "output_coefficients": coefficients[:],
                         "accepted_count": N, "rejected_count": sum(not d["accepted"] for d in decisions)},
                        "FIPS 203，算法 7",
                        f"首个候选值 {decisions[0]['candidate']}："
                        f"{'接受' if decisions[0]['accepted'] else '拒绝'}（q={Q}）")
            matrix.append(row)
        if scope is not None:
            scope.values["A_hat"] = matrix
        return matrix

    def _noise(self, seed, nonce, eta, trace, label):
        prf_input = seed + bytes((nonce,))
        stream = hashlib.shake_256(prf_input).digest(64 * eta)
        bits = [(x >> bit) & 1 for x in stream for bit in range(8)]
        centered = []
        for i in range(N):
            start = 2 * eta * i
            centered.append(sum(bits[start:start + eta]) - sum(bits[start + eta:start + 2 * eta]))
        coefficients = [x % Q for x in centered]
        _record(trace, label,
                "B=SHAKE256(seed || byte(N),64·η)；f[i]=Σ_{j=0}^{η−1}b[2ηi+j]−Σ_{j=0}^{η−1}b[2ηi+η+j] mod q",
                {"seed": seed, "nonce": nonce, "eta": eta, "prf_input": prf_input,
                 "prf_output": stream, "centered_coefficients": centered,
                 "output_coefficients": coefficients[:]}, "FIPS 203，算法 8、PRF_η",
                f"f[0]={sum(bits[:eta])}−{sum(bits[eta:2 * eta])}={centered[0]}；mod q={coefficients[0]}")
        return coefficients

    def keygen(self, d, z, trace=None):
        if len(d) != 32 or len(z) != 32:
            raise ValueError("d、z 必须各为 32 字节随机种子")
        scope = _record(trace, "密钥生成", "(ρ,σ)=G(d || byte(k))；t̂=Â·ŝ+ê", {},
                        "FIPS 203，算法 13、16、19")
        g_input = d + bytes((self.k,))
        expanded = hashlib.sha3_512(g_input).digest()
        rho, sigma = expanded[:32], expanded[32:]
        _record(scope, "展开随机种子", "G=SHA3-512；前 32 字节为 ρ，后 32 字节为 σ", {
            "d": d, "k": self.k, "G_input": g_input, "G_output": expanded,
            "rho": rho, "sigma": sigma}, "FIPS 203，算法 13 第 1 行")
        matrix = self._matrix(rho, scope)
        noise_scope = _record(scope, "采样秘密向量 s 与误差 e", "s_i=CBD_η₁(PRF_η₁(σ,i))；e_i=CBD_η₁(PRF_η₁(σ,k+i))",
                              {}, "FIPS 203，算法 13")
        s = [self._noise(sigma, i, self.eta1, noise_scope, f"s[{i}]") for i in range(self.k)]
        e = [self._noise(sigma, self.k + i, self.eta1, noise_scope, f"e[{i}]") for i in range(self.k)]
        s_hat = [ntt(p, scope, f"ŝ[{i}]=NTT(s[{i}])") for i, p in enumerate(s)]
        e_hat = [ntt(p, scope, f"ê[{i}]=NTT(e[{i}])") for i, p in enumerate(e)]
        t_hat = []
        for i in range(self.k):
            product = _dot(matrix[i], s_hat, scope, f"Â 第 {i} 行与 ŝ 的内积")
            t = _add(product, e_hat[i])
            t_hat.append(t)
            _record(scope, f"t̂[{i}]=内积+ê[{i}]", "t̂_i=(Σ_j Â_ij·ŝ_j+ê_i) mod q", {
                "matrix_product": product, "e_hat": e_hat[i], "output_coefficients": t},
                "FIPS 203，算法 13", f"t̂[{i}][0]=({product[0]}+{e_hat[i][0]}) mod q={t[0]}")
        ek_pke = b"".join(byte_encode(p, 12) for p in t_hat) + rho
        dk_pke = b"".join(byte_encode(p, 12) for p in s_hat)
        h = hashlib.sha3_256(ek_pke).digest()
        dk = dk_pke + ek_pke + h + z
        _record(scope, "编码与封装密钥", "ek=ByteEncode₁₂(t̂) || ρ；dk=ByteEncode₁₂(ŝ) || ek || H(ek) || z", {
            "encoding_bits_per_coefficient": 12, "ek": ek_pke, "dk_PKE": dk_pke,
            "H_ek": h, "z": z, "dk": dk}, "FIPS 203，算法 5、13、16",
            f"t̂[0] 的前两项 {t_hat[0][:2]} 编码为 {byte_encode(t_hat[0], 12)[:3].hex()}（小端 12 位打包）")
        return ek_pke, dk

    def _check_public(self, ek):
        if len(ek) != self.pk_size:
            raise ValueError(f"公钥长度应为 {self.pk_size} 字节")
        encoded = ek[:-32]
        decoded = [byte_decode(encoded[384 * i:384 * (i + 1)], 12) for i in range(self.k)]
        if b"".join(byte_encode(p, 12) for p in decoded) != encoded:
            raise ValueError("公钥系数不满足标准模数检查（必须小于 q）")
        return decoded, ek[-32:]

    def _encode_compressed(self, polynomials, width, trace, label):
        encoded = []
        for i, polynomial in enumerate(polynomials):
            compressed = [compress(x, width) for x in polynomial]
            data = byte_encode(compressed, width)
            encoded.append(data)
            _record(trace, f"{label}[{i}]：压缩与编码",
                    "Compress_d(x)=round(2^d·x/q) mod 2^d；ByteEncode_d 按小端位序打包",
                    {"d": width, "input_coefficients": polynomial[:],
                     "compressed_coefficients": compressed, "encoded_bytes": data},
                    "FIPS 203，§4.2.1、算法 5、14",
                    f"x[0]={polynomial[0]} → Compress_{width}={compressed[0]}；前 8 编码字节={data[:8].hex()}")
        return b"".join(encoded)

    def _encrypt(self, ek, m, coins, trace=None):
        t_hat, rho = self._check_public(ek)
        _record(trace, "解码公钥", "t̂=ByteDecode₁₂(ek[0:384k])；ρ=ek[384k:]", {
            "t_hat": t_hat, "rho": rho}, "FIPS 203，算法 6、14")
        matrix = self._matrix(rho, trace)
        noise_scope = _record(trace, "采样临时向量 y 与误差 e₁、e₂", "以 r 为 PRF 种子；nonce 依次为 0…2k", {
            "r": coins}, "FIPS 203，算法 14")
        y = [self._noise(coins, i, self.eta1, noise_scope, f"y[{i}]") for i in range(self.k)]
        e1 = [self._noise(coins, self.k + i, self.eta2, noise_scope, f"e₁[{i}]") for i in range(self.k)]
        e2 = self._noise(coins, 2 * self.k, self.eta2, noise_scope, "e₂")
        y_hat = [ntt(p, trace, f"ŷ[{i}]=NTT(y[{i}])") for i, p in enumerate(y)]
        u = []
        for i in range(self.k):
            product = _dot([matrix[j][i] for j in range(self.k)], y_hat, trace, f"Âᵀ 第 {i} 行与 ŷ 的内积")
            ordinary = inverse_ntt(product, trace, f"u[{i}] 的逆 NTT")
            polynomial = _add(ordinary, e1[i])
            u.append(polynomial)
            _record(trace, f"u[{i}]=NTT⁻¹(Âᵀ·ŷ)[{i}]+e₁[{i}]", "所有系数模 q", {
                "inverse_ntt": ordinary, "e1": e1[i], "output_coefficients": polynomial},
                "FIPS 203，算法 14")
        message_bits = byte_decode(m, 1)
        mu = [decompress(bit, 1) for bit in message_bits]
        _record(trace, "把随机消息 m 映射为多项式 μ", "μ=Decompress₁(ByteDecode₁(m))；0→0，1→1665", {
            "m": m, "message_bits": message_bits, "mu": mu}, "FIPS 203，算法 14",
            "m 是 ML-KEM 封装的 32 字节随机输入；混合加密页面中的用户消息由 AES-GCM 单独加密。")
        product = _dot(t_hat, y_hat, trace, "t̂ 与 ŷ 的内积")
        ordinary = inverse_ntt(product, trace, "v 的逆 NTT")
        v = _add(ordinary, e2, mu)
        _record(trace, "计算 v", "v=NTT⁻¹(t̂ᵀ·ŷ)+e₂+μ mod q", {
            "inverse_ntt": ordinary, "e2": e2, "mu": mu, "output_coefficients": v},
            "FIPS 203，算法 14",
            f"v[0]=({ordinary[0]}+{e2[0]}+{mu[0]}) mod q={v[0]}")
        c1 = self._encode_compressed(u, self.du, trace, "u")
        c2 = self._encode_compressed([v], self.dv, trace, "v")
        c = c1 + c2
        _record(trace, "拼接 KEM 密文", "c=c₁ || c₂", {"c1": c1, "c2": c2, "c": c},
                "FIPS 203，算法 14", f"{len(c1)}+{len(c2)}={len(c)} 字节")
        return c

    def encaps(self, ek, m, trace=None):
        self._check_public(ek)
        if len(m) != 32:
            raise ValueError("封装随机消息 m 必须为 32 字节")
        scope = _record(trace, "封装", "(K,r)=G(m || H(ek))；c=K-PKE.Encrypt(ek,m,r)", {},
                        "FIPS 203，算法 14、17、20")
        h = hashlib.sha3_256(ek).digest()
        expanded = hashlib.sha3_512(m + h).digest()
        key, coins = expanded[:32], expanded[32:]
        _record(scope, "派生共享秘密 K 与加密随机性 r", "H=SHA3-256；G=SHA3-512；G 输出分成两个 32 字节值", {
            "m": m, "H_ek": h, "G_input": m + h, "G_output": expanded,
            "K": key, "r": coins}, "FIPS 203，算法 17")
        return self._encrypt(ek, m, coins, scope), key

    def _decrypt(self, dk_pke, c, trace):
        u = []
        for i in range(self.k):
            encoded = c[32 * self.du * i:32 * self.du * (i + 1)]
            compressed = byte_decode(encoded, self.du)
            polynomial = [decompress(x, self.du) for x in compressed]
            u.append(polynomial)
            _record(trace, f"解码与解压 u′[{i}]", "u′=Decompress_du(ByteDecode_du(c₁))", {
                "encoded_bytes": encoded, "d": self.du, "compressed_coefficients": compressed,
                "output_coefficients": polynomial}, "FIPS 203，算法 6、15",
                f"{compressed[0]}×q/2^{self.du} 四舍五入 → {polynomial[0]}")
        encoded_v = c[32 * self.du * self.k:]
        compressed_v = byte_decode(encoded_v, self.dv)
        v = [decompress(x, self.dv) for x in compressed_v]
        _record(trace, "解码与解压 v′", "v′=Decompress_dv(ByteDecode_dv(c₂))", {
            "encoded_bytes": encoded_v, "d": self.dv, "compressed_coefficients": compressed_v,
            "output_coefficients": v}, "FIPS 203，算法 15")
        s_hat = [byte_decode(dk_pke[384 * i:384 * (i + 1)], 12) for i in range(self.k)]
        _record(trace, "从解封装密钥中解码 ŝ", "ŝ=ByteDecode₁₂(dk_PKE)", {"s_hat": s_hat},
                "FIPS 203，算法 15")
        u_hat = [ntt(p, trace, f"û′[{i}]=NTT(u′[{i}])") for i, p in enumerate(u)]
        product = _dot(s_hat, u_hat, trace, "ŝ 与 û′ 的内积")
        ordinary = inverse_ntt(product, trace, "秘密乘积的逆 NTT")
        w = [(x - y) % Q for x, y in zip(v, ordinary)]
        bits = [compress(x, 1) for x in w]
        m = byte_encode(bits, 1)
        _record(trace, "恢复消息 m′", "w=v′−NTT⁻¹(ŝᵀ·NTT(u′)) mod q；m′=ByteEncode₁(Compress₁(w))", {
            "v_prime": v, "secret_product": ordinary, "w": w,
            "recovered_bits": bits, "m_prime": m}, "FIPS 203，算法 15",
            f"w[0]=({v[0]}−{ordinary[0]}) mod q={w[0]} → bit={bits[0]}")
        return m

    def decaps(self, dk, c, trace=None, label="解封装"):
        if len(dk) != self.sk_size or len(c) != self.ct_size:
            raise ValueError(f"解封装要求私钥 {self.sk_size} 字节、密文 {self.ct_size} 字节")
        dk_pke = dk[:384 * self.k]
        ek = dk[384 * self.k:-64]
        h, z = dk[-64:-32], dk[-32:]
        if hashlib.sha3_256(ek).digest() != h:
            raise ValueError("解封装密钥中的公钥哈希检查失败")
        scope = _record(trace, label, "解密恢复 m′，派生候选 K′，重加密比对；不匹配时使用 J(z || c)", {
            "c": c, "embedded_public_key_hash_valid": True}, "FIPS 203，算法 15、18、21")
        m = self._decrypt(dk_pke, c, scope)
        expanded = hashlib.sha3_512(m + h).digest()
        candidate, coins = expanded[:32], expanded[32:]
        rejection = hashlib.shake_256(z + c).digest(32)
        reencryption = self._encrypt(ek, m, coins)
        matches = c == reencryption
        selected = candidate if matches else rejection
        _record(scope, "重加密检查与隐式拒绝", "(K′,r′)=G(m′ || h)；c′=Encrypt(ek,m′,r′)；K_reject=J(z || c)", {
            "m_prime": m, "h": h, "G_input": m + h, "G_output": expanded,
            "K_candidate": candidate, "r_prime": coins, "z": z, "J_input": z + c,
            "K_reject": rejection, "c_received": c, "c_reencrypted": reencryption,
            "ciphertext_matches": matches, "selected_K": selected}, "FIPS 203，算法 18",
            "重加密使用与封装相同的矩阵、采样、NTT 和压缩公式；"
            + ("c′=c，选择候选 K′。" if matches else "c′≠c，选择 K_reject（隐式拒绝）。"))
        return selected


def run_calculation(algorithm, native):
    """Run a real ephemeral calculation, recording it and checking native agreement."""
    engine = MLKEM(algorithm)
    trace = Trace()
    d, z, m = (os.urandom(32) for _ in range(3))
    _record(trace, "本次运行的随机输入", "d,z,m ← 系统密码学随机源，各 32 字节；随后所有随机性由它们派生", {
        "d": d, "z": z, "m": m}, "FIPS 203，算法 19–20")
    public, secret = engine.keygen(d, z, trace)
    ciphertext, sender = engine.encaps(public, m, trace)
    receiver = engine.decaps(secret, ciphertext, trace)
    changed = bytearray(ciphertext)
    changed[0] ^= 1
    _record(trace, "篡改试验", "c_tampered[0]=c[0] XOR 0x01", {
        "original_first_byte": ciphertext[0], "tampered_first_byte": changed[0]},
        "本项目演示操作")
    rejected = engine.decaps(secret, bytes(changed), trace, "篡改密文的解封装")
    native_sender_ct, native_sender_key = native.encrypt(public)
    checks = {
        "native_decaps_matches": native.decrypt(secret, ciphertext) == sender,
        "native_rejection_matches": native.decrypt(secret, bytes(changed)) == rejected,
        "native_encaps_matches": engine.decaps(secret, native_sender_ct) == native_sender_key,
        "sender_receiver_match": sender == receiver,
    }
    if not all(checks.values()):
        raise RuntimeError("ML-KEM 教学计算与原生库交叉校验失败")
    _record(trace, "原生库交叉校验", "教学实现生成的密钥/密文由 pqcrypto 解封装；原生库生成的密文由教学实现解封装", checks,
            "本项目互操作验证")
    return dict(public_key=public, ciphertext=ciphertext, sender_shared=sender,
                receiver_shared=receiver, changed_shared=rejected, native_verified=True,
                trace=dict(algorithm=algorithm, parameters=engine.parameters(), steps=trace.steps,
                           source="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf"))
