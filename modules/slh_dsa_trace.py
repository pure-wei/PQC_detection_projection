"""Replay the SPHINCS+ simple backend used by the application's SLH pages.

This follows the actual backend's raw-message/LSB-first FORS interface, which
differs from the final FIPS 205 external message formatting. No false claim
of FIPS-interface interoperability is made.
"""

import hashlib

from modules.mlkem_trace import _record

SOURCE = "https://github.com/PQClean/PQClean/tree/master/crypto_sign"
SETS = {"128s": (16, 63, 7, 12, 14), "128f": (16, 66, 22, 6, 33),
        "192s": (24, 63, 7, 14, 17), "192f": (24, 66, 22, 8, 33),
        "256s": (32, 64, 8, 14, 22), "256f": (32, 68, 17, 9, 35)}


def parameters(algorithm):
    parts = algorithm.rsplit("-", 2)
    if len(parts) != 3 or parts[0] != "SLH-DSA" or parts[1] not in ("SHA2", "SHAKE") or parts[2] not in SETS:
        raise ValueError("不支持的 SLH 参数集")
    n, h, d, a, k = SETS[parts[2]]
    length = 2*n+3
    return dict(n=n, h=h, d=d, h_prime=h//d, a=a, k=k, w=16, lg_w=4,
                wots_len1=2*n, wots_len2=3, wots_len=length,
                nist_security_category={16: 1, 24: 3, 32: 5}[n], hash_family=parts[1],
                public_key_bytes=2*n, secret_key_bytes=4*n,
                signature_bytes=n*(1+k*(a+1)+d*(length+h//d)),
                backend="pqcrypto SPHINCS+ simple；沿用页面 SLH 参数名",
                message_encoding="后端直接签名原始 M；FORS 索引按低位优先读取，与 FIPS 205 外部接口不同。",
                randomness_note="SK.seed、SK.prf、PK.seed 为本轮实际种子；R 来自签名。原生库不返回 optrand。")


def _address(p, layer, tree, kind, keypair=0, height=0, index=0):
    if p["hash_family"] == "SHA2":
        return bytes((layer,))+tree.to_bytes(8, "big")+bytes((kind,))+keypair.to_bytes(4, "big")+height.to_bytes(4, "big")+index.to_bytes(4, "big")
    return layer.to_bytes(4, "big")+b"\x00"*4+tree.to_bytes(8, "big")+kind.to_bytes(4, "big")+keypair.to_bytes(4, "big")+height.to_bytes(4, "big")+index.to_bytes(4, "big")


def _thash(p, seed, address, data):
    n = p["n"]
    if p["hash_family"] == "SHAKE":
        material = seed+address+data
        return hashlib.shake_256(material).digest(n), material, "SHAKE256，输出 n 字节"
    large = n >= 24 and len(data) > n
    block = 128 if large else 64
    material = seed+b"\x00"*(block-n)+address+data
    digest = hashlib.sha512 if large else hashlib.sha256
    return digest(material).digest()[:n], material, ("SHA512" if large else "SHA256")+"，截取前 n 字节"


def _prf(p, seed, secret_seed, address):
    material = seed+address+secret_seed
    if p["hash_family"] == "SHAKE":
        return hashlib.shake_256(material).digest(p["n"])
    material = seed+b"\x00"*(64-p["n"])+address+secret_seed
    return hashlib.sha256(material).digest()[:p["n"]]


def _message_digest(p, R, public, message, trace):
    n, hp = p["n"], p["h_prime"]
    md_bytes = (p["a"]*p["k"]+7)//8
    tree_bits = p["h"]-hp
    tree_bytes, leaf_bytes = (tree_bits+7)//8, (hp+7)//8
    length = md_bytes+tree_bytes+leaf_bytes
    material = R+public+message
    values = {"R": R, "public_key": public, "message": message, "hash_input": material}
    if p["hash_family"] == "SHAKE":
        digest = hashlib.shake_256(material).digest(length)
        formula = "H_msg=SHAKE256(R || PK.seed || PK.root || M,m)"
    else:
        function = hashlib.sha256 if n == 16 else hashlib.sha512
        first = function(material).digest()
        seed = R+public[:n]+first
        blocks = [function(seed+i.to_bytes(4, "big")).digest() for i in range((length+function().digest_size-1)//function().digest_size)]
        digest = b"".join(blocks)[:length]
        values.update(message_hash=first, mgf1_seed=seed, mgf1_blocks=blocks)
        formula = "seed=SHA-X(R || PK.seed || PK.root || M)；H_msg=MGF1-SHA-X(R || PK.seed || seed,m)"
    md = digest[:md_bytes]
    tree = int.from_bytes(digest[md_bytes:md_bytes+tree_bytes], "big") & ((1 << tree_bits)-1)
    leaf = int.from_bytes(digest[-leaf_bytes:], "big") & ((1 << hp)-1)
    indices = [(int.from_bytes(md, "little") >> (p["a"]*i)) & ((1 << p["a"])-1) for i in range(p["k"])]
    values.update(digest=digest, fors_digest=md, tree_index=hex(tree), leaf_index=leaf, fors_indices=indices)
    _record(trace, "计算消息摘要与 FORS/树索引", formula+"；后端 FORS 摘要按低位优先分组", values,
            "PQClean hash_message、message_to_indices（实际 SPHINCS+ 后端）")
    return tree, leaf, indices


def _path(p, seed, node, auth, leaf, offset, layer, tree, kind, keypair, trace):
    original_leaf = leaf
    for level, sibling in enumerate(auth):
        left, right = (sibling, node) if ((original_leaf >> level) & 1) else (node, sibling)
        index = (original_leaf+offset) >> (level+1)
        address = _address(p, layer, tree, kind, keypair, level+1, index)
        node, material, method = _thash(p, seed, address, left+right)
        _record(trace, f"认证路径第 {level+1} 层", "按叶索引对应位决定左右顺序；父节点=H(PK.seed,ADRS,left || right)", {
            "address": address, "left": left, "right": right, "hash_input": material,
            "hash_function": method, "parent": node}, "PQClean compute_root、thash")
    return node


def _wots(p, seed, message, signature, layer, tree, leaf, trace, secret_seed=None):
    n = p["n"]
    digits = [part for x in message for part in (x >> 4, x & 15)]
    checksum = sum(15-x for x in digits)
    lengths = digits+[(checksum >> shift) & 15 for shift in (8, 4, 0)]
    scope = _record(trace, "WOTS+ 哈希链与公钥恢复", "消息转为 base-16 数位，加校验和；从签名链位置走到第 15 步", {
        "signed_root": message, "checksum": checksum, "chain_lengths": lengths}, "PQClean chain_lengths、wots_pk_from_sig")
    public_parts = []
    for i, start in enumerate(lengths):
        piece = signature[i*n:(i+1)*n]
        node, chain = piece, [piece]
        signing_values = {}
        if secret_seed is not None:
            prf_address = _address(p, layer, tree, 5, leaf, i, 0)
            signing_node = _prf(p, seed, secret_seed, prf_address)
            signing_chain = [signing_node]
            for j in range(start):
                signing_node = _thash(p, seed, _address(p, layer, tree, 0, leaf, i, j), signing_node)[0]
                signing_chain.append(signing_node)
            signing_values = dict(prf_address=prf_address, signing_chain_values=signing_chain,
                                  signing_component_matches=signing_node == piece)
            if signing_node != piece:
                raise RuntimeError("WOTS+ 签名链重建与实际签名不一致")
        addresses = []
        for j in range(start, 15):
            address = _address(p, layer, tree, 0, leaf, i, j)
            addresses.append(address)
            node = _thash(p, seed, address, node)[0]
            chain.append(node)
        public_parts.append(node)
        _record(scope, f"链 {i}：签名位置 {start} → 15", "x_{j+1}=F(PK.seed,ADRS(chain=i,hash=j),x_j)", {
            "chain_index": i, "start_step": start, "signature_component": piece,
            "chain_addresses": addresses, "chain_values": chain, "chain_public_value": node,
            **signing_values}, "PQClean WOTS+ simple",
            "签名侧从本轮 SK.seed 的 PRF 值前进至签名位置；验签侧从签名位置前进至链尾。" if secret_seed is not None else "验签从签名位置前进至链尾。")
    address = _address(p, layer, tree, 1, leaf)
    node, material, method = _thash(p, seed, address, b"".join(public_parts))
    _record(scope, "压缩 WOTS+ 公钥为 XMSS 叶节点", "leaf=T_len(PK.seed,ADRS_WOTSPK,所有链尾)", {
        "address": address, "chain_public_values": public_parts, "hash_input": material,
        "hash_function": method, "xmss_leaf": node}, "PQClean thash、WOTSPK 地址类型")
    return node


def calculate(algorithm, message, public, signature, trace, secret=None):
    p = parameters(algorithm)
    n = p["n"]
    if len(public) != 2*n or len(signature) != p["signature_bytes"]:
        return False
    seed, expected_root, R = public[:n], public[n:], signature[:n]
    secret_seed = None
    if secret is not None:
        if len(secret) != 4*n or secret[2*n:] != public:
            raise ValueError("SPHINCS+ 临时私钥与公钥不匹配")
        secret_seed = secret[:n]
    _record(trace, "解码实际密钥与随机化值 R", "pk=PK.seed || PK.root；σ=R || SIG_FORS || SIG_HT", {
        "public_key": public, "signature": signature, "PK_seed": seed, "PK_root": expected_root,
        "R": R, **({"SK_seed": secret[:n], "SK_prf": secret[n:2*n]} if secret is not None else {}),
        "optrand": "原生库未返回；R 是本次签名中的真实随机化值，不代填 optrand。"},
        "PQClean SPHINCS+ simple 密钥/签名布局")
    tree, leaf, indices = _message_digest(p, R, public, message, trace)
    scope = _record(trace, "FORS 签名与公钥恢复", "k 棵高度 a 的树；每棵给出秘密叶输入和 a 个认证节点", {}, "PQClean fors_pk_from_sig")
    roots, offset = [], n
    for i, index in enumerate(indices):
        tree_scope = _record(scope, f"FORS 树 {i}，选择叶 {index}", "全局叶索引=树号·2^a+摘要选择的叶索引", {}, "PQClean FORS")
        piece = signature[offset:offset+n]
        offset += n
        address = _address(p, 0, tree, 3, leaf, 0, index+i*(1 << p["a"]))
        node, material, method = _thash(p, seed, address, piece)
        values = dict(signature_secret=piece, address=address, hash_input=material, hash_function=method, fors_leaf=node)
        if secret_seed is not None:
            prf_address = _address(p, 0, tree, 6, leaf, 0, index+i*(1 << p["a"]))
            generated = _prf(p, seed, secret_seed, prf_address)
            values.update(prf_address=prf_address, derived_secret=generated, signing_component_matches=generated == piece)
            if generated != piece:
                raise RuntimeError("FORS 秘密叶重建与实际签名不一致")
        _record(tree_scope, "秘密输入生成叶节点", "leaf=F(PK.seed,ADRS,SIG_sk)", values, "PQClean fors_sk_to_leaf、prf_addr")
        auth = [signature[offset+n*j:offset+n*(j+1)] for j in range(p["a"])]
        offset += n*p["a"]
        roots.append(_path(p, seed, node, auth, index, i*(1 << p["a"]), 0, tree, 3, leaf, tree_scope))
    address = _address(p, 0, tree, 4, leaf)
    root, material, method = _thash(p, seed, address, b"".join(roots))
    _record(scope, "压缩 FORS 树根", "PK_FORS=T_k(PK.seed,ADRS_FORSPK,roots)", {
        "fors_roots": roots, "hash_input": material, "hash_function": method, "fors_public_key": root}, "PQClean FORSPK")
    for layer in range(p["d"]):
        layer_scope = _record(trace, f"超树 XMSS 层 {layer}", "WOTS+ 签名下层根；经认证路径恢复本层根，直到 PK.root", {
            "xmss_layer": layer, "tree_index": hex(tree), "leaf_index": leaf, "input_root": root}, "PQClean crypto_sign_verify 超树循环")
        wots_size = n*p["wots_len"]
        node = _wots(p, seed, root, signature[offset:offset+wots_size], layer, tree, leaf, layer_scope, secret_seed)
        offset += wots_size
        auth = [signature[offset+n*j:offset+n*(j+1)] for j in range(p["h_prime"])]
        offset += n*p["h_prime"]
        root = _path(p, seed, node, auth, leaf, 0, layer, tree, 2, 0, layer_scope)
        leaf, tree = tree & ((1 << p["h_prime"])-1), tree >> p["h_prime"]
    valid = root == expected_root
    _record(trace, "最终树根比对", "computed_root == PK.root", {
        "computed_root": root, "public_root": expected_root, "root_matches": valid,
        "consumed_signature_bytes": offset, "verified": valid}, "PQClean crypto_sign_verify")
    return valid


def verify(algorithm, message, public, signature, trace=None):
    try:
        return calculate(algorithm, message, public, signature, trace)
    except (ValueError, IndexError):
        return False
