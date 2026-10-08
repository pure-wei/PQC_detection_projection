# 后量子与混合签名计算详情

用户要求现有后量子签名与混合签名页面增加参数和计算过程。覆盖全部现有 17 个 PQ 参数集与 5 个传统参数集，复用 ML-KEM 步骤树，保留执行摘要和公开 Base64 数据。

详情由本次原生库产生的密钥、消息和签名构建。ML-DSA 展示密钥解码、矩阵、NTT、公开密钥关系、从本次 z/c/s1 还原的被接受掩码 y、承诺、挑战、提示与完整验签计算。SLH 页面展示实际 SPHINCS+ simple 后端的随机化值 R、消息摘要、FORS 路径、WOTS+ 链和各层树根；明确该后端的消息编码与 FIPS 205 外部接口不同。Falcon 展示实际 nonce、解码的 h/s2、哈希到点、环乘积、恢复 s1 与范数检查。

混合签名展示版本、两个算法名、两个公钥、消息的完整长度前缀编码，两个组件签名及 AND 验签和独立篡改结果。传统部分显示 Ed25519 的实际 seed/展开/确定性 nonce/挑战/标量关系；ECDSA 显示实际 d/r/s、摘要、由签名反推的等价 nonce 与验签点；RSA-PSS 显示模数/指数、实际盐、MGF1、EM 与摘要比对。

原生库没有返回的随机输入和未通过签名的重试不伪造；界面区分实际签名解码、确定性重算和数学反推。教学临时秘密只留在 demo 详情，不自动保存。公开接口 `sign_hybrid_message` 继续只返回公开签名数据；`run_hybrid_signature_demo` 可返回教学 trace。不增加依赖，不改 TLS 检测，不更换签名生成后端。

每种算法的计算重放必须与原生验签一致；异常报告运行失败。测试独立环卷积、RFC Ed25519 样本、实际 native 签名、篡改、参数与输出一致性、全部 UI 入口及旧详情清理。完成前运行全量测试、界面预览和一次独立审查。

参考：[NIST FIPS 204](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)、[NIST FIPS 205](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf)、[PQClean 源码](https://github.com/PQClean/PQClean/tree/master/crypto_sign)、[Falcon 实现](https://falcon-sign.info/impl/)、[RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html)、[RFC 8017](https://www.rfc-editor.org/rfc/rfc8017.html)。
