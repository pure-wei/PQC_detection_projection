# 个人工作分析与合并记录

**页面入口与多协议扩展已接入：** 主界面首页、顶部菜单和「② 本地后量子实验站」均可进入展示页，支持 HTTPS / TLS / TCP / UDP、可选数字签名及启动、重测和停止；最新完整测试 351 项全部通过。操作、实测与截图见 [多协议验证记录](2026-10-07-pqc-multilayer-validation.md)。

**后续补测已完成：** 在 Conda `code` 中更新 OpenSSL 至 3.6.5 并补齐依赖后，完整测试 **257 项全部通过，0 跳过**，包含此前跳过的 11 项真实 PQC 实验测试。安装内容与证据见 [code 环境补测记录](2026-10-07-code-pqc-validation.md)。下文保留首次合并时的分析及 `base` 环境验证结果。

2026-10-07 已在主项目完成合并。采用主项目现有实现为基准，接入贡献中的后量子验证改进、IPsec 解析和独立 PQC 实验站。现有原文件没有缺失，修改了 8 个原文件，其余原文件保持相同 SHA-256；具体列表见 [合并审计](merge-audit-2026-10-07.json)。

## 输入、备份与分析结论

用户给出的导入目录包含另一层同名目录，合并时实际源码位于 `crypto-analysis-tool-main/crypto-analysis-tool-main`，目标目录为其外侧的主项目。合并及多协议扩展完成后，2026-10-07 按用户要求删除约 20 MB 的原始导入副本及其关联的原作者旧实测说明，并清理相关链接；主程序、启动脚本和测试均不依赖该副本。合并审计及首次验证输出中的来源路径仅记录当时的输入位置。

清理后完整回归 **351 passed、0 failed、0 skipped，72.84 秒**；更新后的说明链接及已合并模块文件检查通过。[清理后回归输出](import-cleanup-pytest-2026-10-07.txt)

合并前的 48 个项目文件备份位于 `/home/wei/code/password/crypto-analysis-tool-merge-backup-20261007-180838`，备份内容已按 [原始文件清单](../../crypto-analysis-tool-merge-backup-20261007-180838/original-manifest.json) 逐一核对。合并时两个目录均没有 Git 仓库，本次直接修改目标项目，未创建提交。

贡献内容有可用增量，但不是可以整体替换主项目的版本。导入的界面、TLS 解析、后量子演示和同名演示测试缺少主项目已有的实时抓包、取消流程、被动证据关联、混合签名和计算详情。因此保留主项目这些实现，仅修改必要的接入位置。合并时对照了导入源码与原始文件；当前保留的依据见 [原始文件清单](../../crypto-analysis-tool-merge-backup-20261007-180838/original-manifest.json)、[合并审计](merge-audit-2026-10-07.json) 和 [当前界面源码](../main.py)。

合并前主项目测试为 **180 passed**；导入版本为 **57 passed、3 failed、1 skipped、9 errors**。导入版本的问题包括未知签名方案状态错误、缺失的功能接口和未处理可选 OpenSSL 依赖。最终验证结果与命令见 [验证记录](merge-validation-2026-10-07.txt)。

## 采纳范围

| 内容 | 合并方式与结果 | 实现依据 |
| --- | --- | --- |
| 后量子主动检测 | 合并 Certificate 列表边界检查、ML-DSA 验签、同次握手证书来源、算法长度检查和服务器提供链的算法判定；保留取消参数与现有接口 | [检测器](../modules/pqc_detect.py)、[真实性测试](../tests/test_pqc_authenticity.py) |
| IPsec | 新增 IKEv1/v2、ESP、AH、NAT-T 解析，接入协议表格、过滤、字段树和 IKE 协商时序图 | [解析器](../modules/ipsec_parser.py)、[抓包分析](../modules/pcap_analysis.py)、[数据流解析](../modules/packet_parser.py)、[时序视图](../modules/handshake_view.py) |
| 本地 PQC 实验站 | 加入实验脚本、TLS 前端、静态网页和 Windows 辅助脚本；运行时生成本机身份及证据 | [搭建说明](../pqc_lab/README.md)、[实验脚本](../pqc_lab/lab.py) |
| 新增测试与演示抓包 | 导入可用测试，按实际页签类查找界面，增加离线模式和回归用例；用修正后的合成报文生成 IPsec 示例 | [界面冒烟测试](../tests/test_all_features.py)、[边界冒烟测试](../tests/test_edge_cases.py)、[示例抓包](../samples/ipsec_demo.pcap) |
| 测试配置与文档 | 默认 pytest 只收集主项目 tests；更新主说明、本机实测及来源记录 | [pytest 配置](../pytest.ini)、[主说明](../README.md)、[项目说明](../项目说明文档.md)、[本机多协议实测](2026-10-07-pqc-multilayer-validation.md) |

以下内容有明确的保留或排除决定：

- 主项目的 TLS 解析器、后量子演示、算法计算模块、原测试与测试向量、依赖文件和启动入口保留原字节内容，见 [合并审计](merge-audit-2026-10-07.json)。
- 导入的 `test_sm2_pubkey.py`、`test_sym_padding.py` 依赖 `validate_pubkey`、`padding_mode` 和相关 GUI 控件；两个版本都没有这些实现，因此没有把对应测试和冒烟条目合入。这些未采纳文件已随导入副本删除，主项目 [SM2 模块](../modules/sm2_sm3.py) 和 [对称算法模块](../modules/sym_crypto.py) 保留。
- 缓存、日志、实验私钥、旧证书、旧 evidence.json 和原作者生成的验证输出没有迁入新实验站。首次合并时目标 `pqc_lab/public` 仅含网页模板，未创建 `.runtime` 身份目录；原始资料已随导入副本删除，后续生成的本机实测保留在 [多协议验证记录](2026-10-07-pqc-multilayer-validation.md)。

## 合并中修复的问题

### 后量子证据与验证

检测结果区分算法证据和已经验证的服务器握手；验签或 Finished 验证失败会阻止成功判定，未知签名方案返回不支持。深度验证优先分析该次握手解密得到的证书；另一次连接取得的证书会明确标出来源。原有 `detect(..., cancel_event=None)` 和 `probe_group_matrix(..., cancel_event=None)` 保留。[检测器](../modules/pqc_detect.py)、[真实性测试](../tests/test_pqc_authenticity.py)、[原检测测试](../tests/test_pqc_detect.py)

“所提供链均为抗量子算法”只描述服务器发送的证书及参数，并不验证证书链签名、CA 信任路径或公共受信身份；这些限制写入界面及 JSON。单独导入证书文件只给算法证据，不能产生已验证服务器握手的结论。[检测器报告字段](../modules/pqc_detect.py)、[证书模式与端口测试](../tests/test_pqc_input.py)

非法端口在启动线程前拦截，修复导入界面边界测试触发后台线程异常的问题。抓包后的主动复测文本明确区分原抓包连接、同次主动握手证书和额外证书连接。[主界面](../main.py)、[输入测试](../tests/test_pqc_input.py)、[抓包与主动复测测试](../tests/test_pcap_pqc_ui.py)

### IPsec 报文格式与主界面接入

- 校正 UDP 4500 的 IKE / ESP 判别：四字节零 Non-ESP Marker 承载 IKE，非零 SPI 承载 ESP；短包及 NAT keepalive 不作为 IKE 协商处理。协议依据：[RFC 3948 (2005/01), §2](https://www.rfc-editor.org/rfc/rfc3948.html#section-2)。
- 校正 IKEv2 提议和变换的末项标记、TV/TLV 属性及密钥长度，并按注册表修正加密、完整性、载荷、身份和认证算法编号。协议依据：[RFC 7296 (2014/10), §3.3](https://www.rfc-editor.org/rfc/rfc7296.html#section-3.3)、[IANA IKEv2 参数表 (2026/10 查阅), Transform IDs](https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml)。
- IKEv1 按 ISAKMP 属性解析变换、按独立 DOI 前缀和通知编号解析 Notify；不将密文继续解析为明文载荷。协议依据：[RFC 2408 (1998/11), §3.14](https://www.rfc-editor.org/rfc/rfc2408.html#section-3.14)、[RFC 2409 (1998/11), 附录 A](https://www.rfc-editor.org/rfc/rfc2409.html#appendix-A)。
- 以 IKE 声明长度限制载荷解析，报告无效长度和截断；停止解析 SK/SKF 的内部密文；将二进制 IPv4/IPv6 身份显示为地址。实现及回归依据：[IPsec 解析器](../modules/ipsec_parser.py)、[集成测试](../tests/test_ipsec_integration.py)。
- IKE 流采用独立 UDP 键和发起者方向，避免与相同端点的 TCP 流冲突；混合抓包中保留完整及不完整 TLS 的展示。实现及回归依据：[数据流解析](../modules/packet_parser.py)、[时序视图](../modules/handshake_view.py)、[集成测试](../tests/test_ipsec_integration.py)。

IPsec 视图只展示可见报文与协商字段；没有添加 ESP 解密或 IKE 身份认证验证。[IPsec 解析器](../modules/ipsec_parser.py)、[时序视图](../modules/handshake_view.py)

### 实验站与可重复验证

实验测试在缺少支持 `X25519MLKEM768` 和 `mldsa65` 的 OpenSSL 时，明确跳过可选真实集成测试；不影响其他测试收集。实验身份不完整的检查仍可独立执行。[依赖夹具](../tests/conftest.py)、[真实实验测试](../tests/test_pqc_lab.py)、[并发测试](../tests/test_pqc_lab_concurrency.py)

网页根据报告中有效的回环端口更新目标、HTTPS 地址和验证命令，支持 `--port 9443` 等自定义端口；Windows 验证脚本转发参数。页面回归使用合成报告执行真实 JavaScript，只验证报告显示逻辑，不作为真实握手成功的证据。[实验网页](../pqc_lab/public/index.html)、[页面测试](../tests/test_pqc_lab_page.py)、[验证脚本](../pqc_lab/verify.bat)

## 首次合并的验证与限制（base 环境）

| 检查 | 结果 |
| --- | --- |
| 主项目完整 pytest | **246 passed、11 skipped**；没有失败或错误 |
| 全功能界面离线冒烟 | **17 通过、0 失败、5 跳过** |
| 边界界面离线冒烟 | **11 通过、0 失败、1 跳过** |
| Python 编译检查、实验 CLI 帮助及状态命令 | 通过；没有记录中的实验服务 |
| 备份与保留文件核对 | 48 个备份文件完整，原文件无缺失，仅 8 个原文件发生预期修改 |
| 独立只读复核 | 原审查发现均已修复；复核相关测试 45 项通过，无剩余阻断问题 |

验证命令和运行记录见 [验证记录](merge-validation-2026-10-07.txt)；文件核对结果见 [合并审计](merge-audit-2026-10-07.json)。

首次合并验证使用 Linux / Python 3.10.19 / `base` 环境 OpenSSL 3.0.18，当时测试选择的 OpenSSL 不支持上述 PQC 实验算法，因此 **11 项真实实验测试未执行**；这些项目现已在 `code` 环境全部补测通过。离线冒烟另跳过外网检测及尚未生成的 ML-DSA 证书场景。首次合并未生成实验 CA；后续真实测试在临时目录生成身份，未导入系统信任根，也未验证 Windows 信任管理或真实浏览器兼容性。[首次验证记录](merge-validation-2026-10-07.txt)、[code 环境补测记录](2026-10-07-code-pqc-validation.md)

原作者的 Windows 实测说明已在清理导入副本时删除。本机真实实验结果见 [多协议验证记录](2026-10-07-pqc-multilayer-validation.md)；复测时使用满足能力检查的 OpenSSL，按 [搭建说明](../pqc_lab/README.md) 启动并运行验证。[OpenSSL 能力检查](../pqc_lab/lab.py)

## 协议资料

[RFC 3948, 2005/01] Huttunen et al. “UDP Encapsulation of IPsec ESP Packets.” IETF. https://www.rfc-editor.org/rfc/rfc3948.html

[RFC 7296, 2014/10] Kaufman et al. “Internet Key Exchange Protocol Version 2 (IKEv2).” IETF. https://www.rfc-editor.org/rfc/rfc7296.html

[RFC 2408, 1998/11] Maughan et al. “Internet Security Association and Key Management Protocol (ISAKMP).” IETF. https://www.rfc-editor.org/rfc/rfc2408.html

[RFC 2409, 1998/11] Harkins and Carrel. “The Internet Key Exchange (IKE).” IETF. https://www.rfc-editor.org/rfc/rfc2409.html

[IANA IKEv2 参数表, 2026/10 查阅] IANA. “Internet Key Exchange Version 2 (IKEv2) Parameters.” https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml
