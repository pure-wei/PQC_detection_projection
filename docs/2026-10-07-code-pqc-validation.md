# code 环境安装与真实 PQC 补测

2026-10-07 在 Conda `code` 环境完成 OpenSSL 更新和测试依赖安装，主项目完整测试结果为 **257 passed，0 failed，0 skipped，耗时 25.23 秒**。此前跳过的 11 项真实 PQC 实验测试已实际运行通过。原始输出见 [pytest 日志](pqc-code-pytest-2026-10-07.txt)，环境及能力信息见 [环境记录](pqc-code-environment-2026-10-07.json)。

## 本次新增工作说明

前一次合并的新增功能与修复主要分为四类，详细文件范围见 [合并分析报告](2026-10-07-contribution-merge.md)：

| 类别 | 实际新增内容 | 依据 |
| --- | --- | --- |
| IPsec 抓包分析 | 解析 IKEv1/v2、ESP、AH、NAT-T，接入表格、过滤、字段树和协商图，修正报文边界、标准编号及混合流展示 | [解析器](../modules/ipsec_parser.py)、[集成测试](../tests/test_ipsec_integration.py) |
| 后量子验证 | 校验 ML-DSA CertificateVerify 和 Finished，检查算法参数与长度，使用同一次主动握手的证书，明确区分算法证据、服务器握手验证和 CA 信任 | [检测器](../modules/pqc_detect.py)、[真实性测试](../tests/test_pqc_authenticity.py) |
| 可复现实验站 | 使用真实 OpenSSL 提供 X25519MLKEM768 + ML-DSA-65 的本地 TLS 服务，生成临时实验身份，验证证书链和完整 HTTPS 请求，支持并发入口和报告页面 | [实验管理](../pqc_lab/lab.py)、[并发入口](../pqc_lab/tls_frontend.py)、[搭建说明](../pqc_lab/README.md) |
| 集成和回归修复 | 保留较新的原功能，补充 IPsec 示例抓包、非法端口拦截、证书文件证据范围、自定义 TLS 端口和测试收集配置 | [主界面](../main.py)、[输入测试](../tests/test_pqc_input.py)、[页面测试](../tests/test_pqc_lab_page.py)、[pytest 配置](../pytest.ini) |

本次补测没有修改业务代码；新增了环境安装记录和真实测试结果。[安装前记录](pqc-code-environment-before-2026-10-07.json)、[安装后记录](pqc-code-environment-2026-10-07.json)

## 环境差异与安装内容

首次合并测试使用的是 Conda `base` 的 Python 及 OpenSSL 3.0.18。此次检查发现另一个 Conda 环境 `code` 已安装 OpenSSL 3.6.4，并支持所需混合组和签名方案；原跳过原因是测试未使用该环境。[首次测试记录](merge-validation-2026-10-07.txt)、[安装前记录](pqc-code-environment-before-2026-10-07.json)

将 `code` 中 OpenSSL 从 3.6.4 更新到 3.6.5；Conda 安装计划仅更新这一个包。3.6.5 是 OpenSSL 官方下载页列出的 3.6 分支补丁版本。[安装后记录](pqc-code-environment-2026-10-07.json)、[OpenSSL Downloads (2026/10 查阅), 3.6](https://www.openssl-library.org/source/)

该环境此前缺少 PySide6、Scapy 和 pytest，已按主项目 `requirements.txt` 补齐。`pqcrypto` 从原环境的 0.4.0 调整为项目明确固定的 **0.3.0**；其他已有依赖版本保持。[项目依赖](../requirements.txt)、[安装前记录](pqc-code-environment-before-2026-10-07.json)、[安装后记录](pqc-code-environment-2026-10-07.json)

| 项目 | 最终配置 |
| --- | --- |
| Conda 环境 | `code` |
| Python | `/home/wei/miniconda3/envs/code/bin/python`，3.10.19 |
| OpenSSL | `/home/wei/miniconda3/envs/code/bin/openssl`，3.6.5 |
| Python ssl 链接版本 | OpenSSL 3.6.5 |
| PySide6 / Scapy | 6.11.2 / 2.8.0 |
| cryptography / pqcrypto | 48.0.0 / 0.3.0 |
| pytest | 9.1.1 |

配置依据：[安装后环境记录](pqc-code-environment-2026-10-07.json)。

实际执行的安装命令：

```bash
conda install -n code -y --freeze-installed 'openssl>=3.6.5,<3.7'
/home/wei/miniconda3/envs/code/bin/python -m pip install -r requirements.txt pytest
```

## 真实补测覆盖

此次完整 pytest 没有跳过任何用例。[pytest 原始输出](pqc-code-pytest-2026-10-07.txt)

- 真实混合密钥交换、ML-DSA-65 CertificateVerify 验签和服务器 Finished 校验。
- 实验 CA、叶子证书、有效期、主机名、根自签名和完整证书链验证。
- 完成真实 HTTPS GET，比较服务端返回的 HTML 字节及证书指纹。
- 负向对照：拒绝仅经典密钥交换、错误主机名和被篡改的证书签名；服务关闭后不保留成功判定。
- 服务启动、停止、私钥不经 HTTP 发布，以及重复管理进程的拦截。
- 空闲 TCP 和已完成 TLS 但未发送 HTTP 的连接不会阻塞其他连接；验证并发连接、连接上限恢复、超时和子进程清理。

上述检查及断言见 [真实实验测试](../tests/test_pqc_lab.py) 和 [并发真实连接测试](../tests/test_pqc_lab_concurrency.py)，执行结果见 [pytest 日志](pqc-code-pytest-2026-10-07.txt)。运行结束后没有遗留测试服务或 OpenSSL 客户端进程。

测试在 pytest 临时目录生成实验 CA 和私钥，显式指定 CA 文件完成信任验证，未导入系统信任库；没有验证 Windows 信任管理或真实浏览器兼容性。[实验实现](../pqc_lab/lab.py)、[测试实现](../tests/test_pqc_lab.py)

## 重现命令

在主项目目录执行：

```bash
conda activate code
QT_QPA_PLATFORM=offscreen python -m pytest -q -rs
```

本次记录使用显式 OpenSSL 路径，确保与环境记录一致：

```bash
QT_QPA_PLATFORM=offscreen \
PQC_OPENSSL=/home/wei/miniconda3/envs/code/bin/openssl \
conda run -n code --no-capture-output python -m pytest -q -rs
```

真实实验测试单独运行可使用：

```bash
QT_QPA_PLATFORM=offscreen conda run -n code --no-capture-output \
python -m pytest tests/test_pqc_lab.py tests/test_pqc_lab_concurrency.py -q
```

## 外部资料

[OpenSSL Downloads, 2026/10 查阅] OpenSSL Project. “Downloads.” OpenSSL Library. https://www.openssl-library.org/source/
