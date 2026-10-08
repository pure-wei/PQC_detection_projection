# 多协议后量子实验站实施计划

> For agentic workers: Use superpowers:executing-plans to implement task by task; preserve the execution ledger below.

**Goal:** 在第二个页签提供 HTTPS、TLS、TCP 与 UDP 的真实实验及可选数字签名。

**Architecture:** 配置集中在 profiles.py；现有 TLS 后端参数化；新增固定公钥的签名消息后端。统一进程生命周期和实测报告，桌面与网页根据实际协议解释证据。

**Tech Stack:** Python、PySide6、OpenSSL 3.6.5、pqcrypto、cryptography、socketserver。

**Spec:** ../specs/2026-10-07-multilayer-pqc-lab-design.md

## Global Constraints

- 用户选择 TLS/HTTPS＋TCP/UDP 应用消息实验；主入口保持第二个位置。
- 只监听 127.0.0.1；私钥不写到公开证据目录。
- TCP/UDP 签名消息为明文，混合签名要求两份验签都通过。
- 4096 UTF-8 字节消息上限；UDP 分片每片最多 1200 字节，总响应上限 128 KiB。
- 保留已有 ML-DSA-65 身份及默认 CLI/API；报告不能跨模式沿用成功。

## Review Focus

- 最大 SLH-DSA 签名超过一个 UDP 数据报，必须完整重组或失败。
- 已存在的默认身份不得因切换算法被覆盖。
- 服务由外部入口启动时，GUI 必须使用实际运行配置并保留关闭所有权。
- 失败或配置不一致的报告不能显示成功。
- 签名、挑战或混合签名任一组成部分遭篡改时必须拒绝。

## Task 1: 配置与真实后端

**Files:** 新建 pqc_lab/profiles.py、pqc_lab/signed_messages.py、tests/test_pqc_lab_multilayer.py；修改 pqc_lab/lab.py、modules/pqc_detect.py。

**Interfaces:** LabProfile(protocol, group, signature, classical_signature)；SignedMessageServer(base, address, profile).start/close；verify_lab(base, openssl, port, profile, message)。

- [x] 先写真实组合与负向对照测试，运行并确认因缺失能力失败。
- [x] 统一配置验证与 TLS 身份路径；增加明确指定检测组的可选参数。
- [x] 实现受固定公钥约束的 TCP/UDP 签名消息、长度限制和应用分片。
- [x] 接入服务启动、报告、重测与停止，保持旧入口兼容。
- [x] 跑通 9 种 TLS 组合、34 种网络签名组合及混合签名与边界测试。

## Task 2: 页面与操作

**Files:** 修改 modules/pqc_lab_ui.py、pqc_lab/public/index.html、tests/test_pqc_lab_ui.py、tests/test_pqc_lab_page.py。

**Interfaces:** 同一 profile 字典用于 CLI、运行记录、实测报告及页面；默认 https。

- [x] 写真实 GUI 新模式生命周期与报告真实性测试，确认失败。
- [x] 加入协议、交换组、签名、混合签名与消息输入，运行中锁定配置。
- [x] 根据实际报告显示地址、签名结果、TLS/HTTPS 状态与信任范围。
- [x] 执行浏览器 JavaScript 渲染并检查 TLS 与消息模式，拒绝矛盾成功报告。

## Task 3: 说明、验收与复核

**Files:** 更新 README.md、pqc_lab/README.md、docs/2026-10-07-pqc-lab-ui.md；新增验证记录。

- [x] 完整回归、真实默认端口展示并保存截图与证据。
- [x] 对完整变更执行一次独立只读复核，修复有实证的问题。
- [x] 更新配置、协议边界、操作方法、实测结果与执行账本。

## Execution Ledger

- Pre-flight: Task 1 的 profile/summary 字段由 Task 2 读取；两处必须使用相同注册表与验证规则。
- Ruling: 目录没有 Git 仓库，直接在用户指定项目中实施并备份将修改的文件，不创建提交。
- Ruling: 用户已指定协议范围；依其授权连续实现，不为常规设计选择重复请求许可。
- Task 1: 真实后端测试先失败后通过；9 种 TLS 组合、34 种网络签名组合、5 种经典混合签名全部跑通。默认 ML-DSA-65 身份保持；消息私钥不发布。
- Task 2: 协议、交换组、签名、混合签名和消息输入接入第二个页签；真实 GUI 生命周期与 Node 网页渲染通过，配置变化清除旧成功报告。
- Review: 独立只读复核发现请求转义上限、外部 OpenSSL 选择、UDP 重复分片期限三项问题。六个复现用例先失败，再修复并全部通过。
- Additional verification: 补齐保存模式恢复和 CLI 前置失败刷新报告，两项先失败后通过；复核相关专项共 98 项通过。
- Display: 默认 8443/8080 上顺序启动、验证和停止 TLS、TCP、UDP、HTTPS；四种报告及五张截图保存在 docs/evidence 和 docs/screenshots。
- Display finding: 立即重启原 TLS 端口受 TIME_WAIT 影响，两项真实回归先失败；POSIX 加 SO_REUSEADDR 后通过，活动端口依然拒绝重复绑定。独立收尾复核两项通过。
- Final verification: code 环境完整回归 351 passed / 0 failed / 0 skipped，69.14 秒；Python 编译通过，实验结束后默认端口无遗留监听。原始输出 docs/pqc-multilayer-pytest-2026-10-07.txt。
- Delivery: docs/2026-10-07-pqc-multilayer-validation.md 记录实现、协议边界、操作方法与不可变实测快照；源码修改前备份位于 /tmp/crypto-lab-multilayer-20261007。
