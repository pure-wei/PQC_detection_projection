# 实时抓包与后量子检测联动实施计划

**Goal:** 让第二页既能现场抓包，也能把 TLS 会话观察结果与主动复测并列展示。

**Architecture:** `live_capture.py` 控制 scapy 抓包并保存；`pqc_passive.py` 从已解析的 TLS 流产生保守证据；`PcapTab` 负责选择会话、后台任务及展示。主动复测复用 `pqc_detect.detect`。

**Tech Stack:** Python、PySide6、scapy、pytest。

**Spec:** `docs/superpowers/specs/2026-09-28-live-capture-pqc-link-design.md`

## Task 1: 被动证据

- [x] 写失败测试：ServerHello 后量子组、经典组、缺失或长度错误、TLS 1.3 证书不可见。
- [x] 运行测试确认失败。
- [x] 实现 ServerHello 组解析及 `assess_tls_flow`。
- [x] 运行测试确认通过。

## Task 2: 实时抓包

- [x] 写失败测试：正常停止、达到时间或包数停止、空结果与错误处理。
- [x] 运行测试确认失败。
- [x] 实现 `live_capture.py` 及后台 Qt 工作线程、抓包控件。
- [x] 运行测试确认通过。

## Task 3: 会话联动与页签

- [x] 写失败测试：第 ② 页为协议分析；选择 TLS 会话展示被动证据；主动复测结果独立显示。
- [x] 运行测试确认失败。
- [x] 实现 PcapTab 联动及主页面排序、文档更新。
- [x] 运行测试确认通过，运行全套测试和离屏界面检查。
