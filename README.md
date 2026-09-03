# PQC_detection_projection

后量子密码（PQC）检测与投影工具 —— 抓取网站 TLS 数据，识别加密算法，判断其是否具备抗量子（PQC）能力。

## 四个核心命令

| 命令 | 功能 | 分析层面 |
|------|------|----------|
| `scan` | 统一安全扫描 — 一次完成抓包/算法解析/抗量子判定 | 综合（三层合一） |
| `pcap` | 深度抓包 — 抓取 TLS 握手全部 hex 原始数据 | 原始包层 |
| `detect` | PQC 握手检测 — 判断网站 TLS 是否支持抗量子密钥交换 | 传输层 |
| `cert` | 证书深度分析 — 识别签名算法、公钥类型、是否抗量子 | 证书层 |

`scan` 是 `pcap` + `detect` + `cert` 的一体化封装，一次调用即可得到分层报告与综合抗量子结论。

## 安装

```bash
pip install -r requirements.txt
```

## 使用

```bash
python -m src.cli.main scan   cloudflare.com
python -m src.cli.main pcap   cloudflare.com
python -m src.cli.main detect cloudflare.com
python -m src.cli.main cert   cloudflare.com
```

## 项目结构

```
├── docs/                           # 项目文档
│   └── PQC-HTTPS项目说明.md         # 详细说明：命令原理、检测流程、数据校验
├── tools/                          # 辅助脚本
│   └── gen_report.py               # 汇报稿 Word 生成（可选）
├── output/                         # 检测结果输出（JSON + PDF，不入库）
├── src/                            # 核心代码
│   ├── cli/                        # 命令行入口（4 个命令）
│   ├── tls_analysis/               # TLS 分析核心：抓包/算法解析/抗量子判定
│   ├── utils/                      # 日志 / 配置 / 翻译 / PDF 报告
│   └── web/                        # Flask Web 界面
├── pyproject.toml
└── requirements.txt
```

## 文档

- [docs/PQC-HTTPS项目说明.md](docs/PQC-HTTPS项目说明.md) — 项目详细说明
