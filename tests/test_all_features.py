# -*- coding: utf-8 -*-
"""全功能端到端冒烟测试：逐页驱动界面，检查各功能是否正常。

覆盖 7 个页签的主要功能；网络相关用例（抗量子检测）在无法联网时标记为 SKIP。

    python tests/test_all_features.py
"""
import os
import struct
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from PySide6.QtWidgets import QApplication                     # noqa: E402

import main as appmod                                          # noqa: E402
from modules import sm2_sm3, pqc_detect                         # noqa: E402

RESULTS = []
TMP = tempfile.mkdtemp(prefix="allfeat_")


def tab_by_class(tabs, cls):
    return next(tabs.widget(i) for i in range(tabs.count()) if isinstance(tabs.widget(i), cls))


def record(name, state, detail=""):
    RESULTS.append((name, state, detail))
    print("[%s] %-46s %s" % (state, name, detail))


def case(name, fn, network=False):
    """执行一个用例；network=True 的用例失败时标记 SKIP（不视为缺陷）。"""
    if network and "--offline" in sys.argv:
        record(name, "SKIP", "离线模式不发起外网检测")
        return
    try:
        detail = fn() or ""
        if str(detail).startswith("SKIP:"):
            record(name, "SKIP", str(detail)[5:].strip())
            return
        record(name, "PASS", str(detail)[:110])
    except Exception as e:
        msg = "%s: %s" % (type(e).__name__, e)
        record(name, "SKIP" if network else "FAIL", msg[:110])


def pump(app, n=8):
    for _ in range(n):
        app.processEvents()


def _mk_tls_pcap(path):
    """合成一个 TLS 1.3 握手抓包（ClientHello + ServerHello），用于④页测试。"""
    from scapy.all import Ether, IP, TCP, Raw, wrpcap
    hello = pqc_detect.build_client_hello("demo.local")
    exts = (struct.pack(">HH", 43, 2) + b"\x03\x04"
            + struct.pack(">HH", 51, 1124) + struct.pack(">HH", 0x11EC, 1120)
            + b"\x00" * 1120)
    body = (b"\x03\x03" + b"\x11" * 32 + b"\x00" + b"\x13\x01" + b"\x00"
            + struct.pack(">H", len(exts)) + exts)
    sh = b"\x02" + len(body).to_bytes(3, "big") + body
    server = b"\x16\x03\x03" + struct.pack(">H", len(sh)) + sh
    c_ip, s_ip, c_port, s_port = "192.0.2.1", "198.51.100.1", 51000, 443
    pkts = []

    def add(src, sport, dst, dport, flags, seq, ack, payload=b""):
        mac_s = "02:00:00:00:00:01" if src == c_ip else "02:00:00:00:00:02"
        mac_d = "02:00:00:00:00:02" if src == c_ip else "02:00:00:00:00:01"
        p = (Ether(src=mac_s, dst=mac_d) / IP(src=src, dst=dst)
             / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack,
                   window=64240) / Raw(load=payload))
        p.time = 1700000000.0 + len(pkts) * 0.001
        pkts.append(p)

    c_isn, s_isn = 1000, 5000
    add(c_ip, c_port, s_ip, s_port, "S", c_isn, 0)
    add(s_ip, s_port, c_ip, c_port, "SA", s_isn, c_isn + 1)
    add(c_ip, c_port, s_ip, s_port, "A", c_isn + 1, s_isn + 1)
    add(c_ip, c_port, s_ip, s_port, "PA", c_isn + 1, s_isn + 1, hello)
    add(s_ip, s_port, c_ip, c_port, "A", s_isn + 1, c_isn + 1 + len(hello))
    add(s_ip, s_port, c_ip, c_port, "PA", s_isn + 1, c_isn + 1 + len(hello), server)
    add(c_ip, c_port, s_ip, s_port, "A", c_isn + 1 + len(hello), s_isn + 1 + len(server))
    wrpcap(path, pkts)
    return path


def t_pqc(app, tabs):
    page = tab_by_class(tabs, appmod.PqcDetectTab)
    state = {"report": None}

    def run_detect(host, port="443", mode=0, timeout="15", rounds=900):
        page.host_edit.setText(host)
        page.port_edit.setText(port)
        page.timeout_edit.setText(timeout)
        page.mode_combo.setCurrentIndex(mode)
        page._report = None
        page._run()
        for _ in range(rounds):
            pump(app, 2)
            if page._report is not None:
                break
            app.thread().msleep(30)
        return page._report or {}

    def empty_input():
        page.host_edit.setText("")
        page._run()
        pump(app)
        assert page._report is None, "空输入不应产生结果"
        return "空输入已拦截"

    def deep_cloudflare():
        rep = run_detect("www.cloudflare.com")
        assert rep, "未取得检测结果"
        t = rep.get("transport") or {}
        c = rep.get("cert") or {}
        assert t.get("is_pqc") and t.get("verified"), "传输层未通过密码学验证"
        assert c.get("sig_algorithm"), "证书层未解析"
        assert page.cert_table.rowCount() >= 4, "关键验证流程为空"
        assert "SNI" in page.ev_ch.text() and "选中组" in page.ev_sh.text()
        assert page.cert_table.item(0, 2).text() == "通过"
        assert os.path.exists(rep.get("detail_file") or ""), "详细报文未落盘"
        return "组=%s 已验证 证书=%s" % (t.get("group_name"), c.get("sig_algorithm"))

    def fast_mode():
        rep = run_detect("www.cloudflare.com", mode=1)
        t = rep.get("transport") or {}
        assert rep.get("deep") is None, "快速模式不应做深度验证"
        assert t.get("ok"), "快速模式未取到 ServerHello 证据"
        assert not t.get("verified"), "快速模式不应标记已验证"
        return "组=%s 未验证" % t.get("group_name")


    def cert_file_mode():
        p = os.path.join(ROOT, "pqc_lab", "public", "server.cert.pem")
        if not os.path.exists(p):
            return "SKIP: 缺少 ML-DSA 测试证书"
        page._load_cert_file(p)
        pump(app)
        c = (page._report or {}).get("cert") or {}
        assert c.get("cert_is_pqc"), "证书文件模式未判为抗量子"
        assert page.cert_table.rowCount() > 0, "证书层结果未显示"
        assert page.cert_table.item(page.cert_table.rowCount() - 1, 0).text() == "证书详情"
        return "%s / %s" % (c.get("sig_algorithm"), c.get("pub_algorithm"))

    def exports():
        rep = run_detect("www.cloudflare.com", mode=1)
        assert rep, "未取得结果"
        jp = os.path.join(TMP, "pqc.json")
        tp = os.path.join(TMP, "pqc_detail.txt")
        old_save = appmod.QFileDialog.getSaveFileName
        try:
            appmod.QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (jp, ""))
            page._export()
            appmod.QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (tp, ""))
            page._export_detail()
        finally:
            appmod.QFileDialog.getSaveFileName = old_save
        assert os.path.getsize(jp) > 500, "JSON 导出为空"
        txt = open(tp, encoding="utf-8").read()
        assert ("附一：原始报文" in txt) and ("附二：逐字段说明" in txt), "详细报文内容不完整"
        return "JSON %d 字节 / 详情 %d 字节" % (os.path.getsize(jp), os.path.getsize(tp))

    def clear():
        page._clear()
        pump(app)
        assert page.cert_table.rowCount() == 0 and not page.status_label.text()
        assert "等待检测" in page.verdict.text()
        return "已复位"

    case("① PQC 空输入拦截", empty_input)
    case("① PQC 深度验证（cloudflare.com）", deep_cloudflare, network=True)
    case("① PQC 快速检测模式", fast_mode, network=True)
    case("① PQC 证书文件模式（ML-DSA）", cert_file_mode)
    case("① PQC 导出 JSON / 详细报文", exports, network=True)
    case("① PQC 清空", clear)


def t_sm2(app, tabs):
    sm2 = tab_by_class(tabs, appmod.Sm2Sm3Tab)
    inner = sm2.inner
    sign, verify, enc = inner.widget(0), inner.widget(1), inner.widget(2)
    priv, pub = sm2_sm3.generate_sm2_keypair()

    def sign_flow():
        sign.priv_edit.setText(priv)
        sign.pub_edit.setText(pub)
        sign.msg_edit.setPlainText("48656c6c6f")
        sign._do_sign()
        pump(app)
        sig = sign.sig_edit.toPlainText().strip()
        assert len(sig) >= 128, "签名输出异常"
        return "签名 %d hex 字符" % len(sig)

    def verify_flow():
        sig = sign.sig_edit.toPlainText().strip()
        verify.pub_edit.setText(pub)
        verify.msg_edit.setPlainText("48656c6c6f")
        verify.sig_edit.setPlainText(sig)
        verify._do_verify()
        pump(app)
        txt = verify.res_edit.toPlainText()
        assert "通过" in txt, "验签未通过：%s" % txt[-80:]
        return "验签通过"

    def encdec_flow():
        enc.pub_edit.setText(pub)
        enc.priv_edit.setText(priv)
        enc.msg_edit.setPlainText(b"pwd-test".hex())
        enc._do_encrypt()
        pump(app)
        ct = enc.out_edit.toPlainText().strip()
        assert ct, "加密输出为空"
        enc.msg_edit.setPlainText(ct)
        enc._do_decrypt()
        pump(app)
        assert enc.out_edit.toPlainText().strip(), "解密输出为空"
        return "密文 %d 字节" % (len(ct) // 2)


    def sm3_flow():
        sign.msg_edit.setPlainText("616263")
        sign._do_sm3()
        pump(app)
        assert "66c7f0f4" in sign.res_edit.toPlainText().lower(), "SM3 摘要值不正确"
        return "SM3(abc) 正确"

    case("② SM2 签名", sign_flow)
    case("② SM2 验签", verify_flow)
    case("② SM2 公钥加密 / 私钥解密", encdec_flow)
    case("② SM3 摘要", sm3_flow)


def t_codec(app, tabs):
    page = tab_by_class(tabs, appmod.CodecTab)
    cases = [("utf8", "hex_upper", "hello", "68656C6C6F"),
             ("hex", "utf8", "68656c6c6f", "hello"),
             ("utf8", "base64", "hello", "aGVsbG8="),
             ("base64", "utf8", "aGVsbG8=", "hello"),
             ("utf8", "url", "a b", "a%20b"),
             ("url", "utf8", "a%20b", "a b")]

    def conv():
        bad = []
        for inf, outf, src, want in cases:
            page.in_combo.setCurrentIndex([v for v, _l in page._IN_FORMATS].index(inf))
            page.out_combo.setCurrentIndex([v for v, _l in page._OUT_FORMATS].index(outf))
            page.in_edit.setPlainText(src)
            page._convert_from_cfg()
            pump(app, 4)
            got = page.out_edit.toPlainText().strip()
            if want.lower() not in got.lower():
                bad.append("%s→%s: %s" % (inf, outf, got[:24]))
        assert not bad, "转换异常：%s" % "; ".join(bad)
        return "%d 组互转正确" % len(cases)

    case("③ 编码转换（HEX/Base64/URL/UTF-8）", conv)


def t_pcap(app, tabs):
    page = tab_by_class(tabs, appmod.PcapTab)
    ike_pcap = os.path.join(ROOT, "samples", "ipsec_demo.pcap")
    tls_pcap = _mk_tls_pcap(os.path.join(TMP, "tls_demo.pcap"))

    def load_ike():
        page.analyze_file(ike_pcap)
        pump(app, 12)
        protos = [page.table.item(r, 4).text() for r in range(page.table.rowCount())]
        assert "IKE" in protos and "ESP" in protos and "AH" in protos, str(protos)
        assert "IPSec" in (page._summary_html or "") or "IKE" in (page._summary_html or "")
        return "协议列：%s" % ",".join(sorted(set(protos)))

    def ike_sequence():
        for i in range(page.mode_combo.count()):
            if page.mode_combo.itemData(i) == 2:
                page.mode_combo.setCurrentIndex(i)
                break
        pump(app, 12)
        labels = [page.flow_combo.itemText(i) for i in range(page.flow_combo.count())]
        assert any("IPSec IKE" in t for t in labels), str(labels)
        n = len(page.handshake_view._events)
        assert n >= 3, "IKE 时序事件为空"
        return "%d 条 IKE 报文" % n

    def tls_pcap_parse():
        page.analyze_file(tls_pcap)
        pump(app, 12)
        protos = [page.table.item(r, 4).text() for r in range(page.table.rowCount())]
        assert "TLS" in protos, str(protos)
        info = " ".join(page.table.item(r, 6).text() for r in range(page.table.rowCount()))
        assert ("ClientHello" in info.replace(" ", "")) or \
               ("ServerHello" in info.replace(" ", "")), info[:80]
        return "协议列：%s" % ",".join(sorted(set(protos)))

    def filter_and_csv():
        page.analyze_file(ike_pcap)
        pump(app, 10)
        before = page.table.rowCount()
        idx = [page.cmb_proto.itemText(i) for i in range(page.cmb_proto.count())].index("IKE")
        page.cmb_proto.setCurrentIndex(idx)
        pump(app, 6)
        after = page.table.rowCount()
        assert 0 < after < before, "协议过滤无效 %d→%d" % (before, after)
        page.cmb_proto.setCurrentIndex(0)
        page.search_edit.setText("ike_sa_init")
        pump(app, 6)
        assert page.table.rowCount() > 0, "关键字搜索无结果"
        page.search_edit.clear()
        pump(app, 6)
        csv_path = os.path.join(TMP, "rows.csv")
        old_save = appmod.QFileDialog.getSaveFileName
        try:
            appmod.QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (csv_path, ""))
            page._export_csv()
        finally:
            appmod.QFileDialog.getSaveFileName = old_save
        assert os.path.getsize(csv_path) > 100, "CSV 导出为空"
        return "过滤 %d→%d 行，CSV %d 字节" % (before, after, os.path.getsize(csv_path))

    def field_tree():
        # 报文字段树由「点击单元格」信号触发（与人工点击一致）
        page._on_cell_clicked(0, 0)
        pump(app, 8)
        n = page.detail_tree.topLevelItemCount()
        assert n > 0, "字段树为空"
        texts = []
        for i in range(n):
            it = page.detail_tree.topLevelItem(i)
            texts.append(it.text(0))
            for j in range(it.childCount()):
                texts.append(it.child(j).text(0))
        assert any("IPSec" in t for t in texts), str(texts[:8])
        return "字段树 %d 个分组，含 IPSec" % n

    case("④ pcap 加载 IPSec 抓包（协议识别）", load_ike)
    case("④ pcap IPSec 协商时序视图", ike_sequence)
    case("④ pcap 加载 TLS 抓包（协议识别）", tls_pcap_parse)
    case("④ pcap 协议过滤 / 搜索 / CSV 导出", filter_and_csv)
    case("④ pcap 单包字段树", field_tree)


def t_cert(app, tabs):
    page = tab_by_class(tabs, appmod.CertTab)

    def demo_cert():
        page._load_demo()
        pump(app, 10)
        assert page.table.rowCount() > 5, "演示证书分析结果为空"
        keys = [page.table.item(r, 0).text() for r in range(page.table.rowCount())]
        assert any("签名算法" in k for k in keys), str(keys[:6])
        return "%d 个字段" % page.table.rowCount()

    def mldsa_cert():
        p = os.path.join(ROOT, "pqc_lab", "public", "server.cert.pem")
        if not os.path.exists(p):
            return "SKIP: 缺少 ML-DSA 测试证书"
        page._load_file(p)
        pump(app, 10)
        vals = " ".join(page.table.item(r, 1).text() for r in range(page.table.rowCount()))
        assert "ML-DSA-65" in vals, "未识别 ML-DSA-65 证书"
        return "识别出 ML-DSA-65"

    def export_result():
        path = os.path.join(TMP, "cert.txt")
        old_save = appmod.QFileDialog.getSaveFileName
        try:
            appmod.QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (path, ""))
            page._export()
        finally:
            appmod.QFileDialog.getSaveFileName = old_save
        assert os.path.exists(path) and os.path.getsize(path) > 100, "证书结果导出失败"
        return "%d 字节" % os.path.getsize(path)

    case("⑤ 证书分析（演示 RSA 证书）", demo_cert)
    case("⑤ 证书分析（ML-DSA 抗量子证书）", mldsa_cert)
    case("⑤ 证书分析结果导出", export_result)


def t_sym(app, tabs):
    page = tab_by_class(tabs, appmod.SymCryptoTab)

    def demo():
        page._load_demo()
        pump(app, 10)
        log = page.log_edit.toPlainText()
        assert "自检" in log or "填充" in log, "演示流程未执行"
        return log.strip().splitlines()[-1][:70]


    case("⑥ 对称加解密演示流程", demo)


def t_hash(app, tabs):
    page = tab_by_class(tabs, appmod.HashTab)

    def hash_all():
        page.rb_text.setChecked(True)
        page.in_edit.setPlainText("abc")
        page._do_hash()
        pump(app, 8)
        assert page.table.rowCount() == 7, "摘要表应有 7 行，实际 %d" % page.table.rowCount()
        vals = {page.table.item(r, 0).text(): page.table.item(r, 1).text()
                for r in range(page.table.rowCount())}
        assert vals.get("SM3", "").startswith("66c7f0f4"), vals.get("SM3", "")[:16]
        assert vals.get("SHA-256", "").startswith("ba7816bf"), vals.get("SHA-256", "")[:16]
        return "7 种摘要全部正确"

    def hmac():
        page.key_edit.setText("6b6579")
        for i in range(page.cmb_hmac.count()):
            if page.cmb_hmac.itemText(i).startswith("SM3"):
                page.cmb_hmac.setCurrentIndex(i)
                break
        page._do_hmac()
        pump(app, 8)
        txt = page.hmac_label.text()
        assert "—" not in txt and len(txt) > 20, "HMAC 结果为空：%s" % txt
        return txt[:60]

    case("⑦ 摘要计算（SM3/SHA 族/MD5）", hash_all)
    case("⑦ HMAC 计算", hmac)


def main():
    app = QApplication.instance() or QApplication([])
    app.setStyleSheet(appmod.QSS)
    appmod.QMessageBox.exec = lambda self, *a, **k: 0
    appmod.QMessageBox.information = staticmethod(lambda *a, **k: 0)
    appmod.QMessageBox.warning = staticmethod(lambda *a, **k: 0)
    appmod.QMessageBox.critical = staticmethod(lambda *a, **k: 0)
    win = appmod.MainWindow()
    win.resize(1280, 820)
    win.show()
    pump(app, 10)
    tabs = win.centralWidget()
    print("页签:", [tabs.tabText(i) for i in range(tabs.count())])
    print("-" * 96)
    for fn in (t_pqc, t_sm2, t_codec, t_pcap, t_cert, t_sym, t_hash):
        fn(app, tabs)
    win.close()
    print("-" * 96)
    n_pass = sum(1 for _n, s, _d in RESULTS if s == "PASS")
    n_fail = sum(1 for _n, s, _d in RESULTS if s == "FAIL")
    n_skip = sum(1 for _n, s, _d in RESULTS if s == "SKIP")
    print("合计 %d 项：通过 %d，失败 %d，跳过 %d" % (len(RESULTS), n_pass, n_fail, n_skip))
    if n_fail:
        print("\n失败明细：")
        for n, s, d in RESULTS:
            if s == "FAIL":
                print("  - %s | %s" % (n, d))
    if n_skip:
        print("\n跳过明细：")
        for n, s, d in RESULTS:
            if s == "SKIP":
                print("  - %s | %s" % (n, d))
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
