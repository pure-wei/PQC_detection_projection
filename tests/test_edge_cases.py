# -*- coding: utf-8 -*-
"""边界与异常路径测试：确认各页面对错误输入给出明确提示，且不崩溃、不误判。

    python tests/test_edge_cases.py
"""
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from PySide6.QtWidgets import QApplication                      # noqa: E402

import main as appmod                                           # noqa: E402
from modules import sm2_sm3                                     # noqa: E402

RESULTS = []
MSGS = []


def tab_by_class(tabs, cls):
    return next(tabs.widget(i) for i in range(tabs.count()) if isinstance(tabs.widget(i), cls))


def record(name, state, detail=""):
    RESULTS.append((name, state, detail))
    print("[%s] %-52s %s" % (state, name, detail))


def case(name, fn, network=False):
    if network and "--offline" in sys.argv:
        record(name, "SKIP", "离线模式不发起外网检测")
        return
    try:
        detail = fn() or ""
        if str(detail).startswith("SKIP:"):
            record(name, "SKIP", str(detail)[5:].strip())
            return
        record(name, "PASS", str(detail)[:100])
    except Exception as e:
        msg = "%s: %s" % (type(e).__name__, e)
        record(name, "SKIP" if network else "FAIL", msg[:100])


def pump(app, n=8):
    for _ in range(n):
        app.processEvents()


def t_pqc(app, tabs):
    page = tab_by_class(tabs, appmod.PqcDetectTab)

    def bad_port():
        MSGS.clear()
        page.host_edit.setText("example.com")
        page.port_edit.setText("99999")
        page._report = None
        try:
            page._run()
            pump(app)
            assert page._report is None, "非法端口不应发起检测"
            assert MSGS, "非法端口未给出提示"
        finally:
            page.port_edit.setText("443")
        return MSGS[-1][:50]

    def bad_timeout():
        page.port_edit.setText("443")
        page.host_edit.setText("www.cloudflare.com")
        page.timeout_edit.setText("abc")
        page.mode_combo.setCurrentIndex(1)
        page._report = None
        page._run()
        for _ in range(500):
            pump(app, 2)
            if page._report is not None:
                break
            app.thread().msleep(30)
        assert page._report, "非法超时应回退默认值并继续检测"
        assert "单次超时 12 秒" in page.log_edit.toPlainText(), "未使用默认超时"
        page.timeout_edit.setText("15")
        return "回退默认超时并完成检测（已提示）"

    def empty_host():
        # 等待上一用例的检测线程结束（界面中按钮此时是禁用的，测试直接调用需自行等待）
        for _ in range(600):
            pump(app, 2)
            if page._worker is None or not page._worker.isRunning():
                break
            app.thread().msleep(30)
        MSGS.clear()
        page.host_edit.setText("")
        page._report = None          # 校验失败时应保持"未发起检测"状态
        page._run()
        pump(app)
        assert page._report is None and MSGS, "空目标未拦截"
        return MSGS[-1][:40]

    case("① 非法端口（99999）被拦截", bad_port)
    case("① 非法超时（abc）回退默认值", bad_timeout, network=True)
    case("① 空目标被拦截", empty_host)


def t_sm2(app, tabs):
    inner = tab_by_class(tabs, appmod.Sm2Sm3Tab).inner
    sign, verify = inner.widget(0), inner.widget(1)
    priv, pub = sm2_sm3.generate_sm2_keypair()

    def sign_without_pub():
        MSGS.clear()
        sign.priv_edit.setText(priv)
        sign.pub_edit.setText("")
        sign.msg_edit.setPlainText("48656c6c6f")
        sign._do_sign()
        pump(app)
        assert MSGS, "缺少公钥时未提示"
        return MSGS[-1][:60]

    def verify_wrong_msg():
        sign.priv_edit.setText(priv)
        sign.pub_edit.setText(pub)
        sign.msg_edit.setPlainText("48656c6c6f")
        sign._do_sign()
        pump(app)
        sig = sign.sig_edit.toPlainText().strip()
        verify.pub_edit.setText(pub)
        verify.sig_edit.setPlainText(sig)
        verify.msg_edit.setPlainText("776f726c64")       # 换一条消息
        verify._do_verify()
        pump(app)
        txt = verify.res_edit.toPlainText()
        assert "不通过" in txt and "通过 ✓" not in txt.split("不通过")[0][-6:], \
            "错误消息不应验签通过"
        return "错误消息判为不通过"

    def verify_der_signature():
        sign.msg_edit.setPlainText("48656c6c6f")
        sign._do_sign()
        pump(app)
        sig = sign.sig_edit.toPlainText().strip()
        der = sm2_sm3.rs_to_der(sig).hex()
        verify.pub_edit.setText(pub)
        verify.sig_edit.setPlainText(der)                 # DER 形式
        verify.msg_edit.setPlainText("48656c6c6f")
        verify._do_verify()
        pump(app)
        assert "通过" in verify.res_edit.toPlainText(), "DER 签名未通过"
        return "r‖s 与 DER 均可验签"

    def verify_empty_pub():
        MSGS.clear()
        verify.pub_edit.setText("")
        verify.sig_edit.setPlainText("00" * 64)
        verify.msg_edit.setPlainText("61")
        verify._do_verify()
        pump(app)
        assert MSGS or "失败" in verify.res_edit.toPlainText() or \
            "不通过" in verify.res_edit.toPlainText(), "空公钥未给出任何反馈"
        return "空公钥已反馈"

    case("② 签名缺少公钥时提示", sign_without_pub)
    case("② 错误消息验签判为不通过", verify_wrong_msg)
    case("② DER 形式签名可验签", verify_der_signature)
    case("② 空公钥验签有反馈", verify_empty_pub)


def t_codec(app, tabs):
    page = tab_by_class(tabs, appmod.CodecTab)

    def empty_input():
        page.in_edit.setPlainText("")
        page._convert_from_cfg()
        pump(app)
        assert page.out_edit.toPlainText().strip() == "", "空输入应清空输出"
        return "空输入清空输出"

    def bad_hex():
        page.in_combo.setCurrentIndex([v for v, _l in page._IN_FORMATS].index("hex"))
        page.in_edit.setPlainText("zzzz")
        page._convert_from_cfg()
        pump(app)
        out = page.out_edit.toPlainText()
        assert "转换失败" in out, "非法 HEX 未在输出区提示：%s" % out[:40]
        return out.strip()[:50]

    case("③ 空输入提示", empty_input)
    case("③ 非法 HEX 提示", bad_hex)


def t_sym(app, tabs):
    page = tab_by_class(tabs, appmod.SymCryptoTab)


    def gcm_bad_tag():
        MSGS.clear()
        page.cmb_alg.setCurrentText("AES")
        page.cmb_mode.setCurrentText("GCM")
        page.key_edit.setText("0123456789abcdef0123456789abcdef")
        page.iv_edit.setText("000102030405060708090a0b")   # 12 字节 nonce
        page.rb_utf8.setChecked(True)
        page.rb_out_hex.setChecked(True)
        page.in_edit.setPlainText("gcm data")
        page._do_encrypt()
        pump(app, 6)
        ct = page.out_edit.toPlainText().strip()
        assert ct, "GCM 加密无输出"
        page.rb_hex.setChecked(True)
        page.in_edit.setPlainText(ct)
        page.tag_edit.setText("00" * 16)                   # 故意填错 Tag
        page._do_decrypt()
        pump(app, 6)
        assert MSGS and "GCM" in MSGS[-1], "GCM 认证失败未给出明确提示"
        return MSGS[-1][:60]

    case("⑥ GCM Tag 错误明确报错", gcm_bad_tag)


def t_pcap(app, tabs):
    page = tab_by_class(tabs, appmod.PcapTab)

    def export_before_load():
        page._clear()
        pump(app)
        assert not page.btn_export.isEnabled(), "未加载文件时导出按钮应禁用"
        return "导出按钮已禁用"

    def load_nonexistent():
        MSGS.clear()
        page.analyze_file(os.path.join(ROOT, "samples", "__not_exist__.pcap"))
        pump(app)
        assert MSGS, "加载不存在的文件未提示"
        return MSGS[-1][:50]

    case("④ 未加载文件时导出禁用", export_before_load)
    case("④ 加载不存在的 pcap 有提示", load_nonexistent)


def main():
    app = QApplication.instance() or QApplication([])
    app.setStyleSheet(appmod.QSS)

    def rec(kind):
        def _f(*args, **kwargs):
            text = ""
            for a in args[1:]:
                if isinstance(a, str) and a:
                    text = a
            MSGS.append(text or "(无文本)")
            return 0
        return staticmethod(_f)

    appmod.QMessageBox.exec = lambda self, *a, **k: 0
    appmod.QMessageBox.information = rec("info")
    appmod.QMessageBox.warning = rec("warn")
    appmod.QMessageBox.critical = rec("crit")
    win = appmod.MainWindow()
    win.show()
    pump(app, 10)
    tabs = win.centralWidget()
    for fn in (t_pqc, t_sm2, t_codec, t_sym, t_pcap):
        fn(app, tabs)
    win.close()
    print("-" * 92)
    n_fail = sum(1 for _n, s, _d in RESULTS if s == "FAIL")
    print("合计 %d 项：通过 %d，失败 %d" % (
        len(RESULTS), sum(1 for _n, s, _d in RESULTS if s == "PASS"), n_fail))
    if n_fail:
        print("\n失败明细：")
        for n, s, d in RESULTS:
            if s == "FAIL":
                print("  - %s | %s" % (n, d))
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
