"""Exercise the actual Qt entry points with an offscreen event loop."""

import os
import time
import datetime
import json
import base64

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtGui import QFont, QFontMetrics
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QTabWidget, QSplitter

from main import MainWindow
from modules.pqc_demo_ui import PqcDemoTab, PqcCompareTab


def _actual_replay_bundle():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, x25519
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.x509.oid import NameOID

    signing_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "replay-ui-test")])
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                   .public_key(signing_key.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
                   .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
                   .sign(signing_key, hashes.SHA256()))
    content = b"actual handshake content"
    signature = signing_key.sign(content, ec.ECDSA(hashes.SHA256()))
    key = bytes(range(32))
    nonce = bytes(range(12))
    plaintext = b"actual record"
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, b"record-header")
    client = x25519.X25519PrivateKey.generate()
    peer = x25519.X25519PrivateKey.generate()
    raw = serialization.Encoding.Raw
    return {
        "session": {"same_handshake": True},
        "certificates": [certificate.public_bytes(serialization.Encoding.DER)],
        "key_exchange": {
            "algorithm": "X25519",
            "server_public_key": peer.public_key().public_bytes(raw, serialization.PublicFormat.Raw),
            "private_key": client.private_bytes(raw, serialization.PrivateFormat.Raw,
                                                serialization.NoEncryption()),
            "expected_shared_secret": client.exchange(peer.public_key()),
        },
        "handshake_signature": {"scheme": "0x0403", "signed_content": content,
                                "signature": signature},
        "encrypted_records": [{"algorithm": "AES-256-GCM", "key": key, "nonce": nonce,
                               "aad": b"record-header", "ciphertext": ciphertext,
                               "expected_plaintext": plaintext}],
    }


def _json_bundle(bundle):
    def encode(value):
        if isinstance(value, bytes):
            return base64.b64encode(value).decode("ascii")
        if isinstance(value, dict):
            return {key: encode(item) for key, item in value.items()}
        if isinstance(value, list):
            return [encode(item) for item in value]
        return value
    return json.dumps(encode(bundle))


def _wait_for(app, predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        app.processEvents()
        if predicate():
            return
        time.sleep(0.01)
    assert predicate(), "操作超时"


def test_main_window_exposes_demo_and_comparison_pages():
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    tabs = window.centralWidget()

    assert isinstance(tabs, QTabWidget)
    assert any(isinstance(tabs.widget(i), PqcDemoTab) for i in range(tabs.count()))
    assert any(isinstance(tabs.widget(i), PqcCompareTab) for i in range(tabs.count()))
    assert tabs.tabText(0) == "① TLS 1.3 后量子检测"
    app.processEvents()
    window.close()


def test_standalone_kem_page_shows_verification_without_dumping_secrets():
    app = QApplication.instance() or QApplication([])
    tab = PqcDemoTab()
    assert tab.pages.tabText(0) == "① ML-KEM 密钥封装"
    assert not tab.message_box.isVisible()
    tab.standalone_kem_combo.setCurrentText("ML-KEM-512")
    tab.btn_kem.click()
    _wait_for(app, lambda: tab.btn_kem.isEnabled())

    output = tab.kem_output.toPlainText()
    assert "ML-KEM-512" in output
    assert "双方共享秘密一致：是" in output
    assert "修改封装密文后秘密不同：是" in output
    assert "800 字节" in output
    assert "768 字节" in output
    assert "公钥（Base64）" not in output
    assert "公钥（Base64）" in tab.kem_raw_output.toPlainText()
    assert "私钥" not in tab.kem_raw_output.toPlainText()
    tab.close()


def test_captured_hybrid_group_configures_hybrid_demo():
    app = QApplication.instance() or QApplication([])
    report = {
        "host": "www.example.com", "port": 443,
        "transport": {
            "group_id": 0x11EC, "group_name": "X25519MLKEM768",
            "key_share_body": 1124, "expect_body": 1124, "size_ok": True,
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
            "offered": ["X25519MLKEM768 (0x11EC)", "X25519 (0x001D)"],
        },
        "cert": {"subject_cn": "example.com"},
    }
    tab = PqcDemoTab(capture_provider=lambda: report)
    assert tab.import_captured_parameters()
    assert tab.pages.currentIndex() == 1
    assert tab.classical_combo.currentText() == "X25519"
    assert tab.kem_combo.currentText() == "ML-KEM-768"
    assert "ServerHello 选中组：X25519MLKEM768" in tab.message_edit.toPlainText()
    assert "已导入" in tab.capture_status.text()
    tab.btn_hybrid.click()
    _wait_for(app, lambda: tab.btn_hybrid.isEnabled())
    assert "来源：www.example.com" in tab.hybrid_output.toPlainText()
    assert "ServerHello 选中组：X25519MLKEM768" in tab.hybrid_output.toPlainText()
    tab.close()


def test_captured_pure_mlkem_group_configures_kem_demo():
    app = QApplication.instance() or QApplication([])
    report = {"host": "pqc.example", "port": 443, "transport": {
        "group_id": 0x0202, "group_name": "MLKEM1024"}}
    tab = PqcDemoTab(capture_provider=lambda: report)
    assert tab.import_captured_parameters()
    assert tab.pages.currentIndex() == 0
    assert tab.standalone_kem_combo.currentText() == "ML-KEM-1024"
    tab.close()


def test_captured_classical_group_is_rejected_with_clear_hint():
    app = QApplication.instance() or QApplication([])
    report = {"transport": {"group_id": 0x001D, "group_name": "X25519"}}
    tab = PqcDemoTab(capture_provider=lambda: report)
    assert not tab.import_captured_parameters()
    assert "未选中 ML-KEM" in tab.capture_status.text()
    tab.close()


def test_message_demo_rejects_input_over_4096_utf8_bytes():
    app = QApplication.instance() or QApplication([])
    tab = PqcDemoTab()
    tab.message_edit.setPlainText("量" * 1366)
    tab.btn_hybrid.click()
    app.processEvents()

    assert "4096 字节" in tab.hybrid_output.toPlainText()
    assert tab.btn_hybrid.isEnabled()
    tab.close()


def test_hybrid_demo_button_shows_real_roundtrip():
    app = QApplication.instance() or QApplication([])
    tab = PqcDemoTab()
    tab.message_edit.setPlainText("界面加密测试")
    tab.btn_hybrid.click()
    _wait_for(app, lambda: tab.btn_hybrid.isEnabled())

    output = tab.hybrid_output.toPlainText()
    assert "AES-256-GCM" in output
    assert "界面加密测试" in output
    assert "篡改检测：已拒绝" in output
    tab.close()


def test_signature_button_shows_verification_and_optional_full_signature():
    app = QApplication.instance() or QApplication([])
    tab = PqcDemoTab()
    tab.message_edit.setPlainText("签名测试")
    tab.signature_combo.setCurrentText("Falcon-512")
    tab.btn_sign.click()
    _wait_for(app, lambda: tab.btn_sign.isEnabled())

    output = tab.signature_output.toPlainText()
    assert "Falcon-512" in output
    assert "原消息验签：通过" in output
    assert "改动消息验签：已拒绝" in output
    assert "签名（Base64）" not in output
    assert "签名（Base64）" in tab.signature_raw_output.toPlainText()
    assert not tab.signature_raw_output.isVisible()
    tab.signature_raw_checkbox.setChecked(True)
    tab.pages.setCurrentIndex(2)
    tab.show()
    app.processEvents()
    assert tab.signature_raw_output.isVisible()
    tab.close()


def test_selected_hybrid_parameters_and_resizable_layout():
    app = QApplication.instance() or QApplication([])
    tab = PqcDemoTab()
    tab.resize(900, 650)
    tab.show()
    tab.pages.setCurrentIndex(1)
    app.processEvents()
    assert tab.message_box.isVisible()
    assert isinstance(tab.main_splitter, QSplitter)
    assert tab.main_splitter.count() == 2
    assert {tab.kem_combo.itemText(i) for i in range(tab.kem_combo.count())} == {
        "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}
    assert {tab.classical_combo.itemText(i) for i in range(tab.classical_combo.count())} == {
        "X25519", "P-256", "P-384"}
    tab.main_splitter.setSizes([220, 380])
    app.processEvents()
    assert tab.main_splitter.sizes()[0] >= 180

    tab.kem_combo.setCurrentText("ML-KEM-1024")
    tab.classical_combo.setCurrentText("P-384")
    tab.message_edit.setPlainText("选择参数组")
    tab.btn_hybrid.click()
    _wait_for(app, lambda: tab.btn_hybrid.isEnabled())
    output = tab.hybrid_output.toPlainText()
    assert "P-384 + ML-KEM-1024" in output
    assert "选择参数组" in output
    assert "P-384 公钥：97 字节" in output
    assert "封装密文：1568 字节" in output
    assert not tab.hybrid_raw_output.isVisible()
    tab.pages.setCurrentIndex(1)
    tab.hybrid_raw_checkbox.setChecked(True)
    app.processEvents()
    assert tab.hybrid_raw_output.isVisible()
    assert "AES-GCM 密文（Base64，含认证标签）" in tab.hybrid_raw_output.toPlainText()
    tab.close()


def test_signature_selector_exposes_all_supported_parameter_sets():
    app = QApplication.instance() or QApplication([])
    from modules.pqc_demo import SIGNATURE_VARIANTS

    tab = PqcDemoTab()
    assert {tab.signature_combo.itemText(i) for i in range(tab.signature_combo.count())} == set(SIGNATURE_VARIANTS)
    tab.signature_combo.setCurrentText("ML-DSA-87")
    tab.btn_sign.click()
    _wait_for(app, lambda: tab.btn_sign.isEnabled())
    assert "算法：ML-DSA-87" in tab.signature_output.toPlainText()
    assert "原消息验签：通过" in tab.signature_output.toPlainText()
    tab.close()


def test_wsl_loads_a_font_with_chinese_glyphs():
    from main import _configure_fonts

    app = QApplication.instance() or QApplication([])
    family = _configure_fonts(app)
    assert QFontMetrics(QFont(family)).inFontUcs4(ord("中"))


def test_replay_page_calculates_from_actual_session_material():
    app = QApplication.instance() or QApplication([])
    tab = PqcDemoTab()
    tab.pages.setCurrentIndex(3)
    tab.show()
    app.processEvents()
    tab.replay_bundle_edit.setPlainText(_json_bundle(_actual_replay_bundle()))
    tab.btn_replay.click()
    assert "Certificate 列表严格解析" in tab.replay_output.toPlainText()
    assert "密钥封装 / 交换复算：共享秘密复算一致" in tab.replay_output.toPlainText()
    assert "握手签名验签：用叶子证书 SPKI 公钥验签通过，服务器掌握对应私钥" in tab.replay_output.toPlainText()
    assert "认证解密通过" in tab.replay_output.toPlainText()
    assert "复算完成 · 同次连接" in tab.replay_status.text()
    assert json.loads(tab.replay_result_json.toPlainText())["conclusion"] == "verified"
    tab.close()


def test_comparison_page_shows_common_classical_algorithms():
    app = QApplication.instance() or QApplication([])
    tab = PqcCompareTab()
    names = {tab.table.item(row, 0).text() for row in range(tab.table.rowCount())}
    assert {"RSA-PSS-2048", "ECDSA-P256", "ECDH-P256", "SM2", "ML-DSA-65"} <= names
    assert not any(tab.table.item(row, col) is None
                   for row in range(tab.table.rowCount())
                   for col in range(tab.table.columnCount()))
    app.processEvents()
    tab.close()


def test_kem_calculation_view_shows_parameters_randomness_and_all_coefficients():
    app = QApplication.instance() or QApplication([])
    tab = PqcDemoTab()
    tab.standalone_kem_combo.setCurrentText("ML-KEM-1024")
    tab.btn_kem.click()
    _wait_for(app, lambda: tab.btn_kem.isEnabled())
    viewer = tab.kem_trace_view
    assert "参数与计算过程" == tab.kem_result_tabs.tabText(1)
    assert "q = 3329" in viewer.detail.toPlainText()
    flags = Qt.MatchFlag.MatchContains | Qt.MatchFlag.MatchRecursive
    randomness = viewer.tree.findItems("本次运行的随机输入", flags)
    assert randomness
    viewer.tree.setCurrentItem(randomness[0])
    assert "d（32 字节，十六进制）" in viewer.detail.toPlainText()
    assert "m（32 字节，十六进制）" in viewer.detail.toPlainText()
    ntt_layers = viewer.tree.findItems("蝶形层 length=128", flags)
    assert ntt_layers
    viewer.tree.setCurrentItem(ntt_layers[0])
    detail = viewer.detail.toPlainText()
    assert "计算示例" in detail
    assert "input_coefficients" in detail
    assert "output_coefficients" in detail
    assert "[240..255]" in detail
    layer = ntt_layers[0]
    output_variable = next(layer.child(i) for i in range(layer.childCount())
                           if layer.child(i).text(0).startswith("output_coefficients"))
    viewer.tree.setCurrentItem(output_variable)
    detail = viewer.detail.toPlainText()
    assert "t=ζ_i" in detail
    assert "FIPS 203，算法 9" in detail
    assert "[240..255]" in detail
    tab.close()


def test_hybrid_trace_is_cleared_when_new_input_is_invalid():
    app = QApplication.instance() or QApplication([])
    tab = PqcDemoTab()
    tab.btn_hybrid.click()
    _wait_for(app, lambda: tab.btn_hybrid.isEnabled())
    viewer = tab.hybrid_trace_view
    flags = Qt.MatchFlag.MatchContains | Qt.MatchFlag.MatchRecursive
    assert viewer.tree.findItems("HKDF", flags)
    tab.message_edit.setPlainText("量" * 1366)
    tab.btn_hybrid.click()
    assert viewer.tree.topLevelItemCount() == 0
    assert "4096" in tab.hybrid_output.toPlainText()
    tab.close()


def test_kem_trace_is_cleared_and_buttons_recover_after_a_failed_retry(monkeypatch):
    from modules import pqc_demo

    app = QApplication.instance() or QApplication([])
    tab = PqcDemoTab()
    tab.btn_kem.click()
    _wait_for(app, lambda: tab.btn_kem.isEnabled())
    assert tab.kem_trace_view.tree.topLevelItemCount()

    def fail(*args):
        raise RuntimeError("计算校验失败")

    monkeypatch.setattr(pqc_demo, "run_kem_demo", fail)
    tab.btn_kem.click()
    _wait_for(app, lambda: tab.btn_kem.isEnabled())
    assert tab.kem_trace_view.tree.topLevelItemCount() == 0
    assert "计算校验失败" in tab.kem_output.toPlainText()
    tab.close()


def test_signature_details_use_family_parameters_and_real_calculations():
    app = QApplication.instance() or QApplication([])
    tab = PqcDemoTab()
    tab.signature_combo.setCurrentText("Falcon-512")
    tab.btn_sign.click()
    _wait_for(app, lambda: tab.btn_sign.isEnabled())
    viewer = tab.signature_trace_view
    assert tab.signature_result_tabs.tabText(1) == "参数与计算过程"
    assert "q = 12289" in viewer.detail.toPlainText()
    assert "FIPS 203" not in viewer.detail.toPlainText()
    flags = Qt.MatchFlag.MatchContains | Qt.MatchFlag.MatchRecursive
    norm = viewer.tree.findItems("短向量范数检查", flags)
    assert norm
    viewer.tree.setCurrentItem(norm[0])
    assert "squared_norm" in viewer.detail.toPlainText()
    assert "[496..511]" in viewer.detail.toPlainText()
    tab.message_edit.setPlainText("量"*1366)
    tab.btn_sign.click()
    assert viewer.tree.topLevelItemCount() == 0
    tab.close()
