"""The displayed teaching material must reproduce the actual operation."""

import os
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from PySide6.QtCore import QPoint
from PySide6.QtWidgets import QApplication
from pqcrypto.kem import ml_kem_512, ml_kem_768
from pqcrypto.sign import ml_dsa_44

from modules import pqc_demo
from modules.pqc_demo_ui import PqcDemoTab


def test_displayed_kem_private_key_decapsulates_displayed_ciphertext():
    material = pqc_demo.run_kem_demo()["materials"]
    secret = ml_kem_512.decrypt(material["keys"]["接收方 ML-KEM 私钥"],
                               material["outputs"]["封装密文"])
    assert secret == material["outputs"]["发送方共享秘密"]
    assert secret == material["outputs"]["接收方共享秘密"]


def test_kem_uses_the_entered_32_bytes_in_the_actual_encapsulation():
    from modules.mlkem_trace import MLKEM

    message = bytes(range(32))
    result = pqc_demo.run_kem_demo(encapsulation_input=message)
    material = result["materials"]
    ciphertext, shared = MLKEM("ML-KEM-512").encaps(material["keys"]["接收方 ML-KEM 公钥"], message)
    assert material["inputs"]["封装输入 m（32 字节）"] == message
    assert material["outputs"]["封装密文"] == ciphertext
    assert material["outputs"]["发送方共享秘密"] == shared


def test_each_page_keeps_its_own_visible_input_when_switching_tabs():
    app = QApplication.instance() or QApplication([])
    tab = PqcDemoTab()
    tab.resize(1040, 800)
    tab.show()
    for page, operation, text in ((0, "kem", "00" * 32), (1, "hybrid", "交换消息"),
                                  (2, "sign", "签名消息"), (3, "hybrid_sign", "混合签名消息")):
        tab.pages.setCurrentIndex(page)
        app.processEvents()
        box = tab.message_inputs[operation]
        assert box.isVisible()
        assert box.edit.isVisible()
        box.edit.setPlainText(text)
    for page, operation, text in ((2, "sign", "签名消息"), (0, "kem", "00" * 32),
                                  (3, "hybrid_sign", "混合签名消息"), (1, "hybrid", "交换消息")):
        tab.pages.setCurrentIndex(page)
        app.processEvents()
        assert tab.message_inputs[operation].edit.toPlainText() == text
        assert tab.message_inputs[operation].edit.height() >= 50
        _run(app, tab, {"kem": tab.btn_kem, "hybrid": tab.btn_hybrid,
                       "sign": tab.btn_sign, "hybrid_sign": tab.btn_hybrid_sign}[operation])
        inputs = tab.material_views[operation]._materials["inputs"]
        assert inputs["封装输入 m（32 字节）" if operation == "kem" else "消息原始字节"] == (
            bytes(32) if operation == "kem" else text.encode("utf-8"))
    tab.close()


@pytest.mark.parametrize("classical", ["X25519", "P-384"])
def test_displayed_hybrid_material_decrypts_the_original_binary_input(classical):
    material = pqc_demo.run_hybrid_demo(b"\x00\xff\x80", classical_algorithm=classical)["materials"]
    assert ml_kem_768.decrypt(material["keys"]["接收方 ML-KEM 私钥"],
                              material["outputs"]["ML-KEM 封装密文"]) == material["outputs"]["ML-KEM 共享秘密"]
    for party in ("发送方", "接收方"):
        key = serialization.load_der_private_key(
            material["keys"][party + " ECDHE 私钥（PKCS8 DER）"], password=None)
        public_format = (serialization.Encoding.Raw, serialization.PublicFormat.Raw) if classical == "X25519" else (
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        assert key.public_key().public_bytes(*public_format) == material["keys"][party + " ECDHE 公钥"]
    recovered = AESGCM(material["outputs"]["AES-256-GCM 密钥"]).decrypt(
        material["inputs"]["Nonce"], material["outputs"]["AES-GCM 密文（含认证标签）"],
        material["inputs"]["AAD"])
    assert recovered == material["inputs"]["消息原始字节"] == b"\x00\xff\x80"
    assert recovered == material["outputs"]["解密明文"]


def test_displayed_signature_key_signs_the_displayed_input():
    material = pqc_demo.run_signature_demo(b"binary\x00\xff", "ML-DSA-44")["materials"]
    public, private = material["keys"]["后量子公钥"], material["keys"]["后量子私钥"]
    message = material["inputs"]["消息原始字节"]
    assert ml_dsa_44.verify(public, message, ml_dsa_44.sign(private, message))
    assert ml_dsa_44.verify(public, message, material["outputs"]["后量子签名"])


def test_displayed_hybrid_signature_uses_both_keys_and_actual_bound_input():
    material = pqc_demo.run_hybrid_signature_demo(b"bound\x00\xff", "ML-DSA-44")["materials"]
    keys, inputs, outputs = (material[section] for section in ("keys", "inputs", "outputs"))
    private = serialization.load_der_private_key(keys["传统私钥（PKCS8 DER）"], password=None)
    assert private.public_key().public_bytes(serialization.Encoding.Raw,
                                            serialization.PublicFormat.Raw) == keys["传统公钥（Raw）"]
    private.public_key().verify(outputs["传统签名"], inputs["实际签名输入（绑定算法、公钥与消息）"])
    assert ml_dsa_44.verify(keys["后量子公钥"], inputs["实际签名输入（绑定算法、公钥与消息）"],
                           ml_dsa_44.sign(keys["后量子私钥"], inputs["实际签名输入（绑定算法、公钥与消息）"]))
    assert inputs["消息原始字节"] == b"bound\x00\xff"
    assert "materials" not in pqc_demo.sign_hybrid_message(b"public artifact")


def _run(app, tab, button):
    button.click()
    deadline = time.monotonic() + 10
    while tab._worker is not None and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.01)
    assert tab._worker is None, "演示执行超时"


@pytest.mark.parametrize("encoding,text", [("HEX", "00 ff 80"), ("Base64", "AP+A")])
def test_binary_message_encoding_and_display_format_preserve_bytes(encoding, text):
    app = QApplication.instance() or QApplication([])
    tab = PqcDemoTab()
    tab.pages.setCurrentIndex(1)
    tab.message_encoding.setCurrentText(encoding)
    tab.message_edit.setPlainText(text)
    assert "3 / 4096" in tab.message_info.text()
    _run(app, tab, tab.btn_hybrid)
    assert "验证通过" in tab.hybrid_status.text()
    view = tab.material_views["hybrid"]
    assert tab.hybrid_result_tabs.currentWidget() is view
    assert "00ff80" in view.output.toPlainText()
    view.encoding_combo.setCurrentText("Base64")
    assert "AP+A" in view.output.toPlainText()
    assert "接收方 ML-KEM 私钥" in view.private_edit.toPlainText()
    assert "私钥" not in view.output.toPlainText()
    tab.message_edit.setPlainText("changed")
    assert not view.output.toPlainText()
    assert not view.private_edit.toPlainText()
    assert tab.hybrid_trace_view.tree.topLevelItemCount() == 0
    tab.close()


@pytest.mark.parametrize("page,operation", [(0, "kem"), (1, "hybrid"), (2, "sign"), (3, "hybrid_sign")])
def test_demo_form_places_keys_above_message_and_output(page, operation):
    app = QApplication.instance() or QApplication([])
    tab = PqcDemoTab()
    tab.resize(1040, 800)
    tab.pages.setCurrentIndex(page)
    tab.show()
    app.processEvents()
    view = tab.material_views[operation]
    assert view.keys_box.isVisible()
    assert view.private_edit.isVisible()
    assert view.public_edit.isVisible()
    assert view.isVisible()
    keys_y = view.keys_box.mapTo(tab, QPoint()).y()
    output_y = view.mapTo(tab, QPoint()).y()
    message_y = tab.message_box.mapTo(tab, QPoint()).y()
    assert keys_y < message_y < output_y
    tab.close()


@pytest.mark.parametrize("encoding,text", [("HEX", "0xz1"), ("Base64", "%%%"), ("Base64", "YQ==!!!!")])
def test_invalid_encoding_clears_old_output_without_starting_crypto(encoding, text):
    app = QApplication.instance() or QApplication([])
    tab = PqcDemoTab()
    tab.pages.setCurrentIndex(2)
    _run(app, tab, tab.btn_sign)
    tab.message_encoding.setCurrentText(encoding)
    tab.message_edit.setPlainText(text)
    tab.btn_sign.click()
    assert tab._worker is None
    assert "输入错误" in tab.signature_status.text()
    assert not tab.material_views["sign"].output.toPlainText()
    assert tab.signature_trace_view.tree.topLevelItemCount() == 0
    # Invalid signing input must not affect the separate ML-KEM input.
    _run(app, tab, tab.btn_kem)
    assert "验证通过" in tab.kem_status.text()
    tab.close()


def test_file_import_keeps_binary_bytes_and_parameter_change_clears_old_keys(tmp_path):
    app = QApplication.instance() or QApplication([])
    tab = PqcDemoTab()
    tab.pages.setCurrentIndex(2)
    path = tmp_path / "message.bin"
    path.write_bytes(b"\x00\xff\x80")
    tab.load_message_file(str(path))
    assert tab.message_encoding.currentText() == "HEX"
    _run(app, tab, tab.btn_sign)
    assert "后量子签名" in tab.material_views["sign"].output.toPlainText()
    assert tab.material_views["sign"].private_edit.toPlainText()
    tab.signature_combo.setCurrentText("ML-DSA-44")
    assert not tab.material_views["sign"].output.toPlainText()
    path.write_bytes(b"a" * 4097)
    tab.load_message_file(str(path))
    assert "4096" in tab.message_info.text()
    assert tab.message_edit.toPlainText() == "00ff80"
    tab.close()


def test_kem_button_uses_the_visible_input_and_rejects_wrong_byte_count():
    app = QApplication.instance() or QApplication([])
    tab = PqcDemoTab()
    tab.message_edit.setPlainText(bytes(range(32)).hex())
    _run(app, tab, tab.btn_kem)
    assert bytes(range(32)).hex() in tab.material_views["kem"].output.toPlainText()
    tab.message_edit.setPlainText("aabb")
    tab.btn_kem.click()
    assert tab._worker is None
    assert "32 字节" in tab.kem_output.toPlainText()
    assert not tab.material_views["kem"].private_edit.toPlainText()
    tab.close()
