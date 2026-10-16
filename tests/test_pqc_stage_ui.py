"""The detection page must describe the work actually completed on this connection."""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication

from main import PqcDetectTab
from modules import pqc_detect


@pytest.fixture
def page():
    app = QApplication.instance() or QApplication([])
    tab = PqcDetectTab()
    yield tab
    tab.close()
    app.processEvents()


def _report(group=0x11EC, **deep_updates):
    deep = {
        "ok": True, "shared_secret_len": 64,
        "key_derivation": {"hash_name": "sha256", "aead": "aes", "key_len": 16,
                           "iv_len": 12, "finished_key_len": 32},
        "server_messages": [{"name": "Certificate", "len": 3000},
                            {"name": "CertificateVerify", "len": 3300},
                            {"name": "Finished", "len": 32}],
        "cert_verify": {"verified": True, "scheme_name": "mldsa65", "sig_len": 3309},
        "finished_verified": True, "finished_len": 32,
    }
    deep.update(deep_updates)
    return {"transport": {"ok": True, "group_id": group,
                          "group_name": pqc_detect.lookup_group(group)[0]}, "deep": deep}


def _row(page, step):
    for i in range(page.cert_table.rowCount()):
        if page.cert_table.item(i, 0).text() == step:
            return page.cert_table.item(i, 1).text(), page.cert_table.item(i, 2).text()
    raise AssertionError("Missing stage: " + step)


@pytest.mark.parametrize("group,present,absent", [
    (0x001D, "ECDHE", "ML-KEM"), (0x0201, "ML-KEM", "ECDHE"),
])
def test_calculation_description_uses_negotiated_group(page, group, present, absent):
    page._fill_compact_report(_report(group, shared_secret_len=32))
    text, status = _row(page, "计算握手密钥")
    assert present in text
    assert absent not in text
    assert status == "通过"


@pytest.mark.parametrize("verification,status", [
    ({}, "未完成"),
    ({"verified": False, "error_kind": "unsupported", "error": "scheme unavailable"}, "不支持"),
    ({"verified": False, "error_kind": "invalid", "error": "invalid signature"}, "失败"),
])
def test_certificate_verify_distinguishes_unavailable_and_invalid(page, verification, status):
    page._fill_compact_report(_report(cert_verify=verification))
    assert _row(page, "CertificateVerify")[1] == status


def test_interrupted_flight_keeps_successful_derivation_without_claiming_decryption_passed(page):
    page._fill_compact_report(_report(
        ok=False, cert_verify={}, finished_verified=False, finished_len=None,
        error="connection closed before Finished",
        server_messages=[{"name": "Certificate", "len": 3000}],
    ))
    assert _row(page, "计算握手密钥")[1] == "通过"
    assert _row(page, "解密服务器握手")[1] == "未完成"
    assert _row(page, "服务器 Finished")[1] == "未完成"


def test_local_certificate_is_not_described_as_a_network_capture(page):
    page._fill_compact_report({"cert": {
        "subject_cn": "local.test", "sig_algorithm": "ML-DSA-65",
        "pub_algorithm": "ML-DSA-65", "sig_bytes": 3309, "pub_bytes": 1952,
    }})
    text, status = _row(page, "证书详情")
    assert "本地证书文件" in text
    assert "独立连接" not in text
    assert "未验证" in text
    assert status == "已解析"


def test_signature_parsing_failure_does_not_erase_completed_decryption(page):
    page._fill_compact_report(_report(
        ok=False, error="ValueError: CertificateVerify 头截断", cert_verify={},
        verification_error_kind="invalid", failed_stage="certificate_verify",
    ))
    assert _row(page, "解密服务器握手")[1] == "通过"
    assert _row(page, "CertificateVerify")[1] == "失败"


@pytest.mark.parametrize("failed_stage,step,updates", [
    ("key_derivation", "计算握手密钥", {"shared_secret_len": 0}),
    ("server_handshake", "解密服务器握手", {"server_messages": [], "finished_len": None}),
    ("finished", "服务器 Finished", {"finished_len": 0}),
])
def test_invalid_crypto_result_is_a_failure_of_its_stage(page, failed_stage, step, updates):
    page._fill_compact_report(_report(
        ok=False, cert_verify={}, finished_verified=False,
        verification_error_kind="invalid", failed_stage=failed_stage, error="校验失败", **updates,
    ))
    assert _row(page, step)[1] == "失败"


def test_wrapped_rows_refit_after_table_width_changes(page):
    app = QApplication.instance()
    page.resize(1500, 820)
    page.show()
    app.processEvents()
    # A long subject is common in real certificates; it must remain readable after resize.
    page._fill_compact_report({"cert": {
        "subject_cn": "测试站点.example.test " * 35,
        "issuer_cn": "测试签发机构", "sig_algorithm": "ML-DSA-65", "pub_algorithm": "ML-DSA-65",
    }})
    for _ in range(4):
        app.processEvents()
    original_height = page.cert_table.rowHeight(page.cert_table.rowCount() - 1)
    page.resize(1100, 720)
    for _ in range(4):
        app.processEvents()
    assert page.cert_table.rowHeight(page.cert_table.rowCount() - 1) > original_height
    assert page.cert_table.geometry().bottom() < page.cert_table.parentWidget().height()
