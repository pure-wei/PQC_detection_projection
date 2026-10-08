"""Exercise the desktop entry and real laboratory process lifecycle."""
import importlib
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.request import urlopen

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QApplication

from main import MainWindow
from pqc_lab import lab


def wait_for(app, predicate, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        app.processEvents()
        if predicate():
            return
        time.sleep(.01)
    assert predicate(), "实验站界面操作超时"


def free_port():
    with socket.socket() as connection:
        connection.bind(("127.0.0.1", 0))
        return connection.getsockname()[1]


def test_openssl_discovery_includes_user_conda_environments(tmp_path, monkeypatch):
    home = tmp_path / "home"
    prefix = tmp_path / "python"
    expected = home / ".conda/envs/code/Library/bin/openssl.exe"
    expected.parent.mkdir(parents=True)
    expected.write_text("placeholder")
    monkeypatch.setenv("PQC_OPENSSL", "")
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.setattr(sys, "prefix", str(prefix))
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    monkeypatch.setattr(lab.pqc_detect, "find_openssl", lambda: "")
    candidates = lab.openssl_candidates()
    assert str(expected.resolve()) in candidates


def lab_page(tmp_path, **kwargs):
    module = importlib.import_module("modules.pqc_lab_ui")
    return module.PqcLabTab(base=tmp_path, **kwargs)


def test_homepage_entry_opens_local_lab_without_starting_it():
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    try:
        tabs = window.centralWidget()
        entry = getattr(tabs.widget(0), "btn_lab", None)
        assert entry is not None, "后量子检测首页需要明显的本地实验站入口"
        entry.click()
        app.processEvents()
        page = tabs.currentWidget()
        assert tabs.currentIndex() == 1
        assert tabs.tabText(1) == "② 本地后量子实验站"
        assert not page.is_busy()
        assert "启动" in page.btn_start.text() and "网页" in page.btn_open.text()
        tabs.setCurrentIndex(0)
        action = next(action for action in window.menuBar().actions()
                      if action.text() == "本地后量子实验站")
        action.trigger()
        app.processEvents()
        assert tabs.currentIndex() == 1
        assert tabs.currentWidget() is page
    finally:
        window.close()


def evidence():
    # This UI fixture is deliberately not a real handshake measurement.
    return {"status": "passed", "generated_at": "2026-10-07T19:00:00+08:00",
            "target": "127.0.0.1:9443", "openssl_version": "OpenSSL 3.6.5",
            "summary": {"group_name": "X25519MLKEM768", "protocol": "TLSv1.3",
                        "certificate_algorithm": "ML-DSA-65", "chain_certificates": 2,
                        "finished_verified": True, "certificate_verify_verified": True},
            "checks": [{"id": "fixture", "label": "显示逻辑测试", "passed": True, "detail": "UI fixture"}]}


@pytest.mark.parametrize("protocol,signature,classic", [
    ("https", "ML-DSA-87", ""),
    ("tcp", "Falcon-512", "ECDSA-P256"),
    ("udp", "SLH-DSA-SHA2-256f", ""),
])
def test_new_modes_have_real_gui_lifecycle(tmp_path, pqc_openssl, monkeypatch, protocol, signature, classic):
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr(QDesktopServices, "openUrl", lambda *_args: True)
    page = lab_page(tmp_path, openssl=pqc_openssl)
    page.protocol_combo.setCurrentIndex(page.protocol_combo.findData(protocol))
    page.signature_combo.setCurrentText(signature)
    if protocol == "https":
        page.group_combo.setCurrentText("SecP384r1MLKEM1024")
    page.hybrid_check.setChecked(bool(classic))
    if classic:
        page.classical_combo.setCurrentText(classic)
    page.message_edit.setText("来自图形界面的实际消息")
    page.tls_port.setValue(free_port())
    page.http_port.setValue(free_port())
    while page.tls_port.value() == page.http_port.value():
        page.http_port.setValue(free_port())
    try:
        page.btn_start.click()
        wait_for(app, lambda: page.btn_verify.isEnabled() and page._report_state == "passed", timeout=30)
        assert not page.protocol_combo.isEnabled()
        assert signature in page.cert_value.text()
        if protocol != "https":
            assert "明文" in page.group_value.text()
            assert "验签" in page.handshake_value.text()
            assert page.tls_address.text() == protocol + "://127.0.0.1:" + str(page.tls_port.value())
        report = json.loads((tmp_path / "public/evidence.json").read_text())
        assert report["profile"]["protocol"] == protocol
        assert report["profile"]["signature"] == signature
        previous = report["generated_at"]
        stamp = (tmp_path / "public/evidence.json").stat().st_mtime_ns
        page.btn_verify.click()
        wait_for(app, lambda: page.btn_verify.isEnabled() and
                 (tmp_path / "public/evidence.json").stat().st_mtime_ns != stamp, timeout=30)
        assert page._report_state == "passed"
        assert json.loads((tmp_path / "public/evidence.json").read_text())["profile"] == report["profile"]
        page.btn_stop.click()
        wait_for(app, lambda: not page.is_busy(), timeout=30)
        assert page.protocol_combo.isEnabled()
    finally:
        page.request_shutdown()
        wait_for(app, lambda: not page.is_busy(), timeout=30)
        page.close()


def test_changing_mode_does_not_reuse_old_success(tmp_path):
    app = QApplication.instance() or QApplication([])
    public = tmp_path / "public"
    public.mkdir()
    (public / "evidence.json").write_text(json.dumps(evidence()))
    page = lab_page(tmp_path)
    try:
        assert page._report_state == "passed"
        page.protocol_combo.setCurrentIndex(page.protocol_combo.findData("udp"))
        page.reload_evidence()
        assert page._report_state != "passed"
        assert page.signature_combo.findText("Falcon-512") >= 0
        page.protocol_combo.setCurrentIndex(page.protocol_combo.findData("https"))
        assert page.signature_combo.findText("Falcon-512") < 0
        assert not page.hybrid_check.isEnabled()
    finally:
        page.close()


def test_external_tls_retest_uses_managers_openssl(tmp_path, pqc_openssl):
    app = QApplication.instance() or QApplication([])
    port, http_port = free_port(), free_port()
    while port == http_port:
        http_port = free_port()
    command = [sys.executable, str(lab.HERE / "lab.py")]
    with (tmp_path / "external.log").open("wb") as log:
        process = subprocess.Popen(command + ["serve", "--base", str(tmp_path), "--openssl", pqc_openssl,
            "--port", str(port), "--http-port", str(http_port)], stdout=log, stderr=log)
        page = None
        try:
            report = tmp_path / "public/evidence.json"
            wait_for(app, lambda: report.exists() and json.loads(report.read_text())["status"] == "passed")
            page = lab_page(tmp_path, openssl="/unavailable/openssl")
            assert page.openssl_edit.text() == pqc_openssl
            stamp = report.stat().st_mtime_ns
            page.btn_verify.click()
            wait_for(app, lambda: page._command.state() == page._command.ProcessState.NotRunning
                     and report.stat().st_mtime_ns != stamp)
            assert page._report_state == "passed"
            assert process.poll() is None
            page.close()
            assert process.poll() is None, "关闭非所有者页面不能停止外部服务"
        finally:
            if page:
                page.close()
            subprocess.run(command + ["stop", "--base", str(tmp_path)], capture_output=True, timeout=10)
            process.wait(timeout=10)


def test_reopening_restores_saved_message_mode(tmp_path):
    app = QApplication.instance() or QApplication([])
    public = tmp_path / "public"
    public.mkdir()
    data = {"status": "passed", "generated_at": "2026-10-07T19:00:00+08:00", "target": "127.0.0.1:9555",
        "profile": {"protocol": "udp", "group": "X25519MLKEM768", "signature": "Falcon-512",
                    "classical_signature": ""},
        "checks": [{"id": name, "label": name, "detail": "UI fixture", "passed": True}
                   for name in ("message_exchange", "message_signature", "reject_replay")],
        "summary": {"protocol": "UDP", "signature_algorithm": "Falcon-512",
                    "message_signature_verified": True, "pq_signature_verified": True,
                    "transport_confidentiality": False}}
    (public / "evidence.json").write_text(json.dumps(data))
    page = lab_page(tmp_path)
    try:
        assert page.protocol_combo.currentData() == "udp"
        assert page.signature_combo.currentText() == "Falcon-512"
        assert page._report_state == "passed"
        page.protocol_combo.setCurrentIndex(page.protocol_combo.findData("https"))
        page.reload_evidence()
        assert page._report_state != "passed"
    finally:
        page.close()


@pytest.mark.parametrize("fault", [None, "finished", "checks", "target", "timestamp", "invalid_json"])
def test_saved_report_is_displayed_and_inconsistent_success_is_rejected(tmp_path, fault):
    app = QApplication.instance() or QApplication([])
    public = tmp_path / "public"
    public.mkdir()
    data = evidence()
    if fault == "finished":
        data["summary"]["finished_verified"] = False
    elif fault == "checks":
        data["checks"] = []
    elif fault == "target":
        data["target"] = "example.com:9443"
    elif fault == "timestamp":
        data["generated_at"] = "invalid"
    (public / "evidence.json").write_text("{" if fault == "invalid_json" else json.dumps(data))
    page = lab_page(tmp_path)
    try:
        page.reload_evidence()
        if fault is None:
            assert "实测通过" in page.report_status.text()
            assert "X25519MLKEM768" in page.group_value.text()
            assert "ML-DSA-65" in page.cert_value.text()
            assert page.checks_table.rowCount() == 1
            assert "9443" in page.report_target.text()
            assert "2026" in page.report_time.text()
        else:
            assert "实测通过" not in page.report_status.text()
    finally:
        page.close()
        app.processEvents()


def test_same_http_and_tls_port_is_rejected_before_process_start(tmp_path):
    app = QApplication.instance() or QApplication([])
    page = lab_page(tmp_path)
    try:
        page.http_port.setValue(8443)
        page.tls_port.setValue(8443)
        page.btn_start.click()
        app.processEvents()
        assert not page.is_busy()
        assert "不同" in page.service_status.text()
        assert not (tmp_path / ".runtime/service.json").exists()
    finally:
        page.close()


def test_occupied_port_is_rejected_before_process_start(tmp_path):
    app = QApplication.instance() or QApplication([])
    page = lab_page(tmp_path)
    with socket.socket() as occupied:
        occupied.bind(("127.0.0.1", 0))
        occupied.listen(1)
        port = occupied.getsockname()[1]
        page.tls_port.setValue(port)
        page.http_port.setValue(free_port())
        try:
            page.btn_start.click()
            app.processEvents()
            assert not page.is_busy()
            assert str(port) in page.service_status.text() and "占用" in page.service_status.text()
            assert not (tmp_path / ".runtime/service.json").exists()
        finally:
            page.close()
            app.processEvents()


def test_stale_runtime_record_does_not_prevent_restart(tmp_path):
    app = QApplication.instance() or QApplication([])
    runtime = tmp_path / ".runtime"
    runtime.mkdir()
    (runtime / "service.json").write_text(json.dumps({"pid": 99999999, "port": 8443, "http_port": 8080, "token": "stale"}))
    page = lab_page(tmp_path)
    try:
        assert page.btn_start.isEnabled()
        assert not page.btn_open.isEnabled()
        assert not page.btn_stop.isEnabled()
        assert (runtime / "service.json").exists(), "不要在仅检查状态时删除原记录"
    finally:
        page.close()
        app.processEvents()


def test_refresh_after_report_is_deleted_clears_success(tmp_path):
    app = QApplication.instance() or QApplication([])
    public = tmp_path / "public"
    public.mkdir()
    report = public / "evidence.json"
    report.write_text(json.dumps(evidence()))
    page = lab_page(tmp_path)
    try:
        assert "实测通过" in page.report_status.text()
        report.unlink()
        page.reload_evidence()
        assert "实测通过" not in page.report_status.text()
        assert page.checks_table.rowCount() == 0
        assert page.group_value.text() == "等待实测"
    finally:
        page.close()
        app.processEvents()


def test_shutdown_does_not_stop_external_service_that_wins_start_race(tmp_path, pqc_openssl, monkeypatch):
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr(QDesktopServices, "openUrl", lambda url: True)
    release = tmp_path / "release-owned-start"
    wrapper = tmp_path / "delayed-lab.py"
    wrapper.write_text("import time, runpy\nfrom pathlib import Path\n"
                       "for _ in range(1500):\n"
                       "    if Path(%r).exists(): break\n    time.sleep(.01)\n"
                       "runpy.run_path(%r, run_name='__main__')\n" % (str(release), lab.__file__))
    page = lab_page(tmp_path, openssl=pqc_openssl)
    original_args = page._args
    def delayed_args(action):
        args = original_args(action)
        if action == "serve":
            args[1] = str(wrapper)
        return args
    monkeypatch.setattr(page, "_args", delayed_args)
    tls_port, http_port = free_port(), free_port()
    while tls_port == http_port:
        http_port = free_port()
    page.tls_port.setValue(tls_port)
    page.http_port.setValue(http_port)
    external = None
    try:
        page.btn_start.click()
        wait_for(app, lambda: page._service.processId() > 0)
        external = subprocess.Popen([sys.executable, lab.__file__, "serve", "--base", str(tmp_path),
            "--openssl", pqc_openssl, "--port", str(tls_port), "--http-port", str(http_port)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        state_file = tmp_path / ".runtime/service.json"
        wait_for(app, lambda: state_file.exists() and json.loads(state_file.read_text())["pid"] == external.pid)
        page.request_shutdown()
        end = time.monotonic() + .8
        while time.monotonic() < end:
            app.processEvents()
            time.sleep(.01)
        assert external.poll() is None, "自动关闭不得停止其他入口获得的服务"
        assert state_file.exists() and json.loads(state_file.read_text())["pid"] == external.pid
        release.touch()
        wait_for(app, lambda: not page.is_busy())
        assert external.poll() is None
    finally:
        release.touch()
        if external is not None and external.poll() is None:
            subprocess.run([sys.executable, lab.__file__, "stop", "--base", str(tmp_path)], timeout=10, capture_output=True)
            external.wait(timeout=10)
        page.request_shutdown()
        wait_for(app, lambda: not page.is_busy())
        page.close()


def test_start_open_verify_and_stop_use_real_pqc_service(tmp_path, pqc_openssl, monkeypatch):
    app = QApplication.instance() or QApplication([])
    opened = []
    monkeypatch.setattr(QDesktopServices, "openUrl", lambda url: opened.append(url.toString()) or True)
    page = lab_page(tmp_path, openssl=pqc_openssl)
    tls_port, http_port = free_port(), free_port()
    while tls_port == http_port:
        http_port = free_port()
    page.tls_port.setValue(tls_port)
    page.http_port.setValue(http_port)
    try:
        page.btn_start.click()
        wait_for(app, lambda: "实测通过" in page.report_status.text() and bool(opened))
        address = "http://127.0.0.1:%d/index.html" % http_port
        assert opened == [address]
        with urlopen(address, timeout=2) as response:
            assert response.status == 200 and "双层抗量子 HTTPS" in response.read().decode()
        assert page.checks_table.rowCount() == 11
        assert "ML-DSA-65" in page.cert_value.text()
        assert "X25519MLKEM768" in page.group_value.text()
        assert str(tls_port) in page.tls_address.text()
        assert str(http_port) in page.http_address.text()
        assert page.btn_verify.isEnabled()
        old = (tmp_path / "public/evidence.json").stat().st_mtime_ns
        page.btn_verify.click()
        wait_for(app, lambda: page.btn_verify.isEnabled() and (tmp_path / "public/evidence.json").stat().st_mtime_ns > old)
        assert "实测通过" in page.report_status.text()
        page.btn_stop.click()
        wait_for(app, lambda: not page.is_busy() and not (tmp_path / ".runtime/service.json").exists())
        assert "停止" in page.service_status.text()
        assert not page.btn_open.isEnabled()
        assert not page.btn_verify.isEnabled()
    finally:
        page.request_shutdown()
        wait_for(app, lambda: not page.is_busy())
        page.close()


def test_closing_main_window_stops_its_real_lab(tmp_path, pqc_openssl, monkeypatch):
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr(QDesktopServices, "openUrl", lambda url: True)
    window = MainWindow(pqc_lab_base=tmp_path)
    page = window._pqc_lab_tab
    page.openssl_edit.setText(pqc_openssl)
    tls_port, http_port = free_port(), free_port()
    while tls_port == http_port:
        http_port = free_port()
    page.tls_port.setValue(tls_port)
    page.http_port.setValue(http_port)
    window.show()
    try:
        page.btn_start.click()
        wait_for(app, lambda: "实测通过" in page.report_status.text())
        window.close()
        wait_for(app, lambda: not window.isVisible() and not page.is_busy())
        assert not (tmp_path / ".runtime/service.json").exists()
        with pytest.raises(OSError):
            socket.create_connection(("127.0.0.1", tls_port), timeout=.2)
    finally:
        page.request_shutdown()
        wait_for(app, lambda: not page.is_busy())
        window.close()
