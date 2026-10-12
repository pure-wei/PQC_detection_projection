"""Actual fourth-page flow, stale-result clearing, and worker shutdown."""
import importlib
import json
import os
import threading
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication
from scapy.all import IP, TCP, Raw

from main import MainWindow
from test_pqc_recheck import wire_fixture, session_and_parameters, engine


def wait_for(app, predicate, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        app.processEvents()
        if predicate():
            return
        time.sleep(.01)
    assert predicate(), "复核界面操作超时"


def make_page(sessions):
    module = importlib.import_module("modules.pqc_recheck_ui")
    return module.PqcRecheckTab(session_provider=lambda: sessions)


def test_session_runs_real_recheck_and_input_changes_invalidate_results():
    app = QApplication.instance() or QApplication([])
    fixture = wire_fixture()
    session, parameters = session_and_parameters(fixture)
    session["_secrets"] = parameters
    other = engine().session_from_streams(b"", b"", label="另一抓包会话")
    page = make_page([session, other])
    try:
        page.refresh_sessions()
        assert page.session_combo.count() == 2
        assert fixture["parameters"]["kem_private_key"] in page.secret_edit.toPlainText()
        page.btn_run.click()
        wait_for(app, lambda: page._worker is None and page._result is not None)
        assert page._result["records"]["status"] == "passed"
        assert fixture["plain"].decode().replace("\r\n", "\n") in page.output.toPlainText()
        assert page.trace_views["exchange"].tree.topLevelItemCount() > 1
        page.keylog_edit.setPlainText(fixture["keylog"])
        assert page._result is None
        page.session_combo.setCurrentIndex(1)
        assert page._result is None
        assert fixture["parameters"]["kem_private_key"] not in page.secret_edit.toPlainText()
        assert not page.keylog_edit.toPlainText()
        page.btn_run.click()
        wait_for(app, lambda: page._worker is None and page._result is not None)
        assert page._result["records"]["status"] == "missing"
        assert "缺少" in page.output.toPlainText()
    finally:
        page.close()


def test_main_window_exposes_detection_and_original_capture_as_separate_sessions(tmp_path, monkeypatch):
    app = QApplication.instance() or QApplication([])
    fixture = wire_fixture()
    window = MainWindow(pqc_lab_base=tmp_path)
    try:
        tabs = window.centralWidget()
        detector = tabs.widget(0)
        report = {"host": "original.test", "port": 443, "started_at": "test", "deep": {
            "trace": [{"dir": "→", "raw": fixture["client"]}, {"dir": "←", "raw": fixture["server"]}],
            "_recheck_secrets": fixture["parameters"]}}
        monkeypatch.setattr(detector, "_detail_file_path", lambda _report: str(tmp_path / "details.txt"))
        detector._on_done(report)
        pkts = [IP(src="10.0.0.2", dst="10.0.0.3") / TCP(sport=52000, dport=443, seq=1) / Raw(fixture["client"]),
                IP(src="10.0.0.3", dst="10.0.0.2") / TCP(sport=443, dport=52000, seq=1) / Raw(fixture["server"])]
        from modules.tls_parser import analyze_flows
        capture = tabs.widget(2)
        capture._streams = analyze_flows(pkts)["flows"]
        capture._populate_pqc_sessions()
        page = tabs.widget(3)
        assert type(page).__name__ == "PqcRecheckTab"
        page.refresh_sessions()
        assert page.session_combo.count() == 2
        assert page._sessions[0].get("_secrets")
        assert not page._sessions[1].get("_secrets")
        assert page._sessions[1]["server_records"]
        assert "kem_private_key" not in (tmp_path / "details.txt").read_text(encoding="utf-8")
    finally:
        window.close()
        app.processEvents()


def test_imported_public_capture_can_use_matching_keylog(tmp_path):
    app = QApplication.instance() or QApplication([])
    fixture = wire_fixture()
    session, _ = session_and_parameters(fixture)
    path = tmp_path / "report.json"
    path.write_text(json.dumps({"recheck_session": engine().public_session(session)}))
    keylog = tmp_path / "keys.log"
    keylog.write_text(fixture["keylog"])
    page = make_page([])
    try:
        page.import_report(path)
        page.import_keylog(keylog)
        page.btn_run.click()
        wait_for(app, lambda: page._worker is None and page._result is not None)
        assert page._result["exchange"]["status"] == "missing"
        assert page._result["signature"]["status"] == "passed"
        assert page._result["records"]["status"] == "passed"
    finally:
        page.close()


def test_refresh_preserves_supplied_secrets_for_the_same_capture_without_selecting_detection():
    app = QApplication.instance() or QApplication([])
    fixture = wire_fixture()
    session, parameters = session_and_parameters(fixture)
    session["_secrets"] = parameters
    capture = engine().public_session(session)
    capture["label"] = "同一连接的抓包来源"
    page = make_page([session, capture])
    try:
        page.session_combo.setCurrentIndex(1)
        page.keylog_edit.setPlainText(fixture["keylog"])
        page.refresh_sessions()
        assert page.session_combo.currentIndex() == 1
        assert not page._selected().get("_secrets")
        assert page.keylog_edit.toPlainText() == fixture["keylog"]
    finally:
        page.close()


def test_main_window_waits_for_recheck_worker_before_closing(tmp_path, monkeypatch):
    app = QApplication.instance() or QApplication([])
    fixture = wire_fixture()
    session, parameters = session_and_parameters(fixture)
    session["_secrets"] = parameters
    module = importlib.import_module("modules.pqc_recheck_ui")
    real_recheck = module.pqc_recheck.recheck
    started, release = threading.Event(), threading.Event()

    def delayed(*args, **kwargs):
        started.set()
        assert release.wait(5)
        return real_recheck(*args, **kwargs)

    monkeypatch.setattr(module.pqc_recheck, "recheck", delayed)
    window = MainWindow(pqc_lab_base=tmp_path)
    page = window.centralWidget().widget(3)
    page._session_provider = lambda: [session]
    page.refresh_sessions()
    window.show()
    try:
        page.btn_run.click()
        wait_for(app, started.is_set)
        assert window.close() is False
        assert window.isVisible()
        release.set()
        wait_for(app, lambda: not window.isVisible())
        assert page._worker is None
    finally:
        release.set()
        if page._worker:
            page._worker.wait(5000)
        window.close()
