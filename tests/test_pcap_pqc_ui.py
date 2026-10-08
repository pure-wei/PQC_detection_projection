"""Offscreen checks for capture and the two independent PQC evidence paths."""

import os
import json
import threading
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication
from scapy.all import IP, TCP, wrpcap

from main import MainWindow, PcapTab
from modules import pqc_detect


def _wait_for(app, predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        app.processEvents()
        if predicate():
            return
        time.sleep(0.01)
    assert predicate(), "操作超时"


def _captured_flow():
    return {
        "proto": "TLS", "client": "10.0.0.2:52000", "server": "198.51.100.10:443",
        "messages": [
            {"type": "ClientHello", "fields": {"SNI": "example.test"}},
            {"type": "ServerHello", "fields": {
                "selected_group_id": 0x11EC, "key_share_bytes": 1120,
                "key_share_length_valid": True, "ext_supported_versions": "TLS 1.3"}},
        ],
    }


def test_protocol_analysis_follows_local_lab():
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    tabs = window.centralWidget()
    assert isinstance(tabs.widget(2), PcapTab)
    assert tabs.tabText(2) == "③ 协议分析与抓包"
    assert tabs.tabText(3) == "④ 后量子算法演示"
    window.close()


def test_selected_capture_and_active_probe_keep_separate_results(monkeypatch):
    app = QApplication.instance() or QApplication([])
    tab = PcapTab()
    tab._streams = {("10.0.0.2", 52000, "198.51.100.10", 443): _captured_flow()}
    tab._populate_pqc_sessions()

    assert tab.pqc_flow_combo.count() == 1
    assert "X25519MLKEM768" in tab.passive_evidence.text()
    assert "无法观察" in tab.passive_evidence.text()
    assert "未主动复测" in tab.active_evidence.text()

    called = []

    def fake_detect(host, port, **kwargs):
        called.append((host, port, kwargs["mode"]))
        return {"overall": "主动复测：部分后量子", "overall_state": "partial",
                "transport": {"group_name": "X25519MLKEM768", "verified": True},
                "cert": {"sig_algorithm": "RSA", "pub_algorithm": "RSA"}}

    monkeypatch.setattr(pqc_detect, "detect", fake_detect)
    tab.btn_probe.click()
    _wait_for(app, lambda: tab.btn_probe.isEnabled())

    assert called == [("example.test", 443, "deep")]
    assert "另一次连接" in tab.active_evidence.text()
    assert "部分后量子" in tab.active_evidence.text()
    assert "X25519MLKEM768" in tab.passive_evidence.text()
    tab.close()


def test_failed_active_probe_does_not_claim_handshake_or_certificate():
    text = PcapTab._active_report_text({"overall": "检测失败", "error": "超时"})
    assert "未取得握手证据" in text
    assert "证书层未取得" in text


def test_exported_pqc_report_keeps_passive_and_active_as_separate_sessions(tmp_path, monkeypatch):
    app = QApplication.instance() or QApplication([])
    tab = PcapTab()
    key = ("10.0.0.2", 52000, "198.51.100.10", 443)
    tab._streams = {key: _captured_flow()}
    tab._populate_pqc_sessions()
    tab._active_reports[key] = {"host": "example.test", "port": 443,
                                "overall": "主动探测结果", "transport": {"group_name": "X25519MLKEM768"}}
    path = tmp_path / "pqc_evidence.json"
    monkeypatch.setattr("main.QFileDialog.getSaveFileName",
                        lambda *args, **kwargs: (str(path), "JSON"))
    tab.btn_export_pqc.click()

    report = json.loads(path.read_text(encoding="utf-8"))
    assert len(report["sessions"]) == 1
    session = report["sessions"][0]
    assert session["passive_observation"]["state"] == "pqc_observed"
    assert session["active_probe"]["overall"] == "主动探测结果"
    assert "另一次连接" in report["note"]
    tab.close()


def test_live_capture_saves_and_opens_pcap(tmp_path, monkeypatch):
    app = QApplication.instance() or QApplication([])
    tab = PcapTab()
    path = tmp_path / "live.pcap"

    def fake_capture(interface, bpf_filter, duration, output, stop_event, max_packets=10000):
        wrpcap(output, [IP(src="192.0.2.1", dst="192.0.2.2") / TCP(dport=443)])
        return 1

    monkeypatch.setattr("main.live_capture.capture_packets", fake_capture)
    monkeypatch.setattr("main.QFileDialog.getSaveFileName",
                        lambda *args, **kwargs: (str(path), "pcap"))
    tab.btn_capture.click()
    _wait_for(app, lambda: tab.btn_capture.isEnabled() and path.exists())

    assert tab.path_label.text() == str(path)
    assert len(tab._pkts) == 1
    assert not tab.btn_stop_capture.isEnabled()
    tab.close()


def test_closing_window_requests_capture_stop_before_destroying_thread():
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    tab = window._pcap_tab

    class RunningCapture:
        stop_event = threading.Event()

        def isRunning(self):
            return True

    fake = RunningCapture()
    tab._capture_worker = fake
    assert window.close() is False
    assert fake.stop_event.is_set()
    tab._capture_worker = None
    window.close()


def test_closing_window_requests_active_probe_cancel():
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    tab = window._pcap_tab

    class RunningProbe:
        cancel_event = threading.Event()

        def isRunning(self):
            return True

    fake = RunningProbe()
    tab._probe_worker = fake
    assert window.close() is False
    assert fake.cancel_event.is_set()
    tab._probe_worker = None
    window.close()


def test_canceled_probe_does_not_open_network_connection(monkeypatch):
    stop = threading.Event()
    stop.set()

    def forbidden(*args, **kwargs):
        raise AssertionError("已取消的探测不应发起网络连接")

    monkeypatch.setattr(pqc_detect, "deep_verify", forbidden)
    report = pqc_detect.detect("example.test", cancel_event=stop)
    assert report["overall_state"] == "unknown"
    assert "已取消" in report["overall"]
