"""Capture lifecycle around scapy's interface-facing sniffer."""

import threading
from types import SimpleNamespace

import pytest
from scapy.all import IP, TCP, rdpcap
from scapy.error import Scapy_Exception

from modules import live_capture


class FakeSniffer:
    def __init__(self, **kwargs):
        self.options = kwargs
        self.results = [IP(src="192.0.2.1", dst="192.0.2.2") / TCP(dport=443)]
        self.running = True
        self.thread = SimpleNamespace(is_alive=lambda: self.running)
        self.stopped = False

    def start(self):
        pass

    def stop(self):
        self.stopped = True
        self.running = False

    def join(self, timeout=None):
        pass


def test_stop_writes_captured_packets_and_preserves_filter(tmp_path, monkeypatch):
    instances = []

    def make_sniffer(**kwargs):
        sniffer = FakeSniffer(**kwargs)
        instances.append(sniffer)
        return sniffer

    monkeypatch.setattr(live_capture, "AsyncSniffer", make_sniffer)
    path = tmp_path / "capture.pcap"
    stop = threading.Event()
    stop.set()

    count = live_capture.capture_packets("lo", "tcp port 443", 30, str(path), stop)

    assert count == 1
    assert instances[0].options["iface"] == "lo"
    assert instances[0].options["filter"] == "tcp port 443"
    assert instances[0].stopped
    assert len(rdpcap(str(path))) == 1


def test_empty_capture_reports_no_packets_without_writing_file(tmp_path, monkeypatch):
    class EmptySniffer(FakeSniffer):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self.results = []

    monkeypatch.setattr(live_capture, "AsyncSniffer", EmptySniffer)
    path = tmp_path / "empty.pcap"
    stop = threading.Event()
    stop.set()

    with pytest.raises(ValueError, match="没有捕获"):
        live_capture.capture_packets("lo", "tcp", 10, str(path), stop)
    assert not path.exists()


def test_capture_saves_when_packet_limit_ends_sniffer(tmp_path, monkeypatch):
    class FinishedSniffer(FakeSniffer):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self.running = False

    monkeypatch.setattr(live_capture, "AsyncSniffer", FinishedSniffer)
    path = tmp_path / "limit.pcap"
    count = live_capture.capture_packets("lo", "tcp", 10, str(path),
                                         threading.Event(), max_packets=1)
    assert count == 1
    assert len(rdpcap(str(path))) == 1


def test_stop_race_still_saves_already_captured_packets(tmp_path, monkeypatch):
    class StoppedDuringStop(FakeSniffer):
        def stop(self):
            self.running = False
            raise Scapy_Exception("Not running !")

    monkeypatch.setattr(live_capture, "AsyncSniffer", StoppedDuringStop)
    path = tmp_path / "race.pcap"
    stop = threading.Event()
    stop.set()
    assert live_capture.capture_packets("lo", "tcp", 10, str(path), stop) == 1
    assert len(rdpcap(str(path))) == 1
