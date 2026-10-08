# -*- coding: utf-8 -*-
"""Bounded, stoppable live packet capture saved for existing pcap analysis."""

import threading

from scapy.all import AsyncSniffer, wrpcap
from scapy.error import Scapy_Exception


def capture_packets(interface: str, bpf_filter: str, duration: int, path: str,
                    stop_event: threading.Event, max_packets: int = 10000) -> int:
    """Capture until time, packet cap or user stop, then write a pcap file."""
    if not interface:
        raise ValueError("请选择抓包网卡")
    if not path:
        raise ValueError("请选择抓包保存路径")
    if not 1 <= duration <= 300:
        raise ValueError("抓包时长必须为 1–300 秒")
    if not 1 <= max_packets <= 50000:
        raise ValueError("最大包数必须为 1–50000")
    sniffer = AsyncSniffer(iface=interface, filter=bpf_filter or None,
                           timeout=duration, count=max_packets, store=True)
    sniffer.start()
    while sniffer.thread and sniffer.thread.is_alive():
        if stop_event.wait(0.1) and sniffer.running:
            try:
                sniffer.stop()
            except AttributeError:  # startup has not installed stop_cb yet
                continue
            except Scapy_Exception:
                if sniffer.running:
                    raise
            break
    sniffer.join()
    packets = sniffer.results or []
    if not packets:
        raise ValueError("没有捕获到数据包；请检查网卡、过滤条件或抓包权限")
    wrpcap(path, packets)
    return len(packets)
