from __future__ import annotations

import asyncio
import threading
import time
from typing import Dict, List, Optional

import psutil
from scapy.all import IP, TCP, UDP, ICMP, ARP, DNS, sniff

from models import PacketSummary, TrafficStats

PROTOCOL_MAP = {
    6: "TCP",
    17: "UDP",
    1: "ICMP",
    2: "IGMP",
}


def _identify_protocol(packet) -> str:
    if packet.haslayer(DNS):
        return "DNS"
    if packet.haslayer(TCP):
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        if 443 in (sport, dport):
            return "HTTPS"
        if 80 in (sport, dport):
            return "HTTP"
        if 22 in (sport, dport):
            return "SSH"
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(ICMP):
        return "ICMP"
    if packet.haslayer(ARP):
        return "ARP"
    if packet.haslayer(IP):
        proto_num = packet[IP].proto
        return PROTOCOL_MAP.get(proto_num, f"IP/{proto_num}")
    return "Other"


def _build_summary(packet, protocol: str) -> str:
    parts = [protocol]
    if packet.haslayer(TCP):
        flags = packet[TCP].flags
        flag_str = str(flags)
        parts.append(flag_str)
    if packet.haslayer(DNS) and packet[DNS].qr == 0:
        try:
            parts.append(f"query={packet[DNS].qd.qname.decode()}")
        except Exception:
            pass
    return " ".join(parts)


class CaptureEngine:
    def __init__(self):
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=5000)
        self._stats = TrafficStats()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._loop: Optional[asyncio.AbstractEventLoop] = None

        self._window_packets: int = 0
        self._window_bytes: int = 0
        self._window_start: float = 0.0

    def get_interfaces(self) -> List[str]:
        return list(psutil.net_if_addrs().keys())

    def get_stats(self) -> TrafficStats:
        with self._lock:
            return self._stats.model_copy()

    def start(self, interface: str = "en0"):
        if self._running:
            return
        self._running = True
        self._loop = asyncio.get_event_loop()

        with self._lock:
            self._stats = TrafficStats(
                capture_active=True,
                interface=interface,
                start_time=time.time(),
            )

        self._window_packets = 0
        self._window_bytes = 0
        self._window_start = time.time()

        self._thread = threading.Thread(
            target=self._capture_loop,
            args=(interface,),
            daemon=True,
        )
        self._thread.start()

    def stop(self):
        self._running = False
        with self._lock:
            self._stats.capture_active = False

    def _capture_loop(self, interface: str):
        try:
            sniff(
                iface=interface,
                prn=self._process_packet,
                stop_filter=lambda _: not self._running,
                store=False,
            )
        except Exception as e:
            print(f"[NetGaze] Capture error: {e}")
            with self._lock:
                self._stats.capture_active = False
            self._running = False

    def _process_packet(self, packet):
        now = time.time()

        src_ip = packet[IP].src if packet.haslayer(IP) else "N/A"
        dst_ip = packet[IP].dst if packet.haslayer(IP) else "N/A"
        protocol = _identify_protocol(packet)
        size = len(packet)

        src_port: Optional[int] = None
        dst_port: Optional[int] = None
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        summary_text = _build_summary(packet, protocol)

        pkt_summary = PacketSummary(
            timestamp=now,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            src_port=src_port,
            dst_port=dst_port,
            size=size,
            summary=summary_text,
        )

        with self._lock:
            self._stats.total_packets += 1
            self._stats.total_bytes += size
            self._stats.protocol_counts[protocol] = (
                self._stats.protocol_counts.get(protocol, 0) + 1
            )

            self._window_packets += 1
            self._window_bytes += size
            elapsed = now - self._window_start
            if elapsed >= 1.0:
                self._stats.packets_per_sec = self._window_packets / elapsed
                self._stats.bytes_per_sec = self._window_bytes / elapsed
                self._window_packets = 0
                self._window_bytes = 0
                self._window_start = now

        try:
            if self._loop and self._loop.is_running():
                self._loop.call_soon_threadsafe(self._enqueue, pkt_summary)
            else:
                self._queue.put_nowait(pkt_summary)
        except asyncio.QueueFull:
            pass

    def _enqueue(self, pkt: PacketSummary):
        try:
            self._queue.put_nowait(pkt)
        except asyncio.QueueFull:
            pass

    async def get_packet(self) -> Optional[PacketSummary]:
        try:
            return self._queue.get_nowait()
        except asyncio.QueueEmpty:
            return None
