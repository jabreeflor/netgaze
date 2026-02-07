from __future__ import annotations

import asyncio
import struct
import threading
import time
from collections import OrderedDict
from typing import Dict, List, Optional

import psutil
from scapy.all import IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSRR, Raw, sniff

from models import PacketSummary, TrafficStats

PROTOCOL_MAP = {
    6: "TCP",
    17: "UDP",
    1: "ICMP",
    2: "IGMP",
}

DNS_CACHE_MAX = 5000


def _extract_sni(packet) -> Optional[str]:
    """Extract Server Name Indication from TLS ClientHello."""
    if not packet.haslayer(Raw):
        return None
    payload = bytes(packet[Raw].load)
    if len(payload) < 6:
        return None
    # TLS record: content_type=22 (handshake), version, length
    if payload[0] != 22:
        return None
    # Handshake type: 1 = ClientHello
    if len(payload) < 6 or payload[5] != 1:
        return None
    try:
        # Skip TLS record header (5 bytes) + handshake header (4 bytes)
        # + client version (2) + random (32) = offset 43
        offset = 43
        if offset >= len(payload):
            return None
        # Session ID length
        sid_len = payload[offset]
        offset += 1 + sid_len
        if offset + 2 > len(payload):
            return None
        # Cipher suites length
        cs_len = struct.unpack("!H", payload[offset:offset + 2])[0]
        offset += 2 + cs_len
        if offset >= len(payload):
            return None
        # Compression methods length
        cm_len = payload[offset]
        offset += 1 + cm_len
        if offset + 2 > len(payload):
            return None
        # Extensions length
        ext_len = struct.unpack("!H", payload[offset:offset + 2])[0]
        offset += 2
        ext_end = offset + ext_len
        while offset + 4 <= ext_end and offset + 4 <= len(payload):
            ext_type = struct.unpack("!H", payload[offset:offset + 2])[0]
            ext_data_len = struct.unpack("!H", payload[offset + 2:offset + 4])[0]
            offset += 4
            if ext_type == 0:  # SNI extension
                if offset + 5 <= len(payload):
                    # Skip SNI list length (2) + type (1) + name length (2)
                    name_len = struct.unpack("!H", payload[offset + 3:offset + 5])[0]
                    name_start = offset + 5
                    if name_start + name_len <= len(payload):
                        return payload[name_start:name_start + name_len].decode("ascii", errors="ignore")
                return None
            offset += ext_data_len
    except Exception:
        pass
    return None


def _extract_dns_domain(packet) -> Optional[str]:
    """Extract domain from DNS query."""
    if not packet.haslayer(DNS):
        return None
    dns = packet[DNS]
    if dns.qr == 0 and dns.qd:  # Query
        try:
            name = dns.qd.qname.decode("utf-8", errors="ignore").rstrip(".")
            return name
        except Exception:
            pass
    return None


def _extract_dns_responses(packet) -> Dict[str, str]:
    """Extract IP->domain mappings from DNS responses."""
    mappings = {}
    if not packet.haslayer(DNS):
        return mappings
    dns = packet[DNS]
    if dns.qr != 1 or not dns.qd:
        return mappings
    try:
        domain = dns.qd.qname.decode("utf-8", errors="ignore").rstrip(".")
        # Walk answer records
        for i in range(dns.ancount):
            rr = dns.an[i] if dns.ancount > 1 else dns.an
            if hasattr(rr, "rdata") and isinstance(rr, DNSRR):
                rdata = rr.rdata
                if isinstance(rdata, bytes):
                    rdata = rdata.decode("utf-8", errors="ignore")
                if isinstance(rdata, str) and rdata.count(".") >= 1:
                    mappings[rdata] = domain
            if dns.ancount == 1:
                break
    except Exception:
        pass
    return mappings


def _get_ips(packet):
    """Extract src/dst IPs supporting both IPv4 and IPv6."""
    if packet.haslayer(IP):
        return packet[IP].src, packet[IP].dst
    if packet.haslayer(IPv6):
        return packet[IPv6].src, packet[IPv6].dst
    return "N/A", "N/A"


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


def _build_summary(packet, protocol: str, domain: Optional[str]) -> str:
    parts = [protocol]
    if domain:
        parts.append(domain)
    if packet.haslayer(TCP):
        flags = packet[TCP].flags
        flag_str = str(flags)
        parts.append(flag_str)
    if packet.haslayer(DNS) and packet[DNS].qr == 0:
        try:
            qname = packet[DNS].qd.qname.decode().rstrip(".")
            parts.append(f"query={qname}")
        except Exception:
            pass
    elif packet.haslayer(DNS) and packet[DNS].qr == 1:
        try:
            qname = packet[DNS].qd.qname.decode().rstrip(".")
            parts.append(f"response={qname}")
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
        self._dns_cache: OrderedDict = OrderedDict()

        self._window_packets: int = 0
        self._window_bytes: int = 0
        self._window_start: float = 0.0

    def set_loop(self, loop: asyncio.AbstractEventLoop):
        self._loop = loop

    def get_interfaces(self) -> List[str]:
        return list(psutil.net_if_addrs().keys())

    def get_stats(self) -> TrafficStats:
        with self._lock:
            return self._stats.model_copy()

    def start(self, interface: str = "en0"):
        if self._running:
            return
        self._running = True
        self._dns_cache.clear()

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

    def _dns_cache_put(self, ip: str, domain: str):
        self._dns_cache[ip] = domain
        if len(self._dns_cache) > DNS_CACHE_MAX:
            self._dns_cache.popitem(last=False)

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

        src_ip, dst_ip = _get_ips(packet)
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

        # Domain resolution
        domain: Optional[str] = None

        # 1. DNS query - extract queried domain
        dns_domain = _extract_dns_domain(packet)
        if dns_domain:
            domain = dns_domain

        # 2. DNS response - cache IP->domain mappings
        dns_mappings = _extract_dns_responses(packet)
        for ip, dom in dns_mappings.items():
            self._dns_cache_put(ip, dom)
        if dns_mappings and not domain:
            domain = next(iter(dns_mappings.values()))

        # 3. TLS SNI - extract from ClientHello
        if not domain and packet.haslayer(TCP):
            sni = _extract_sni(packet)
            if sni:
                domain = sni
                # Also cache it for this destination IP
                if dst_ip != "N/A":
                    self._dns_cache_put(dst_ip, sni)

        # 4. Fallback: look up in DNS cache
        if not domain:
            if dst_ip in self._dns_cache:
                domain = self._dns_cache[dst_ip]
            elif src_ip in self._dns_cache:
                domain = self._dns_cache[src_ip]

        summary_text = _build_summary(packet, protocol, domain)

        pkt_summary = PacketSummary(
            timestamp=now,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            src_port=src_port,
            dst_port=dst_port,
            size=size,
            summary=summary_text,
            domain=domain,
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
