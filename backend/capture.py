from __future__ import annotations

import asyncio
import ipaddress
import struct
import threading
import time
from collections import Counter, OrderedDict
from typing import Dict, List, Optional, Set

import psutil
from scapy.all import IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSRR, Raw, sniff

from models import PacketHeader, PacketSummary, TrafficStats

PROTOCOL_MAP = {
    6: "TCP",
    17: "UDP",
    1: "ICMP",
    2: "IGMP",
}

DNS_CACHE_MAX = 5000
MAX_PAYLOAD_BYTES = 4096
BANDWIDTH_HISTORY_MAX = 60
TOP_N = 10

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


def _is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is in a private range."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


def _get_direction(src_ip: str, dst_ip: str) -> str:
    """Determine packet direction based on IP addresses."""
    src_private = _is_private_ip(src_ip)
    dst_private = _is_private_ip(dst_ip)
    if src_private and dst_private:
        return "local"
    if src_private:
        return "outbound"
    if dst_private:
        return "inbound"
    return "outbound"


_TCP_FLAG_NAMES = {
    "F": "FIN",
    "S": "SYN",
    "R": "RST",
    "P": "PSH",
    "A": "ACK",
    "U": "URG",
    "E": "ECE",
    "C": "CWR",
}


def _tcp_flags_str(packet) -> Optional[str]:
    """Extract TCP flags as a human-readable string."""
    if not packet.haslayer(TCP):
        return None
    flags = str(packet[TCP].flags)
    parts = []
    for char in flags:
        name = _TCP_FLAG_NAMES.get(char)
        if name:
            parts.append(name)
    if not parts:
        return flags
    return "-".join(parts)


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
        # Check for mDNS (port 5353) before generic DNS
        if packet.haslayer(UDP):
            if 5353 in (packet[UDP].sport, packet[UDP].dport):
                return "mDNS"
        return "DNS"
    if packet.haslayer(TCP):
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        ports = (sport, dport)
        if 443 in ports:
            return "HTTPS"
        if 80 in ports:
            return "HTTP"
        if 22 in ports:
            return "SSH"
        if 21 in ports:
            return "FTP"
        if 25 in ports or 587 in ports:
            return "SMTP"
        if 143 in ports or 993 in ports:
            return "IMAP"
        if 110 in ports or 995 in ports:
            return "POP3"
        if 1883 in ports or 8883 in ports:
            return "MQTT"
        return "TCP"
    if packet.haslayer(UDP):
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        ports = (sport, dport)
        if 443 in ports:
            return "QUIC"
        if 67 in ports or 68 in ports:
            return "DHCP"
        if 123 in ports:
            return "NTP"
        if 5353 in ports:
            return "mDNS"
        if 5355 in ports:
            return "LLMNR"
        if 1883 in ports:
            return "MQTT"
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


def _extract_headers(packet, protocol: str) -> List[PacketHeader]:
    """Extract protocol-level headers from a packet."""
    headers: List[PacketHeader] = []

    # IP layer headers
    if packet.haslayer(IP):
        ip = packet[IP]
        headers.append(PacketHeader(key="IP Version", value="4"))
        headers.append(PacketHeader(key="IP TTL", value=str(ip.ttl)))
        headers.append(PacketHeader(key="IP ID", value=str(ip.id)))
        headers.append(PacketHeader(key="IP Total Length", value=str(ip.len)))
        headers.append(PacketHeader(key="IP Flags", value=str(ip.flags)))
        headers.append(PacketHeader(key="IP Protocol", value=str(ip.proto)))
    elif packet.haslayer(IPv6):
        ipv6 = packet[IPv6]
        headers.append(PacketHeader(key="IP Version", value="6"))
        headers.append(PacketHeader(key="IPv6 Hop Limit", value=str(ipv6.hlim)))
        headers.append(PacketHeader(key="IPv6 Traffic Class", value=str(ipv6.tc)))
        headers.append(PacketHeader(key="IPv6 Flow Label", value=str(ipv6.fl)))
        headers.append(PacketHeader(key="IPv6 Payload Length", value=str(ipv6.plen)))
        headers.append(PacketHeader(key="IPv6 Next Header", value=str(ipv6.nh)))

    # TCP headers
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        headers.append(PacketHeader(key="TCP Seq", value=str(tcp.seq)))
        headers.append(PacketHeader(key="TCP Ack", value=str(tcp.ack)))
        headers.append(PacketHeader(key="TCP Flags", value=str(tcp.flags)))
        headers.append(PacketHeader(key="TCP Window", value=str(tcp.window)))
        headers.append(PacketHeader(key="TCP Data Offset", value=str(tcp.dataofs)))
        if tcp.options:
            for opt_name, opt_val in tcp.options:
                headers.append(PacketHeader(key=f"TCP Opt {opt_name}", value=str(opt_val)))

    # UDP headers
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        headers.append(PacketHeader(key="UDP Length", value=str(udp.len)))
        headers.append(PacketHeader(key="UDP Checksum", value=hex(udp.chksum) if udp.chksum else "0x0"))

    # DNS headers
    if packet.haslayer(DNS):
        dns = packet[DNS]
        headers.append(PacketHeader(key="DNS ID", value=str(dns.id)))
        headers.append(PacketHeader(key="DNS QR", value="Response" if dns.qr else "Query"))
        headers.append(PacketHeader(key="DNS Opcode", value=str(dns.opcode)))
        headers.append(PacketHeader(key="DNS QD Count", value=str(dns.qdcount)))
        headers.append(PacketHeader(key="DNS AN Count", value=str(dns.ancount)))
        if dns.qd:
            try:
                qname = dns.qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                headers.append(PacketHeader(key="DNS Query", value=qname))
                headers.append(PacketHeader(key="DNS Query Type", value=str(dns.qd.qtype)))
            except Exception:
                pass
        if dns.qr == 1 and dns.ancount > 0:
            try:
                for i in range(min(dns.ancount, 5)):
                    rr = dns.an[i] if dns.ancount > 1 else dns.an
                    if hasattr(rr, "rdata"):
                        rdata = rr.rdata
                        if isinstance(rdata, bytes):
                            rdata = rdata.decode("utf-8", errors="ignore")
                        headers.append(PacketHeader(key=f"DNS Answer {i+1}", value=str(rdata)))
                    if dns.ancount == 1:
                        break
            except Exception:
                pass

    # ICMP headers
    if packet.haslayer(ICMP):
        icmp = packet[ICMP]
        headers.append(PacketHeader(key="ICMP Type", value=str(icmp.type)))
        headers.append(PacketHeader(key="ICMP Code", value=str(icmp.code)))

    # ARP headers
    if packet.haslayer(ARP):
        arp = packet[ARP]
        headers.append(PacketHeader(key="ARP Operation", value="Request" if arp.op == 1 else "Reply"))
        headers.append(PacketHeader(key="ARP Sender MAC", value=str(arp.hwsrc)))
        headers.append(PacketHeader(key="ARP Sender IP", value=str(arp.psrc)))
        headers.append(PacketHeader(key="ARP Target MAC", value=str(arp.hwdst)))
        headers.append(PacketHeader(key="ARP Target IP", value=str(arp.pdst)))

    # HTTP headers (from Raw payload on ports 80)
    if protocol == "HTTP" and packet.haslayer(Raw):
        try:
            raw_data = bytes(packet[Raw].load)
            text = raw_data.decode("utf-8", errors="replace")
            lines = text.split("\r\n")
            if lines:
                first_line = lines[0]
                if first_line.startswith(("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")):
                    headers.append(PacketHeader(key="HTTP Method", value=first_line))
                elif first_line.startswith("HTTP/"):
                    headers.append(PacketHeader(key="HTTP Status", value=first_line))
                for line in lines[1:]:
                    if not line:
                        break
                    if ": " in line:
                        k, v = line.split(": ", 1)
                        headers.append(PacketHeader(key=f"HTTP {k}", value=v))
        except Exception:
            pass

    return headers


def _extract_payload(packet) -> tuple[str, str]:
    """Extract raw payload as hex dump and printable text."""
    if not packet.haslayer(Raw):
        return "", ""
    try:
        raw_bytes = bytes(packet[Raw].load)[:MAX_PAYLOAD_BYTES]
    except Exception:
        return "", ""

    # Hex representation
    hex_lines = []
    for i in range(0, len(raw_bytes), 16):
        chunk = raw_bytes[i:i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        hex_lines.append(f"{i:04x}  {hex_part}")
    hex_str = "\n".join(hex_lines)

    # Printable text
    text_chars = []
    for b in raw_bytes:
        if 32 <= b <= 126:
            text_chars.append(chr(b))
        elif b in (10, 13):
            text_chars.append(chr(b))
        else:
            text_chars.append(".")
    text_str = "".join(text_chars)

    return hex_str, text_str


class CaptureEngine:
    def __init__(self):
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=5000)
        self._stats = TrafficStats()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._dns_cache: OrderedDict = OrderedDict()
        self._captured_packets: List[PacketSummary] = []
        self._captured_lock = threading.Lock()
        self._max_captured = 10000

        self._window_packets: int = 0
        self._window_bytes: int = 0
        self._window_start: float = 0.0

        # Connection tracking
        self._talker_counts: Counter = Counter()
        self._dest_counts: Counter = Counter()
        self._domain_counts: Counter = Counter()
        self._connections: Set[tuple] = set()
        self._bandwidth_history: List[dict] = []

    def set_loop(self, loop: asyncio.AbstractEventLoop):
        self._loop = loop

    def get_interfaces(self) -> List[str]:
        return list(psutil.net_if_addrs().keys())

    def get_stats(self) -> TrafficStats:
        with self._lock:
            return self._stats.model_copy()

    def get_captured_packets(self) -> List[PacketSummary]:
        with self._captured_lock:
            return list(self._captured_packets)

    def start(self, interface: str = "en0"):
        if self._running:
            return
        self._running = True
        self._dns_cache.clear()

        with self._captured_lock:
            self._captured_packets.clear()

        with self._lock:
            self._stats = TrafficStats(
                capture_active=True,
                interface=interface,
                start_time=time.time(),
            )

        self._window_packets = 0
        self._window_bytes = 0
        self._window_start = time.time()

        self._talker_counts.clear()
        self._dest_counts.clear()
        self._domain_counts.clear()
        self._connections.clear()
        self._bandwidth_history.clear()

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

        # Extract headers and payload
        headers = _extract_headers(packet, protocol)
        payload_hex, payload_text = _extract_payload(packet)

        # Direction, TTL, TCP flags
        direction = _get_direction(src_ip, dst_ip) if src_ip != "N/A" else None
        ttl = None
        if packet.haslayer(IP):
            ttl = packet[IP].ttl
        elif packet.haslayer(IPv6):
            ttl = packet[IPv6].hlim
        tcp_flags = _tcp_flags_str(packet)

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
            headers=headers,
            payload_hex=payload_hex,
            payload_text=payload_text,
            direction=direction,
            tcp_flags=tcp_flags,
            ttl=ttl,
        )

        # Store for export
        with self._captured_lock:
            self._captured_packets.append(pkt_summary)
            if len(self._captured_packets) > self._max_captured:
                self._captured_packets = self._captured_packets[-self._max_captured:]

        with self._lock:
            self._stats.total_packets += 1
            self._stats.total_bytes += size
            self._stats.protocol_counts[protocol] = (
                self._stats.protocol_counts.get(protocol, 0) + 1
            )

            # Track top talkers and destinations
            if src_ip != "N/A":
                self._talker_counts[src_ip] += 1
            if dst_ip != "N/A":
                self._dest_counts[dst_ip] += 1

            # Track unique connections
            if src_ip != "N/A" and dst_ip != "N/A":
                self._connections.add((src_ip, dst_ip))
            self._stats.connection_count = len(self._connections)

            # Track top domains
            if domain:
                self._domain_counts[domain] += 1

            # Update top-N dicts on stats
            self._stats.top_talkers = dict(self._talker_counts.most_common(TOP_N))
            self._stats.top_destinations = dict(self._dest_counts.most_common(TOP_N))
            self._stats.top_domains = dict(self._domain_counts.most_common(TOP_N))

            self._window_packets += 1
            self._window_bytes += size
            elapsed = now - self._window_start
            if elapsed >= 1.0:
                self._stats.packets_per_sec = self._window_packets / elapsed
                self._stats.bytes_per_sec = self._window_bytes / elapsed

                # Append to bandwidth history
                self._bandwidth_history.append({
                    "timestamp": now,
                    "bytes_per_sec": self._stats.bytes_per_sec,
                    "packets_per_sec": self._stats.packets_per_sec,
                })
                if len(self._bandwidth_history) > BANDWIDTH_HISTORY_MAX:
                    self._bandwidth_history = self._bandwidth_history[-BANDWIDTH_HISTORY_MAX:]
                self._stats.bandwidth_history = list(self._bandwidth_history)

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
