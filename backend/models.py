from __future__ import annotations

from typing import Dict, List, Optional

from pydantic import BaseModel


class PacketHeader(BaseModel):
    key: str
    value: str


class PacketSummary(BaseModel):
    timestamp: float
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    size: int
    summary: str
    domain: Optional[str] = None
    headers: List[PacketHeader] = []
    payload_hex: str = ""
    payload_text: str = ""
    direction: Optional[str] = None
    tcp_flags: Optional[str] = None
    ttl: Optional[int] = None


class TrafficStats(BaseModel):
    packets_per_sec: float = 0.0
    bytes_per_sec: float = 0.0
    total_packets: int = 0
    total_bytes: int = 0
    protocol_counts: Dict[str, int] = {}
    capture_active: bool = False
    interface: str = ""
    start_time: Optional[float] = None
    top_talkers: Dict[str, int] = {}
    top_destinations: Dict[str, int] = {}
    top_domains: Dict[str, int] = {}
    bandwidth_history: List[dict] = []
    connection_count: int = 0
