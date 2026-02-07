from __future__ import annotations

from typing import Dict, Optional

from pydantic import BaseModel


class PacketSummary(BaseModel):
    timestamp: float
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    size: int
    summary: str


class TrafficStats(BaseModel):
    packets_per_sec: float = 0.0
    bytes_per_sec: float = 0.0
    total_packets: int = 0
    total_bytes: int = 0
    protocol_counts: Dict[str, int] = {}
    capture_active: bool = False
    interface: str = ""
    start_time: Optional[float] = None
