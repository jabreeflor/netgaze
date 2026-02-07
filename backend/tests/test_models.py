import time
import pytest
from models import PacketSummary, TrafficStats


def test_packet_summary_required_fields():
    pkt = PacketSummary(
        timestamp=time.time(),
        src_ip="192.168.1.1",
        dst_ip="8.8.8.8",
        protocol="TCP",
        size=64,
        summary="TCP SYN",
    )
    assert pkt.src_ip == "192.168.1.1"
    assert pkt.dst_ip == "8.8.8.8"
    assert pkt.protocol == "TCP"
    assert pkt.size == 64
    assert pkt.src_port is None
    assert pkt.dst_port is None


def test_packet_summary_with_ports():
    pkt = PacketSummary(
        timestamp=time.time(),
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        protocol="TCP",
        src_port=52000,
        dst_port=443,
        size=1500,
        summary="HTTPS traffic",
    )
    assert pkt.src_port == 52000
    assert pkt.dst_port == 443


def test_packet_summary_serialization():
    pkt = PacketSummary(
        timestamp=1700000000.0,
        src_ip="192.168.1.1",
        dst_ip="8.8.8.8",
        protocol="UDP",
        src_port=53,
        dst_port=53,
        size=128,
        summary="DNS query",
    )
    data = pkt.model_dump()
    assert isinstance(data, dict)
    assert data["protocol"] == "UDP"
    assert data["timestamp"] == 1700000000.0

    restored = PacketSummary.model_validate(data)
    assert restored == pkt


def test_traffic_stats_defaults():
    stats = TrafficStats()
    assert stats.packets_per_sec == 0.0
    assert stats.bytes_per_sec == 0.0
    assert stats.total_packets == 0
    assert stats.total_bytes == 0
    assert stats.protocol_counts == {}
    assert stats.capture_active is False
    assert stats.interface == ""
    assert stats.start_time is None


def test_traffic_stats_with_data():
    stats = TrafficStats(
        packets_per_sec=150.5,
        bytes_per_sec=98000.0,
        total_packets=10000,
        total_bytes=5000000,
        protocol_counts={"TCP": 7000, "UDP": 2500, "ICMP": 500},
        capture_active=True,
        interface="en0",
        start_time=1700000000.0,
    )
    assert stats.packets_per_sec == 150.5
    assert stats.protocol_counts["TCP"] == 7000
    assert len(stats.protocol_counts) == 3


def test_traffic_stats_serialization():
    stats = TrafficStats(
        total_packets=42,
        protocol_counts={"TCP": 30, "UDP": 12},
    )
    data = stats.model_dump()
    assert isinstance(data, dict)
    restored = TrafficStats.model_validate(data)
    assert restored.total_packets == 42
    assert restored.protocol_counts == {"TCP": 30, "UDP": 12}
