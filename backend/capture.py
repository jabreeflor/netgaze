"""Placeholder capture engine - will be implemented in Step 3."""
from __future__ import annotations

import asyncio
from typing import List, Optional

import psutil

from models import PacketSummary, TrafficStats


class CaptureEngine:
    def __init__(self):
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._stats = TrafficStats()
        self._running = False

    def get_interfaces(self) -> List[str]:
        return list(psutil.net_if_addrs().keys())

    def get_stats(self) -> TrafficStats:
        return self._stats

    def start(self, interface: str = "en0"):
        self._stats.interface = interface
        self._stats.capture_active = True

    def stop(self):
        self._running = False
        self._stats.capture_active = False

    async def get_packet(self) -> Optional[PacketSummary]:
        try:
            return self._queue.get_nowait()
        except asyncio.QueueEmpty:
            return None
