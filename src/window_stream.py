"""J26-CS-336: memory-conscious event-time window aggregation for VERIFIED packets.

Input must be a chronological stream of PacketEvent objects (nondecreasing UTC ts).
The function yields only nonempty, complete windows when a later window starts;
caller's end-of-stream closes the last window. It does not ingest or relabel CICAPT.

A window stores running aggregates and sets of seen IPs/ports/flows rather than
all individual packet objects. Memory is bounded by the distinct entities
within the CURRENT active window, not by the full duration of the stream.

No outputs for empty windows. Late/out-of-order timestamps raise ValueError.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Iterable, Iterator

from src.window_features import (
    PacketEvent, TCP_FLAGS, WINDOW_SIZES, _bidirectional_flow,
    _check_packet, _iso_z, _window_start,
)


@dataclass
class _AssetAggregate:
    packet_count: int = 0
    total_bytes: int = 0
    tcp_packet_count: int = 0
    dst_ports: set[int] = field(default_factory=set)
    dst_ips: set[str] = field(default_factory=set)
    flows: set[tuple] = field(default_factory=set)
    previous_ts: datetime | None = None
    gap_sum_seconds: float = 0.0
    gap_count: int = 0
    flags: dict[str, int] = field(default_factory=lambda: {f: 0 for f in TCP_FLAGS})

    def add(self, packet: PacketEvent) -> None:
        self.packet_count += 1
        self.total_bytes += packet.size_bytes
        self.dst_ports.add(packet.dst_port)
        self.dst_ips.add(packet.dst_ip)
        self.flows.add(_bidirectional_flow(packet))
        if self.previous_ts is not None:
            self.gap_sum_seconds += (packet.ts - self.previous_ts).total_seconds()
            self.gap_count += 1
        self.previous_ts = packet.ts
        if packet.protocol == 6:
            self.tcp_packet_count += 1
            for flag in TCP_FLAGS:
                self.flags[flag] += getattr(packet, flag)

    def result(self, asset_id: str, start: datetime, seconds: int) -> dict:
        result = {
            "asset_id": asset_id,
            "window_start": _iso_z(start),
            "window_end": _iso_z(start + timedelta(seconds=seconds)),
            "window_seconds": seconds,
            "packet_count": self.packet_count,
            "total_bytes": self.total_bytes,
            "mean_packet_size": round(self.total_bytes / self.packet_count, 4),
            "tcp_packet_count": self.tcp_packet_count,
            "unique_dst_ports": len(self.dst_ports),
            "unique_dst_ips": len(self.dst_ips),
            "flow_count": len(self.flows),
            "packet_rate_per_second": round(self.packet_count / seconds, 4),
            "byte_rate_per_second": round(self.total_bytes / seconds, 4),
            "mean_iat_seconds": round(self.gap_sum_seconds / self.gap_count, 4)
            if self.gap_count else None,
        }
        for flag in TCP_FLAGS:
            result[f"{flag}_packet_count"] = self.flags[flag]
        return result


def iter_window_features(events: Iterable[PacketEvent], seconds: int) -> Iterator[dict]:
    """Yield per-asset features from globally chronological, verified packets.

    Windows are aligned to UTC epoch multiples of `seconds` and are half-open
    [start, end). End of input closes any active windows. An out-of-order
    packet raises an error rather than silently putting it in the wrong window.
    Caller should only feed VERIFIED packet events, not unvalidated CSV rows.
    """
    if seconds not in WINDOW_SIZES:
        raise ValueError(f"Window must be one of {WINDOW_SIZES}")

    active_start: datetime | None = None
    previous_input_ts: datetime | None = None
    assets: dict[str, _AssetAggregate] = {}

    for packet in events:
        _check_packet(packet)
        if previous_input_ts is not None and packet.ts < previous_input_ts:
            raise ValueError("Packets must arrive in nondecreasing UTC timestamp order")
        previous_input_ts = packet.ts
        packet_window_start = _window_start(packet.ts, seconds)
        if active_start is not None and packet_window_start != active_start:
            for asset_id, group in sorted(assets.items()):
                yield group.result(asset_id, active_start, seconds)
            assets.clear()
        active_start = packet_window_start
        assets.setdefault(packet.asset_id, _AssetAggregate()).add(packet)

    if active_start is not None:
        for asset_id, group in sorted(assets.items()):
            yield group.result(asset_id, active_start, seconds)
