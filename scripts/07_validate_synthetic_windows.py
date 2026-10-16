"""J26-CS-336 Phase 5.11 — test four UTC tumbling windows on synthetic packets.

Runs ONLY synthetic data in memory. It does not read or modify the CICAPT datasets.
Requires Python 3.12+ standard library (no pip installs).

Semantics:
  - A row in this synthetic fixture is exactly one known packet observation.
  - Windows are [start, end) UTC, aligned to Unix-epoch multiples of duration.
  - Device/asset is set explicitly for this controlled test.
  - All-direction destination diversity is a basic statistic, NOT a scan detector.
  - A flow is a bidirectional, protocol-specific five-tuple within a window.
  - Mean IAT is calculated across consecutive packets for the SAME asset
    WITHIN the window, not a per-flow IAT.
  - No training, relabeling, attack detection, or original-file access.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from statistics import mean

WINDOW_SIZES = (5, 10, 15, 20)
BASE = datetime(2026, 10, 16, 10, 0, 0, tzinfo=timezone.utc)


@dataclass(frozen=True)
class Packet:
    ts: datetime
    device_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol_number: int
    size_bytes: int
    syn: int = 0
    rst: int = 0


def sample_packet(offset_seconds, size_bytes, src_port=40001, *, reverse=False, syn=0, rst=0, device_id="virtual-plc-01"):
    src, dst = "192.168.10.50", "192.168.10.20"
    sport, dport = src_port, 502
    if reverse:
        src, dst = dst, src
        sport, dport = dport, sport
    return Packet(
        BASE + timedelta(seconds=offset_seconds), device_id,
        src, dst, sport, dport, 6, size_bytes, syn, rst,
    )


def example_events():
    # Explicit packet events: fixed known answers, including exact boundary events.
    return [
        sample_packet(0.5, 100, syn=1),
        sample_packet(1.5, 200),
        sample_packet(4.999, 120, src_port=40002, syn=1),
        sample_packet(5.0, 60, reverse=True),  # belongs to [5, 10)
        sample_packet(9.9, 80, src_port=40003, syn=1),
        sample_packet(10.0, 110),             # belongs to [10, 15)
        sample_packet(14.5, 90),
        sample_packet(15.0, 70, rst=1),       # belongs to [15, 20)
        sample_packet(19.9, 130, src_port=40004, syn=1),
        sample_packet(20.0, 150),             # belongs to [20, 25)
        sample_packet(22.0, 50),
        sample_packet(2.0, 80, device_id="virtual-hmi-01"),
        sample_packet(12.0, 100, device_id="virtual-hmi-01"),
    ]


def start_of_window(ts: datetime, seconds: int) -> datetime:
    if ts.tzinfo is None or ts.utcoffset() != timedelta(0):
        raise ValueError("Event timestamp must be timezone-aware UTC")
    epoch_start = int(ts.timestamp() // seconds) * seconds
    return datetime.fromtimestamp(epoch_start, tz=timezone.utc)


def iso_z(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def bidirectional_flow_key(p: Packet):
    peers = tuple(sorted(((p.src_ip, p.src_port), (p.dst_ip, p.dst_port))))
    return (p.protocol_number, peers)


def window_features(events: list[Packet], seconds: int) -> list[dict]:
    if seconds not in WINDOW_SIZES:
        raise ValueError(f"Unsupported window size: {seconds}")
    grouped = defaultdict(list)
    for event in events:
        if event.size_bytes <= 0 or event.syn not in (0, 1) or event.rst not in (0, 1):
            raise ValueError("Invalid synthetic packet size or TCP flag")
        grouped[(event.device_id, start_of_window(event.ts, seconds))].append(event)

    result = []
    for (device_id, beginning), packets in sorted(grouped.items()):
        ordered = sorted(packets, key=lambda p: p.ts)
        gaps = [
            (ordered[i].ts - ordered[i - 1].ts).total_seconds()
            for i in range(1, len(ordered))
        ]
        total_bytes = sum(p.size_bytes for p in ordered)
        count = len(ordered)
        result.append({
            "device_id": device_id,
            "window_start": iso_z(beginning),
            "window_end": iso_z(beginning + timedelta(seconds=seconds)),
            "window_seconds": seconds,
            "packet_count": count,
            "total_bytes": total_bytes,
            "mean_packet_size": round(total_bytes / count, 4),
            "tcp_packet_count": sum(p.protocol_number == 6 for p in ordered),
            "syn_packet_count": sum(p.syn for p in ordered if p.protocol_number == 6),
            "rst_packet_count": sum(p.rst for p in ordered if p.protocol_number == 6),
            "unique_dst_ports": len({p.dst_port for p in ordered}),
            "unique_dst_ips": len({p.dst_ip for p in ordered}),
            "flow_count": len({bidirectional_flow_key(p) for p in ordered}),
            "packet_rate_per_second": round(count / seconds, 4),
            "byte_rate_per_second": round(total_bytes / seconds, 4),
            "mean_iat_seconds": round(mean(gaps), 4) if gaps else None,
        })
    return result


def verify(events):
    expected_plc_counts = {
        5: {0: 3, 5: 2, 10: 2, 15: 2, 20: 2},
        10: {0: 5, 10: 4, 20: 2},
        15: {0: 7, 15: 4},
        20: {0: 9, 20: 2},
    }
    for seconds in WINDOW_SIZES:
        rows = window_features(events, seconds)
        plc = {
            int((datetime.fromisoformat(r["window_start"].replace("Z", "+00:00")) - BASE).total_seconds()): r
            for r in rows if r["device_id"] == "virtual-plc-01"
        }
        actual = {offset: r["packet_count"] for offset, r in plc.items()}
        assert actual == expected_plc_counts[seconds], (
            f"Wrong window counts for {seconds}s: {actual}"
        )
        assert sum(r["packet_count"] for r in rows) == len(events), "Packets dropped/duplicated"
        assert sum(r["total_bytes"] for r in rows) == sum(e.size_bytes for e in events), "Bytes dropped/duplicated"
        for r in rows:
            assert (datetime.fromisoformat(r["window_end"].replace("Z", "+00:00")) -
                    datetime.fromisoformat(r["window_start"].replace("Z", "+00:00"))).total_seconds() == seconds
            assert r["mean_iat_seconds"] is None or r["mean_iat_seconds"] >= 0
            assert "label" not in r and "attack" not in r
        if seconds == 5:
            assert plc[0]["total_bytes"] == 420
            assert plc[0]["syn_packet_count"] == 2
            assert plc[0]["flow_count"] == 2
            assert plc[0]["mean_iat_seconds"] == 2.2495
            assert plc[5]["total_bytes"] == 140
        if seconds == 20:
            assert plc[0]["total_bytes"] == 960
            assert plc[20]["total_bytes"] == 200
        print(f"\nPASS: {seconds}s windows: correct counts, totals, boundaries and device separation")
        for row in rows:
            print(f"  {row['device_id']:<15} {row['window_start']} to {row['window_end']}  "
                  f"packets={row['packet_count']:<2} bytes={row['total_bytes']:<3} "
                  f"flows={row['flow_count']:<2} mean_IAT={row['mean_iat_seconds']}")


def main():
    print("=== J26-CS-336 SYNTHETIC WINDOW VERIFICATION ===")
    print("No actual CICAPT or ToN-IoT files are read or modified.")
    events = example_events()
    print(f"Known input: {len(events)} artificial packet events across 2 device IDs")
    verify(events)
    print("\nALL FOUR WINDOW TESTS PASSED")
    print("NEXT: review real CICAPT record semantics before adapting this to CSV input.")


if __name__ == "__main__":
    main()
