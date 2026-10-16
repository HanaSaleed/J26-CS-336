"""Unit tests for J26-CS-336 source module, using known synthetic packets only."""
import unittest
from datetime import datetime, timedelta, timezone

from src.window_features import PacketEvent, build_window_features

BASE = datetime(2026, 10, 16, 10, 0, 0, tzinfo=timezone.utc)


def pkt(offset, size, sport=40001, *, reverse=False, asset="virtual-plc-01", syn=0, rst=0):
    src, dst = "192.168.10.50", "192.168.10.20"
    src_port, dst_port = sport, 502
    if reverse:
        src, dst = dst, src
        src_port, dst_port = dst_port, src_port
    return PacketEvent(BASE + timedelta(seconds=offset), asset, src, dst, src_port,
                       dst_port, 6, size, syn=syn, rst=rst)


def known_packets():
    return [
        pkt(0.5, 100, syn=1),
        pkt(1.5, 200),
        pkt(4.999, 120, sport=40002, syn=1),
        pkt(5.0, 60, reverse=True),
        pkt(9.9, 80, sport=40003, syn=1),
        pkt(10.0, 110),
        pkt(14.5, 90),
        pkt(15.0, 70, rst=1),
        pkt(19.9, 130, sport=40004, syn=1),
        pkt(20.0, 150),
        pkt(22.0, 50),
        pkt(2.0, 80, asset="virtual-hmi-01"),
        pkt(12.0, 100, asset="virtual-hmi-01"),
    ]


class TestWindowFeatures(unittest.TestCase):
    def test_all_four_window_sizes(self):
        expected = {
            5: {0: (3, 420), 5: (2, 140), 10: (2, 200), 15: (2, 200), 20: (2, 200)},
            10: {0: (5, 560), 10: (4, 400), 20: (2, 200)},
            15: {0: (7, 760), 15: (4, 400)},
            20: {0: (9, 960), 20: (2, 200)},
        }
        events = known_packets()
        for seconds, expected_windows in expected.items():
            with self.subTest(window=seconds):
                rows = build_window_features(events, seconds)
                plc = {int((datetime.fromisoformat(r["window_start"].replace("Z", "+00:00")) - BASE).total_seconds()): r
                       for r in rows if r["asset_id"] == "virtual-plc-01"}
                self.assertEqual({k: (r["packet_count"], r["total_bytes"]) for k, r in plc.items()}, expected_windows)
                self.assertEqual(sum(r["packet_count"] for r in rows), 13)
                self.assertEqual(sum(r["total_bytes"] for r in rows), 1340)
                self.assertTrue(all(r["window_seconds"] == seconds for r in rows))
                self.assertTrue(all("label" not in r for r in rows))

    def test_boundary_and_flag_counts(self):
        rows = build_window_features(known_packets(), 5)
        plc = [r for r in rows if r["asset_id"] == "virtual-plc-01"]
        self.assertEqual(plc[0]["packet_count"], 3)
        self.assertEqual(plc[0]["syn_packet_count"], 2)
        self.assertEqual(plc[0]["flow_count"], 2)
        self.assertEqual(plc[0]["mean_iat_seconds"], 2.2495)
        self.assertEqual(plc[1]["packet_count"], 2)
        self.assertEqual(plc[1]["window_start"], "2026-10-16T10:00:05Z")

    def test_device_separation(self):
        rows = build_window_features(known_packets(), 5)
        self.assertEqual(sum(r["packet_count"] for r in rows if r["asset_id"] == "virtual-hmi-01"), 2)
        self.assertEqual(sum(r["packet_count"] for r in rows if r["asset_id"] == "virtual-plc-01"), 11)

    def test_no_packets_and_single_packet(self):
        self.assertEqual(build_window_features([], 5), [])
        row = build_window_features([pkt(1.0, 90)], 5)[0]
        self.assertIsNone(row["mean_iat_seconds"])
        self.assertEqual(row["packet_rate_per_second"], 0.2)
        self.assertEqual(row["byte_rate_per_second"], 18)

    def test_invalid_inputs(self):
        with self.assertRaises(ValueError):
            build_window_features(known_packets(), 7)
        with self.assertRaises(ValueError):
            build_window_features([PacketEvent(datetime(2026, 10, 16, 10, 0, 0),
                "plc", "1.1.1.1", "2.2.2.2", 111, 502, 6, 100)], 5)
        with self.assertRaises(ValueError):
            build_window_features([pkt(1, -20)], 5)


if __name__ == "__main__":
    unittest.main()
