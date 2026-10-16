"""Tests for chronological, running-aggregate processing using synthetic packets."""
import unittest
from datetime import datetime, timedelta, timezone

from src.window_features import PacketEvent, build_window_features
from src.window_stream import iter_window_features

BASE = datetime(2026, 10, 16, 10, 0, 0, tzinfo=timezone.utc)


def packet(t, *, asset="plc", size=100, src="192.168.10.1", dst="192.168.10.2",
           sport=30000, dport=502, proto=6, syn=0, rst=0):
    return PacketEvent(BASE + timedelta(seconds=t), asset, src, dst, sport, dport,
                       proto, size, syn=syn, rst=rst)


def fixture():
    return [
        packet(0.5, syn=1), packet(1.5, size=200), packet(2, asset="hmi", size=80),
        packet(4.999, sport=30001, syn=1), packet(5, size=60),
        packet(9.9, size=80), packet(10, size=110),
        packet(12, asset="hmi", size=100), packet(14.5, size=90),
        packet(15, size=70, rst=1), packet(19.9, size=130),
        packet(20, size=150), packet(22, size=50),
    ]


class TestWindowStream(unittest.TestCase):
    def test_matches_batch_all_four_durations(self):
        records = fixture()
        for seconds in (5, 10, 15, 20):
            with self.subTest(seconds=seconds):
                expected = build_window_features(records, seconds)
                actual = list(iter_window_features(iter(records), seconds))
                order = lambda r: (r["asset_id"], r["window_start"])
                self.assertEqual(sorted(actual, key=order), sorted(expected, key=order))
                self.assertEqual(sum(r["packet_count"] for r in actual), len(records))
                self.assertTrue(all("label" not in r for r in actual))

    def test_same_timestamp_and_window_boundary(self):
        events = [packet(0, syn=1), packet(0, size=60), packet(5, size=120)]
        rows = list(iter_window_features(events, 5))
        self.assertEqual([r["packet_count"] for r in rows], [2, 1])
        self.assertEqual(rows[0]["mean_iat_seconds"], 0)
        self.assertEqual(rows[1]["window_start"], "2026-10-16T10:00:05Z")

    def test_rejects_out_of_order_packets(self):
        with self.assertRaisesRegex(ValueError, "nondecreasing"):
            list(iter_window_features([packet(2), packet(1)], 5))

    def test_empty_and_bad_window(self):
        self.assertEqual(list(iter_window_features([], 10)), [])
        with self.assertRaises(ValueError):
            list(iter_window_features([], 7))

    def test_rejects_invalid_input(self):
        with self.assertRaises(ValueError):
            list(iter_window_features([packet(1, size=-10)], 5))

    def test_iterative_large_stream(self):
        n = 12000
        events = (packet(i / 1000, size=50) for i in range(n))
        rows = list(iter_window_features(events, 5))
        self.assertEqual(sum(r["packet_count"] for r in rows), n)
        self.assertEqual(sum(r["total_bytes"] for r in rows), n * 50)
        self.assertEqual(len(rows), 3)


if __name__ == "__main__":
    unittest.main()
