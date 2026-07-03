"""Tests for traffic aggregation logic.

Tests the pure aggregation functions extracted from the Flask endpoints:
  - _aggregate_history_rows: per-bucket deltas from raw snapshots
  - _aggregate_batch_rows:   per-MAC totals from raw snapshots

These must be correct regardless of the snapshot (cron) interval, and must
handle nft counter resets (router reboots) without producing spikes.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import _aggregate_history_rows, _aggregate_batch_rows


# Bytes transferred at a constant rate over a period, snapshotted every
# SNAP_INTERVAL seconds, as cumulative counters: [(ts, bytes_out, bytes_in), ...]
def _snapshots(rate_up, rate_down, period, snap_interval, start=0):
    rows = []
    out = 0
    inn = 0
    for ts in range(start, period + snap_interval, snap_interval):
        rows.append((ts, out, inn))
        out += rate_up * snap_interval
        inn += rate_down * snap_interval
    return rows


class HistoryDayViewTests(unittest.TestCase):
    """Day view: 15-min buckets, 5-min cron snapshots, constant 1 MB/s down."""

    BUCKET = 900        # 15 minutes
    SNAP = 300          # 5 minutes (current cron)
    PERIOD = 86400      # 24 hours
    RATE_DOWN = 1_000_000   # 1 MB/s
    RATE_UP = 200_000       # 200 KB/s

    def _rows(self):
        return _snapshots(self.RATE_UP, self.RATE_DOWN, self.PERIOD, self.SNAP)

    def test_total_down_matches_actual(self):
        # Synthetic data starts at ts=0 (== cutoff) with counter 0, so the
        # first delta (0->300) is fully captured: no boundary loss here.
        actual_down = self.RATE_DOWN * self.PERIOD
        buckets, total_up, total_down = _aggregate_history_rows(
            self._rows(), self.BUCKET, cutoff=0
        )
        self.assertEqual(total_down, actual_down)
        self.assertEqual(total_up, self.RATE_UP * self.PERIOD)

    def test_first_bucket_captures_full_bucket_of_traffic(self):
        buckets, _, _ = _aggregate_history_rows(self._rows(), self.BUCKET, cutoff=0)
        first = buckets[0]
        # 3 deltas of 300s each = 900s of traffic in the first bucket
        expected_down = self.RATE_DOWN * self.BUCKET
        self.assertAlmostEqual(first["down"], expected_down, delta=1)
        self.assertEqual(first["ts"], 0)

    def test_bucket_count_is_one_per_15_minutes(self):
        buckets, _, _ = _aggregate_history_rows(self._rows(), self.BUCKET, cutoff=0)
        self.assertEqual(len(buckets), self.PERIOD // self.BUCKET)

    def test_buckets_are_monotonic_in_ts(self):
        buckets, _, _ = _aggregate_history_rows(self._rows(), self.BUCKET, cutoff=0)
        ts_list = [b["ts"] for b in buckets]
        self.assertEqual(ts_list, sorted(ts_list))


class HistoryDecouplingTests(unittest.TestCase):
    """Changing the cron interval must not change the reported total."""

    BUCKET = 900
    PERIOD = 86400
    RATE_DOWN = 1_000_000
    RATE_UP = 200_000

    def test_one_minute_cron_matches_five_minute_cron(self):
        actual_down = self.RATE_DOWN * self.PERIOD
        rows_5min = _snapshots(self.RATE_UP, self.RATE_DOWN, self.PERIOD, 300)
        rows_1min = _snapshots(self.RATE_UP, self.RATE_DOWN, self.PERIOD, 60)
        _, _, total_5 = _aggregate_history_rows(rows_5min, self.BUCKET, cutoff=0)
        _, _, total_1 = _aggregate_history_rows(rows_1min, self.BUCKET, cutoff=0)
        # Both within one snapshot-interval of actual, and within 1% of each other
        self.assertAlmostEqual(total_1, total_5, delta=actual_down * 0.02)


class HistoryCounterResetTests(unittest.TestCase):
    """Router reboots reset the nft cumulative counter to 0.

    The aggregation must treat a reset as a new baseline, NOT produce a
    spurious huge 'MAX - MIN' spike.
    """

    BUCKET = 900
    RATE = 1_000_000

    def test_reboot_mid_bucket_produces_no_spurious_spike(self):
        # Snapshots at t=0,300,600,900 with a counter reset at t=600.
        # Without reset, bucket 0 (ts 0..899) would have 600s of traffic = 600_000_000.
        # A naive MAX-MIN would see max=600_000_000 (pre-reboot) vs min=0 => 600_000_000,
        # then the next bucket starts at 0 again producing another huge delta.
        rows = [
            (0,   0,             0),
            (300, 300_000_000,   0),
            (600, 0,             0),   # reboot: counter resets to 0
            (900, 300_000_000,   0),  # 300s of traffic after reboot
        ]
        buckets, total_up, _ = _aggregate_history_rows(rows, self.BUCKET, cutoff=0)
        # Deltas by start ts:
        #   start 0:   300M (0->300)
        #   start 300: clamped 0 (reset: 0 - 600M)
        #   start 600: 300M (0->300, post-reboot traffic)
        # Bucket 0 = 300M + 0 + 300M = 600M (only [0,300] and [600,900] measured;
        #            [300,600] lost to reboot). No row at 1200, so no bucket 900.
        self.assertEqual(len(buckets), 1)
        self.assertEqual(buckets[0]["ts"], 0)
        self.assertEqual(buckets[0]["up"], 600_000_000)
        # No spike: a 15-min bucket at 1MB/s cannot exceed 900_000_000 bytes
        for b in buckets:
            self.assertLessEqual(b["up"], self.RATE * self.BUCKET)
        self.assertEqual(total_up, 600_000_000)

    def test_reboot_at_period_boundary_does_not_inflate_total(self):
        # 2 buckets worth of snapshots, reboot at the bucket boundary (ts=900).
        rows = [
            (0,   0,           0),
            (300, 300_000_000, 0),
            (600, 600_000_000, 0),
            (900, 0,           0),   # reboot at bucket boundary
            (1200, 300_000_000, 0),
            (1500, 600_000_000, 0),
        ]
        buckets, total_up, _ = _aggregate_history_rows(rows, self.BUCKET, cutoff=0)
        # Deltas by start ts:
        #   start 0:   300M, start 300: 300M, start 600: clamped 0 (reset)
        #   start 900: 300M, start 1200: 300M
        # Bucket 0  = 600M (full [0,600] measured; [600,900] lost to reboot)
        # Bucket 900 = 600M (full [900,1500] measured)
        by_ts = {b["ts"]: b["up"] for b in buckets}
        self.assertAlmostEqual(by_ts[0], 600_000_000, delta=1)
        self.assertAlmostEqual(by_ts[900], 600_000_000, delta=1)
        self.assertAlmostEqual(total_up, 1_200_000_000, delta=1)


class HistoryBoundaryLossTests(unittest.TestCase):
    """In production the first fetched snapshot is at/after cutoff with a
    nonzero cumulative counter; its predecessor (before cutoff) is unfetched,
    so the [predecessor_ts, first_ts] interval is unmeasurable. This documents
    that at most one snapshot interval is lost at the period start.
    """

    BUCKET = 900
    RATE = 1_000_000
    SNAP = 300

    def test_first_interval_lost_when_predecessor_unfetched(self):
        # Realistic: counter already at 1.2B before cutoff=900. SQL fetches
        # ts >= 900 only, so the [600,900] interval (300M of traffic) is lost.
        rows = [
            (900,  1_200_000_000, 0),   # first fetched; counter already large
            (1200, 1_500_000_000, 0),   # +300M
            (1500, 1_800_000_000, 0),   # +300M
        ]
        buckets, total_up, _ = _aggregate_history_rows(rows, self.BUCKET, cutoff=900)
        # Only deltas with start >= 900: start 900 (+300M), start 1200 (+300M) = 600M.
        # The [600,900] traffic (300M) is lost: its start (600) < cutoff.
        self.assertEqual(total_up, 600_000_000)
        self.assertLess(total_up, self.RATE * 3 * self.SNAP)  # would be 900M with no loss


class BatchHistoryTests(unittest.TestCase):
    """batch-history: per-MAC totals over the whole period via delta-sum."""

    PERIOD = 3600
    RATE_DOWN = 1_000_000
    RATE_UP = 200_000

    def _mac_rows(self, mac, start=0):
        return [
            (mac, ts, out, inn)
            for ts, out, inn in _snapshots(self.RATE_UP, self.RATE_DOWN, self.PERIOD, 300, start)
        ]

    def test_single_mac_total_matches_actual(self):
        rows = self._mac_rows("aa:bb:cc:dd:ee:01")
        actual_down = self.RATE_DOWN * self.PERIOD
        totals = _aggregate_batch_rows(rows, cutoff=0)
        self.assertEqual(totals["aa:bb:cc:dd:ee:01"]["down"], actual_down)
        self.assertEqual(totals["aa:bb:cc:dd:ee:01"]["up"], self.RATE_UP * self.PERIOD)

    def test_multiple_macs_are_independent(self):
        rows = self._mac_rows("aa:bb:cc:dd:ee:01")
        rows += self._mac_rows("aa:bb:cc:dd:ee:02")
        totals = _aggregate_batch_rows(rows, cutoff=0)
        self.assertEqual(set(totals), {"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"})
        self.assertAlmostEqual(
            totals["aa:bb:cc:dd:ee:01"]["down"],
            totals["aa:bb:cc:dd:ee:02"]["down"],
            delta=1,
        )

    def test_reboot_does_not_inflate_batch_total(self):
        rows = [
            ("aa:bb:cc:dd:ee:01", 0,   0,           0),
            ("aa:bb:cc:dd:ee:01", 300, 300_000_000, 0),
            ("aa:bb:cc:dd:ee:01", 600, 0,           0),   # reboot
            ("aa:bb:cc:dd:ee:01", 900, 300_000_000, 0),
        ]
        totals = _aggregate_batch_rows(rows, cutoff=0)
        # Only the non-reset deltas count: 300M (0->300) + 0 (reset clamped) + 300M (600->900) = 600M
        self.assertAlmostEqual(totals["aa:bb:cc:dd:ee:01"]["up"], 600_000_000, delta=1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
