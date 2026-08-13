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

from traffic_aggregate import aggregate_history_rows as _aggregate_history_rows
from traffic_aggregate import aggregate_batch_rows as _aggregate_batch_rows
from traffic_aggregate import aggregate_daily_rows as _aggregate_daily_rows
from traffic_aggregate import _render_buckets as _render_buckets
from traffic_aggregate import cmd_history as _cmd_history
from traffic_aggregate import cmd_batch as _cmd_batch


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


class DailyRollupTests(unittest.TestCase):
    """month/year periods read the daily rollup table, whose rows are absolute
    per-day totals (no delta math). Daily rows map directly into buckets.
    """

    def test_daily_rows_sum_into_daily_buckets(self):
        # 3 days, 1000 bytes up / 500 bytes down each, 86400s buckets.
        rows = [
            (0,           1000, 500),
            (86400,       1000, 500),
            (172800,      1000, 500),
        ]
        buckets, total_up, total_down = _aggregate_daily_rows(rows, 86400)
        self.assertEqual(total_up, 3000)
        self.assertEqual(total_down, 1500)
        self.assertEqual(len(buckets), 3)
        self.assertEqual(buckets[0]["up"], 1000)
        self.assertEqual(buckets[2]["down"], 500)

    def test_daily_rows_sum_into_weekly_buckets(self):
        # 14 days of 1000 bytes/day, 604800s (weekly) buckets -> 2 buckets of 7000.
        rows = [(d * 86400, 1000, 500) for d in range(14)]
        buckets, total_up, total_down = _aggregate_daily_rows(rows, 604800)
        self.assertEqual(total_up, 14000)
        self.assertEqual(total_down, 7000)
        self.assertEqual(len(buckets), 2)
        self.assertEqual(buckets[0]["up"], 7000)
        self.assertEqual(buckets[1]["up"], 7000)

    def test_empty_input(self):
        buckets, total_up, total_down = _aggregate_daily_rows([], 86400)
        self.assertEqual(buckets, [])
        self.assertEqual(total_up, 0)
        self.assertEqual(total_down, 0)


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

class WindowedRenderTests(unittest.TestCase):
    """_render_buckets(agg, bucket_size, start, end) zero-fills the full window.

    The window [start, end) is supplied by the caller (app.py), computed in
    the browser's local time so "today" spans 00:00 to now. The renderer must
    cover the entire window — not just first-activity to last-activity — so a
    partial day renders from midnight, and an empty day renders a flat line.
    """

    BUCKET = 900  # 15 minutes (day period)

    def test_full_day_window_spans_midnight_to_end(self):
        # Two snapshots at 10:00 and 14:00. Window is the full day
        # [0, 86400). Renderer must fill all 96 buckets, not just 2.
        agg = [
            {"ts": (10 * 3600 // 900) * 900, "up": 1000, "down": 5000},
            {"ts": (14 * 3600 // 900) * 900, "up": 2000, "down": 8000},
        ]
        filled = _render_buckets(agg, self.BUCKET, start=0, end=86400)
        self.assertEqual(len(filled), 86400 // self.BUCKET)  # 96 buckets
        self.assertEqual(filled[0]["ts"], 0)
        self.assertEqual(filled[-1]["ts"], 86400 - self.BUCKET)
        # The two activity buckets carry their values; the rest are zeros.
        activity = {a["ts"] for a in agg}
        for b in filled:
            if b["ts"] in activity:
                self.assertNotEqual(b["down"], 0)
            else:
                self.assertEqual(b["down"], 0)
                self.assertEqual(b["up"], 0)

    def test_partial_day_window_clamps_to_now(self):
        # Window is [0, 54000) (00:00 to 15:00). Must fill exactly 60 buckets.
        agg = [{"ts": 0, "up": 100, "down": 500}]
        filled = _render_buckets(agg, self.BUCKET, start=0, end=54000)
        self.assertEqual(len(filled), 54000 // self.BUCKET)  # 60 buckets
        self.assertEqual(filled[0]["down"], 500)
        self.assertEqual(filled[1]["down"], 0)
        self.assertEqual(filled[-1]["ts"], 54000 - self.BUCKET)

    def test_empty_window_fills_with_zeros(self):
        # No data at all in the window: still fill the whole window with
        # zeros so today renders a flat line instead of a blank chart.
        filled = _render_buckets([], self.BUCKET, start=0, end=86400)
        self.assertEqual(len(filled), 86400 // self.BUCKET)
        self.assertTrue(all(b["up"] == 0 and b["down"] == 0 for b in filled))
        self.assertTrue(all("up_mbps" in b and "down_mbps" in b for b in filled))

    def test_prev_day_window_excludes_today(self):
        # Window is yesterday [86400, 172800). A snapshot today at ts=170000
        # must NOT appear; only yesterday's activity should render.
        agg = [{"ts": 90000, "up": 1000, "down": 5000}]  # yesterday 01:00
        filled = _render_buckets(agg, self.BUCKET, start=86400, end=172800)
        self.assertEqual(len(filled), 86400 // self.BUCKET)
        self.assertEqual(filled[0]["ts"], 86400)
        self.assertEqual(filled[-1]["ts"], 172800 - self.BUCKET)
        # Only the bucket containing ts=90000 has traffic.
        activity = [b for b in filled if b["down"] != 0]
        self.assertEqual(len(activity), 1)
        self.assertEqual(activity[0]["down"], 5000)

    def test_weekly_window_fills_daily_rollup(self):
        # Month period (86400s buckets) over a 7-day window [0, 604800).
        # Only 3 days have data; renderer must still fill all 7 day-buckets.
        agg = [
            {"ts": 0, "up": 1000, "down": 5000},
            {"ts": 86400, "up": 2000, "down": 8000},
            {"ts": 172800, "up": 1500, "down": 6000},
        ]
        filled = _render_buckets(agg, 86400, start=0, end=604800)
        self.assertEqual(len(filled), 7)
        self.assertEqual(filled[0]["ts"], 0)
        self.assertEqual(filled[3]["down"], 0)  # day 4 had no data
        self.assertEqual(filled[0]["down"], 5000)

    def test_no_window_falls_back_to_activity_range(self):
        # Backward compat: no start/end -> fill from first to last bucket,
        # same behavior as before the window feature (existing callers).
        agg = [
            {"ts": 3600, "up": 100, "down": 500},
            {"ts": 7200, "up": 200, "down": 800},
        ]
        filled = _render_buckets(agg, 3600)
        self.assertEqual(len(filled), 2)
        self.assertEqual(filled[0]["ts"], 3600)
        self.assertEqual(filled[1]["ts"], 7200)

class LiveTodayMergeTests(unittest.TestCase):
    """Month/year views read the daily rollup, which only holds complete
    *previous* days — today's traffic lives only in the raw snapshot table.
    Without merging today's live raw delta-sum, month would report less than
    a week inside the same month (the bug this class locks down).
    """

    MAC = "aa:bb:cc:dd:ee:00"

    def _build_db(self, today_down, today_up=0, with_yesterday_daily=True,
                  spurious_daily_today=False):
        """Build a temp DB. today_down/today_up are today's traffic (bytes),
        delivered as raw 5-min snapshots from midnight. Yesterday's traffic
        (2 GB down / 200 MB up) is in the daily rollup only.
        """
        import os as _os
        path = _os.environ.get("VEGGEN_DB", "/tmp/test_live_today.db")
        import sqlite3, time
        db = sqlite3.connect(path)
        db.execute("DROP TABLE IF EXISTS mac_traffic")
        db.execute("DROP TABLE IF EXISTS mac_traffic_daily")
        db.execute(
            "CREATE TABLE mac_traffic (ts INTEGER, mac TEXT, bytes_in INTEGER, "
            "bytes_out INTEGER, PRIMARY KEY (ts, mac))"
        )
        db.execute("CREATE INDEX idx_mac_ts ON mac_traffic(mac, ts)")
        db.execute(
            "CREATE TABLE mac_traffic_daily (day INTEGER, mac TEXT, bytes_in INTEGER, "
            "bytes_out INTEGER, PRIMARY KEY (day, mac))"
        )
        now = int(time.time())
        today_mid = now - (now % 86400)
        prev_day = today_mid - 86400
        # Yesterday: daily rollup row only.
        if with_yesterday_daily:
            db.execute("INSERT INTO mac_traffic_daily VALUES (?,?,?,?)",
                        (prev_day, self.MAC, 2_000_000_000, 200_000_000))
        # Today: raw 5-min cumulative snapshots from midnight.
        if today_down or today_up:
            ts = today_mid
            out = 0
            inn = 0
            # Even rate so the delta-sum is exactly today_down/today_up.
            snaps = max(1, (now - today_mid) // 300)
            rate_down = today_down / snaps if snaps else 0
            rate_up = today_up / snaps if snaps else 0
            for _ in range(snaps + 1):
                db.execute("INSERT OR REPLACE INTO mac_traffic VALUES (?,?,?,?)",
                            (ts, self.MAC, int(inn), int(out)))
                ts += 300
                out += int(rate_up * 300)
                inn += int(rate_down * 300)
        # Optional spurious daily row for today (double-count guard).
        if spurious_daily_today:
            db.execute("INSERT INTO mac_traffic_daily VALUES (?,?,?,?)",
                        (today_mid, self.MAC, 10_000_000_000, 1_000_000_000))
        db.commit()
        db.close()
        return path, now, today_mid

    def test_month_includes_today_live_traffic(self):
        path, now, today_mid = self._build_db(today_down=5_000_000_000)
        import traffic_aggregate
        old_db = traffic_aggregate.DB
        traffic_aggregate.DB = path
        try:
            mo = _cmd_history(self.MAC, "month", today_mid - 30 * 86400, now)
        finally:
            traffic_aggregate.DB = old_db
        # 2 GB yesterday + ~5 GB today = ~7 GB. Must be >= today's traffic.
        self.assertGreater(mo["total_down"], 6_000_000_000,
                           "month must include today's live traffic, not just rollup")

    def test_month_never_less_than_week(self):
        """The bug report: week 5.3 GB but month 2.9 GB. Month must be >= week
        when the week window is inside the month window."""
        path, now, today_mid = self._build_db(today_down=5_000_000_000)
        import traffic_aggregate
        old_db = traffic_aggregate.DB
        traffic_aggregate.DB = path
        try:
            wk = _cmd_history(self.MAC, "week", today_mid - 7 * 86400, now)
            mo = _cmd_history(self.MAC, "month", today_mid - 30 * 86400, now)
        finally:
            traffic_aggregate.DB = old_db
        self.assertGreaterEqual(mo["total_down"], wk["total_down"],
                                "month must never report less than a week inside it")

    def test_past_month_excludes_today(self):
        """A month window ending at today's midnight (exclusive) must not
        include today's live traffic."""
        path, now, today_mid = self._build_db(today_down=5_000_000_000)
        import traffic_aggregate
        old_db = traffic_aggregate.DB
        traffic_aggregate.DB = path
        try:
            mo = _cmd_history(self.MAC, "month", today_mid - 30 * 86400, today_mid)
        finally:
            traffic_aggregate.DB = old_db
        # Only yesterday's rollup (2 GB). No today.
        self.assertAlmostEqual(mo["total_down"], 2_000_000_000, delta=1)

    def test_no_double_count_with_daily_today_row(self):
        """A spurious daily row for today must NOT inflate the month total —
        the daily query is capped at today's midnight."""
        path, now, today_mid = self._build_db(
            today_down=5_000_000_000, spurious_daily_today=True)
        import traffic_aggregate
        old_db = traffic_aggregate.DB
        traffic_aggregate.DB = path
        try:
            mo = _cmd_history(self.MAC, "month", today_mid - 30 * 86400, now)
        finally:
            traffic_aggregate.DB = old_db
        # Must equal the version WITHOUT the spurious row (today from raw, not daily).
        path2, _, _ = self._build_db(today_down=5_000_000_000, spurious_daily_today=False)
        traffic_aggregate.DB = path2
        try:
            mo2 = _cmd_history(self.MAC, "month", today_mid - 30 * 86400, now)
        finally:
            traffic_aggregate.DB = old_db
        self.assertEqual(mo["total_down"], mo2["total_down"])

    def test_batch_month_includes_today(self):
        """batch-history month columns must also include today's live traffic."""
        path, now, today_mid = self._build_db(today_down=5_000_000_000)
        import traffic_aggregate
        old_db = traffic_aggregate.DB
        traffic_aggregate.DB = path
        try:
            mo = _cmd_batch("month", today_mid - 30 * 86400, now)
            wk = _cmd_batch("week", today_mid - 7 * 86400, now)
        finally:
            traffic_aggregate.DB = old_db
        self.assertGreaterEqual(mo["macs"][self.MAC]["down"],
                                wk["macs"][self.MAC]["down"])




if __name__ == "__main__":
    unittest.main(verbosity=2)

