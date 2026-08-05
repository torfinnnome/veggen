#!/usr/bin/env python3
"""Router-side traffic aggregation for Veggen.

Runs on the OpenWrt router. Reads the raw snapshot table (mac_traffic) from
SQLite and outputs only the aggregated data the Veggen frontend renders, so the
app never transfers millions of raw rows over SSH.

Usage:
    python3 traffic_aggregate.py history --mac aa:bb:cc:dd:ee:ff --period day
    python3 traffic_aggregate.py batch --period week

Output is a single JSON object on stdout. Mirrors the aggregation logic in
app.py (_aggregate_history_rows / _aggregate_batch_rows) so results are
identical regardless of where they run.
"""

import argparse
import json
import os
import sqlite3
import sys
import time

DB = os.environ.get("VEGGEN_DB", "/etc/veggen/traffic.db")

BUCKET_SECONDS = {"day": 900, "week": 86400, "month": 86400, "year": 604800}
PERIOD_SECONDS = {
    "day": 86400,
    "week": 604800,
    "month": 2592000,
    "year": 31536000,
}


def period_cutoff(period):
    return time.time() - PERIOD_SECONDS[period]


def aggregate_history_rows(rows, bucket_size, cutoff):
    """Per-bucket traffic totals via consecutive-delta sums.

    rows: iterable of (ts, bytes_out, bytes_in) ordered by ts ascending.
    Returns (buckets, total_up, total_down). See app.py for semantics.
    """
    bucket_up = {}
    bucket_down = {}
    total_up = 0
    total_down = 0
    prev_ts = None
    prev_out = None
    prev_in = None
    for ts, out, inb in rows:
        if prev_ts is not None and prev_ts >= cutoff:
            d_out = out - prev_out
            d_in = inb - prev_in
            if d_out < 0:
                d_out = 0
            if d_in < 0:
                d_in = 0
            b = (prev_ts // bucket_size) * bucket_size
            bucket_up[b] = bucket_up.get(b, 0) + d_out
            bucket_down[b] = bucket_down.get(b, 0) + d_in
            total_up += d_out
            total_down += d_in
        prev_ts = ts
        prev_out = out
        prev_in = inb

    buckets = [
        {"ts": b, "up": bucket_up.get(b, 0), "down": bucket_down.get(b, 0)}
        for b in sorted(set(bucket_up) | set(bucket_down))
    ]
    return buckets, total_up, total_down


def aggregate_batch_rows(rows, cutoff):
    """Per-MAC traffic totals via consecutive-delta sums.

    rows: iterable of (mac, ts, bytes_out, bytes_in) ordered by mac, then ts.
    Returns {mac: {"up": int, "down": int}}.
    """
    totals = {}
    prev_mac = None
    prev_ts = None
    prev_out = None
    prev_in = None
    for mac, ts, out, inb in rows:
        if mac != prev_mac:
            prev_mac, prev_ts, prev_out, prev_in = mac, ts, out, inb
            continue
        if prev_ts >= cutoff:
            d_out = out - prev_out
            d_in = inb - prev_in
            if d_out < 0:
                d_out = 0
            if d_in < 0:
                d_in = 0
            t = totals.setdefault(mac, {"up": 0, "down": 0})
            t["up"] += d_out
            t["down"] += d_in
        prev_ts, prev_out, prev_in = ts, out, inb
    return totals


# Periods whose cutoff stays within the raw 5-min retention window (14 days)
# are served from the raw snapshot table. Longer periods (month/year) are
# served from the daily rollup table, which keeps one row per MAC per day
# indefinitely. Daily rows are absolute per-day totals, so no delta math is
# needed for them — they map directly into buckets.
RAW_PERIODS = {"day", "week"}
DAILY_PERIODS = {"month", "year"}


def aggregate_daily_rows(rows, bucket_size):
    """Sum daily rollup rows into buckets.

    rows: iterable of (day_ts, bytes_out, bytes_in) where day_ts is the UTC
    midnight of each day. Returns (buckets, total_up, total_down).
    """
    bucket_up = {}
    bucket_down = {}
    total_up = 0
    total_down = 0
    for day_ts, out, inb in rows:
        b = (day_ts // bucket_size) * bucket_size
        bucket_up[b] = bucket_up.get(b, 0) + out
        bucket_down[b] = bucket_down.get(b, 0) + inb
        total_up += out
        total_down += inb
    buckets = [
        {"ts": b, "up": bucket_up.get(b, 0), "down": bucket_down.get(b, 0)}
        for b in sorted(set(bucket_up) | set(bucket_down))
    ]
    return buckets, total_up, total_down


def _render_buckets(agg, bucket_size):
    """Convert aggregated buckets to chart form with mbps + zero-filling."""
    if not agg:
        return []
    buckets = []
    for b in agg:
        up_mbps = round(b["up"] * 8 / bucket_size / 1_000_000, 3)
        down_mbps = round(b["down"] * 8 / bucket_size / 1_000_000, 3)
        buckets.append({"ts": b["ts"], "up": b["up"], "down": b["down"],
                        "up_mbps": up_mbps, "down_mbps": down_mbps})
    first_ts = buckets[0]["ts"]
    last_ts = buckets[-1]["ts"]
    bucket_map = {b["ts"]: b for b in buckets}
    filled = []
    ts = first_ts
    while ts <= last_ts:
        if ts in bucket_map:
            filled.append(bucket_map[ts])
        else:
            filled.append({"ts": ts, "up": 0, "down": 0, "up_mbps": 0, "down_mbps": 0})
        ts += bucket_size
    return filled


def cmd_history(mac, period):
    cutoff = int(period_cutoff(period))
    bucket_size = BUCKET_SECONDS[period]

    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    if period in RAW_PERIODS:
        rows = db.execute(
            "SELECT ts, bytes_out, bytes_in FROM mac_traffic "
            "WHERE mac = ? AND ts >= ? ORDER BY ts",
            (mac, cutoff),
        )
        raw = [(r["ts"], r["bytes_out"], r["bytes_in"]) for r in rows]
        agg, total_up, total_down = aggregate_history_rows(raw, bucket_size, cutoff)
    else:
        rows = db.execute(
            "SELECT day, bytes_out, bytes_in FROM mac_traffic_daily "
            "WHERE mac = ? AND day >= ? ORDER BY day",
            (mac, cutoff),
        )
        raw = [(r["day"], r["bytes_out"], r["bytes_in"]) for r in rows]
        agg, total_up, total_down = aggregate_daily_rows(raw, bucket_size)
    db.close()

    buckets = _render_buckets(agg, bucket_size)
    if not buckets:
        return {"period": period, "mac": mac, "total_up": 0, "total_down": 0,
                "avg_up_per_day": 0, "avg_down_per_day": 0, "buckets": []}

    first_ts = buckets[0]["ts"]
    last_ts = buckets[-1]["ts"]
    span_days = max((last_ts - first_ts) / 86400, 1)
    return {
        "period": period,
        "mac": mac,
        "total_up": total_up,
        "total_down": total_down,
        "avg_up_per_day": int(total_up / span_days),
        "avg_down_per_day": int(total_down / span_days),
        "buckets": buckets,
    }


def cmd_batch(period):
    cutoff = int(period_cutoff(period))

    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    if period in RAW_PERIODS:
        rows = db.execute(
            "SELECT mac, ts, bytes_out, bytes_in FROM mac_traffic "
            "WHERE ts >= ? ORDER BY mac, ts",
            (cutoff,),
        )
        raw = [(r["mac"], r["ts"], r["bytes_out"], r["bytes_in"]) for r in rows]
        macs = aggregate_batch_rows(raw, cutoff)
    else:
        rows = db.execute(
            "SELECT mac, day, bytes_out, bytes_in FROM mac_traffic_daily "
            "WHERE day >= ? ORDER BY mac, day",
            (cutoff,),
        )
        totals = {}
        for mac, day, out, inb in rows:
            t = totals.setdefault(mac, {"up": 0, "down": 0})
            t["up"] += out
            t["down"] += inb
        macs = totals
    db.close()

    return {"period": period, "macs": macs}


def main():
    parser = argparse.ArgumentParser(description="Veggen traffic aggregation")
    sub = parser.add_subparsers(dest="mode", required=True)

    h = sub.add_parser("history")
    h.add_argument("--mac", required=True)
    h.add_argument("--period", required=True, choices=sorted(BUCKET_SECONDS))

    b = sub.add_parser("batch")
    b.add_argument("--period", required=True, choices=sorted(BUCKET_SECONDS))

    args = parser.parse_args()

    if args.mode == "history":
        result = cmd_history(args.mac, args.period)
    else:
        result = cmd_batch(args.period)

    json.dump(result, sys.stdout)
    print()


if __name__ == "__main__":
    main()
