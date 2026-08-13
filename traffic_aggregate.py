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
import time
import sys

DB = os.environ.get("VEGGEN_DB", "/etc/veggen/traffic.db")

BUCKET_SECONDS = {"day": 900, "week": 86400, "month": 86400, "year": 604800}

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

def _live_today_mac(db, mac, now):
    """Live delta-sum of today's raw snapshots for one MAC.

    The daily rollup table only holds *complete* previous days (the rollup
    cron runs once/day at UTC midnight). Today's traffic exists only in the
    raw snapshot table, so month/year views would miss it and report *less*
    than a week view inside the same month. This returns today's
    delta-summed totals as a single bucket keyed to today's UTC midnight.
    Returns (today_midnight, up, down) or (0, 0, 0) if no raw rows today.
    """
    today_mid = now - (now % 86400)
    rows = db.execute(
        "SELECT ts, bytes_out, bytes_in FROM mac_traffic "
        "WHERE mac = ? AND ts >= ? ORDER BY ts",
        (mac, today_mid),
    )
    raw = [(r["ts"], r["bytes_out"], r["bytes_in"]) for r in rows]
    buckets, total_up, total_down = aggregate_history_rows(raw, 86400, today_mid)
    if not buckets:
        return today_mid, 0, 0
    return today_mid, total_up, total_down


def _live_today_all_macs(db, now):
    """Live delta-sum of today's raw snapshots for ALL MACs.

    Returns {mac: {"up": int, "down": int}} for today only. Used by
    batch-history month/year views so the device-list traffic columns
    include today, not just rolled-up previous days.
    """
    today_mid = now - (now % 86400)
    rows = db.execute(
        "SELECT mac, ts, bytes_out, bytes_in FROM mac_traffic "
        "WHERE ts >= ? ORDER BY mac, ts",
        (today_mid,),
    )
    raw = [(r["mac"], r["ts"], r["bytes_out"], r["bytes_in"]) for r in rows]
    return aggregate_batch_rows(raw, today_mid)


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


def _render_buckets(agg, bucket_size, start=None, end=None):
    """Convert aggregated buckets to chart form with mbps + zero-filling.

    When start/end are given (epoch seconds, [start, end)), zero-fill across
    the full window so a partial day (today, offset 0) spans 00:00 to now on
    the x-axis rather than only first-activity to last-activity.
    """
    if not agg and start is None:
        return []
    if not agg:
        # No data in the window: fill the whole window with zeros so an empty
        # today still renders a flat line instead of an early-return blank.
        if end is None or end <= start:
            return []
        ts = (start // bucket_size) * bucket_size
        end_bucket = (end // bucket_size) * bucket_size
        filled = []
        while ts < end_bucket:
            filled.append({"ts": ts, "up": 0, "down": 0, "up_mbps": 0, "down_mbps": 0})
            ts += bucket_size
        return filled
    buckets = []
    for b in agg:
        up_mbps = round(b["up"] * 8 / bucket_size / 1_000_000, 3)
        down_mbps = round(b["down"] * 8 / bucket_size / 1_000_000, 3)
        buckets.append({"ts": b["ts"], "up": b["up"], "down": b["down"],
                        "up_mbps": up_mbps, "down_mbps": down_mbps})
    bucket_map = {b["ts"]: b for b in buckets}
    if start is not None and end is not None:
        first_ts = (start // bucket_size) * bucket_size
        end_bucket = (end // bucket_size) * bucket_size
    else:
        first_ts = buckets[0]["ts"]
        end_bucket = buckets[-1]["ts"] + bucket_size
    filled = []
    ts = first_ts
    while ts < end_bucket:
        if ts in bucket_map:
            filled.append(bucket_map[ts])
        else:
            filled.append({"ts": ts, "up": 0, "down": 0, "up_mbps": 0, "down_mbps": 0})
        ts += bucket_size
    return filled


def cmd_history(mac, period, start, end):
    """Aggregated history for one MAC over [start, end) (epoch seconds).

    The window is computed by the caller (app.py) in the browser's local
    time so that "today" aligns to the user's midnight — not the router's
    UTC-internal clock. The router only filters and aggregates.
    """
    bucket_size = BUCKET_SECONDS[period]

    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    if period in RAW_PERIODS:
        rows = db.execute(
            "SELECT ts, bytes_out, bytes_in FROM mac_traffic "
            "WHERE mac = ? AND ts >= ? AND ts < ? ORDER BY ts",
            (mac, start, end),
        )
        raw = [(r["ts"], r["bytes_out"], r["bytes_in"]) for r in rows]
        agg, total_up, total_down = aggregate_history_rows(raw, bucket_size, start)
    else:
        now = int(time.time())
        today_mid = now - (now % 86400)
        # The daily rollup only holds complete previous days; today's traffic
        # lives only in the raw snapshot table. Cap the daily query at today's
        # midnight so a late/early rollup row for today can't double-count
        # with the live-today merge below.
        daily_end = min(end, today_mid)
        rows = db.execute(
            "SELECT day, bytes_out, bytes_in FROM mac_traffic_daily "
            "WHERE mac = ? AND day >= ? AND day < ? ORDER BY day",
            (mac, start, daily_end),
        )
        raw = [(r["day"], r["bytes_out"], r["bytes_in"]) for r in rows]
        agg, total_up, total_down = aggregate_daily_rows(raw, bucket_size)
        # Merge today's live delta-sum from raw snapshots so month/year views
        # include today and never report less than a week view in the same month.
        t_up, t_down = 0, 0
        if today_mid < end:
            _, t_up, t_down = _live_today_mac(db, mac, now)
        if (t_up or t_down) and start <= today_mid < end:
            agg.append({"ts": today_mid, "up": t_up, "down": t_down})
            total_up += t_up
            total_down += t_down

    buckets = _render_buckets(agg, bucket_size, start, end)
    if not buckets:
        return {"period": period, "mac": mac, "total_up": 0, "total_down": 0,
                "avg_up_per_day": 0, "avg_down_per_day": 0, "buckets": []}

    span_seconds = end - start
    span_days = max(span_seconds / 86400, 1)
    return {
        "period": period,
        "mac": mac,
        "total_up": total_up,
        "total_down": total_down,
        "avg_up_per_day": int(total_up / span_days),
        "avg_down_per_day": int(total_down / span_days),
        "buckets": buckets,
    }


def cmd_batch(period, start, end):
    """Per-MAC traffic totals over [start, end) (epoch seconds)."""
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    if period in RAW_PERIODS:
        rows = db.execute(
            "SELECT mac, ts, bytes_out, bytes_in FROM mac_traffic "
            "WHERE ts >= ? AND ts < ? ORDER BY mac, ts",
            (start, end),
        )
        raw = [(r["mac"], r["ts"], r["bytes_out"], r["bytes_in"]) for r in rows]
        macs = aggregate_batch_rows(raw, start)
    else:
        now = int(time.time())
        today_mid = now - (now % 86400)
        # Cap the daily query at today's midnight so a rollup row for today
        # can't double-count with the live-today merge below.
        daily_end = min(end, today_mid)
        rows = db.execute(
            "SELECT mac, day, bytes_out, bytes_in FROM mac_traffic_daily "
            "WHERE day >= ? AND day < ? ORDER BY mac, day",
            (start, daily_end),
        )
        totals = {}
        for mac, day, out, inb in rows:
            t = totals.setdefault(mac, {"up": 0, "down": 0})
            t["up"] += out
            t["down"] += inb
        macs = totals
        # The daily rollup misses today (only complete previous days are
        # rolled up). Merge today's live raw delta-sum so the device-list
        # traffic columns include today.
        if today_mid < end:
            for mac, t in _live_today_all_macs(db, now).items():
                dt = macs.setdefault(mac, {"up": 0, "down": 0})
                dt["up"] += t["up"]
                dt["down"] += t["down"]
    db.close()

    return {"period": period, "macs": macs}
def _iface_names():
    """Map device name -> logical interface name.

    Reads /etc/veggen/iface_names.json, written by the root-run snapshot
    cron (ubus call network.interface dump -> {device: "wan"}). The veggen
    user can't reach ubus or /etc/config/network directly, so the snapshot
    script dumps the mapping to a world-readable file. Returns {} if the
    file is missing or unreadable (interfaces keep their raw kernel name).
    """
    try:
        with open("/etc/veggen/iface_names.json") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def cmd_interfaces():
    """List all network interfaces with their synthetic MACs and friendly names.

    Reads the iface_mac mapping table written by parse_nlbwmon.py. Resolves
    logical names (wan/lan/guest/etc.) from /etc/veggen/iface_names.json,
    dumped by the root-run snapshot cron. Returns [{iface, mac, name}]
    sorted by interface name. 'name' is the friendly label when mapped,
    else the raw iface.
    """
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    rows = db.execute("SELECT iface, mac FROM iface_mac ORDER BY iface").fetchall()
    db.close()
    dev_names = _iface_names()
    result = []
    for r in rows:
        iface = r["iface"]
        result.append({
            "iface": iface,
            "mac": r["mac"],
            "name": dev_names.get(iface, iface),
        })
    return result


def main():
    parser = argparse.ArgumentParser(description="Veggen traffic aggregation")
    sub = parser.add_subparsers(dest="mode", required=True)

    h = sub.add_parser("history")
    h.add_argument("--mac", required=True)
    h.add_argument("--period", required=True, choices=sorted(BUCKET_SECONDS))
    h.add_argument("--start", required=True, type=int)
    h.add_argument("--end", required=True, type=int)

    b = sub.add_parser("batch")
    b.add_argument("--period", required=True, choices=sorted(BUCKET_SECONDS))
    b.add_argument("--start", required=True, type=int)
    b.add_argument("--end", required=True, type=int)

    sub.add_parser("interfaces")

    args = parser.parse_args()

    if args.mode == "history":
        result = cmd_history(args.mac, args.period, args.start, args.end)
    elif args.mode == "batch":
        result = cmd_batch(args.period, args.start, args.end)
    else:
        result = cmd_interfaces()

    json.dump(result, sys.stdout)
    print()


if __name__ == "__main__":
    main()
