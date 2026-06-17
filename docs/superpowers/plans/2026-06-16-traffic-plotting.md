# Traffic Plotting Per MAC — Implementation Plan

> **Goal:** Add per-device bandwidth usage display with real-time speeds and historical charts.

**Architecture:** nft meter → python3 snapshot → SQLite `/etc/veggen/traffic.db` → Flask endpoints (ssh sqlite3) → Chart.js

## Task 1: Router deployment script (`deploy_router.py`) ✅

Generates shell setup script (idempotent, safe to rerun). User pipes output to router as root.

**Files deployed:**
- `/usr/share/veggen/nft-accounting-init.sh` — creates nft meters (called from firewall.user on reload)
- `/usr/share/veggen/parse_meters.py` — reads meters, writes to SQLite
- `/usr/share/veggen/traffic-snapshot.sh` — cron wrapper
- `/etc/cron.d/veggen-traffic` — snapshot every 15 min as `veggen`
- `/etc/firewall.user` — appends meter init hook

**Deploy:**
```bash
python3 deploy_router.py > setup.sh  # generate
ssh root@router 'sh -s' < setup.sh   # apply as root
```

## Task 2: Traffic snapshot script (router-side) ✅

Writes to SQLite `/etc/veggen/traffic.db` every 15 minutes via cron.

**Schema:**
```sql
CREATE TABLE mac_traffic (
  ts INTEGER, mac TEXT, bytes_in INTEGER, bytes_out INTEGER,
  PRIMARY KEY (ts, mac)
)
```

**Flow:** `traffic-snapshot.sh` → `parse_meters.py "$TS"` → `INSERT OR REPLACE` into SQLite

## Task 3: Real-time endpoint (`/api/traffic/summary`) ✅

**Helpers in `app.py`:**
- `_parse_meter(name)` — parses `nft list meter` output via regex
- `_read_meters()` — returns `{"up": {mac: bytes}, "down": {mac: bytes}}`
- `_traffic_delta()` — computes bytes/sec from two consecutive reads
- `_bps_str(delta, elapsed)` — formats as "X MB/s", "X KB/s", etc.

**Response:** JSON keyed by MAC with `up`, `down` (bytes during delta), `up_text`, `down_text` (formatted)

**Test:** `curl localhost:5000/api/traffic/summary`

## Task 4: History endpoint (`/api/traffic/history`) ✅

**Query:** `sqlite3 /etc/veggen/traffic.db "SELECT bucket_ts, MAX(bytes_out)-MIN(bytes_out), MAX(bytes_in)-MIN(bytes_in) FROM mac_traffic WHERE mac='...' AND ts >= ... GROUP BY bucket_ts"`

**Helpers in `app.py`:**
- `_bucket_seconds(period)` — day=3600, week=86400, month=86400, year=604800
- `_period_cutoff(period)` — cutoff timestamp for period

**Response:** `{"period", "mac", "total_up", "total_down", "avg_up_per_day", "avg_down_per_day", "buckets"}`

**Test:** `curl localhost:5000/api/traffic/history?mac=AA:BB:CC:DD:EE:FF&period=day`

**Step 3:** Commit.

## Task 5: Frontend — "Now" column

**Step 1:** Add second column header:
```html
<th style="width: 110px;">Now</th>
```

**Step 2:** Add "Now" cell to each device row:
```html
<td style="font-size: 10px;">
  <span style="color: #1565c0;">↓ <span class="down-speed">—</span></span><br>
  <span style="color: #c62828;">↑ <span class="up-speed">—</span></span>
</td>
```

**Step 3:** Add traffic summary polling:
- Every 15 seconds fetch `/api/traffic/summary`
- Update `.down-speed` and `.up-speed` by MAC

**Step 4:** Commit.

## Task 6: Frontend — Expandable detail panel

**Step 1:** Period selector pills (Day/Week/Month/Year) in detail row

**Step 2:** Stats display:
- Total down and total up for selected period
- Average per day
- Bar chart (Chart.js) of per-bucket traffic

**Step 3:** Chart.js CDN: add `<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>`

**Step 4:** On expand: fetch `/api/traffic/history?mac=X&period=day`
On period change: re-fetch with new period

**Step 5:** Commit.

## Task 7: Testing & cleanup

- Verify all nft meters work after block/unblock cycle (firewall reload)
- Verify cron creates valid JSONL entries
- Both endpoints return valid JSON
- Frontend: real-time updates, expand/collapse, period tabs
- Commit.
