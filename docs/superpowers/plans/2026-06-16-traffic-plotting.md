# Traffic Plotting Per MAC — Implementation Plan

> **Goal:** Add per-device bandwidth usage display with real-time speeds and historical charts.

**Architecture:** nft meter → cron snapshot to `/etc/veggen/traffic.jsonl` → Flask endpoints → Chart.js

## Task 1: Router deployment script (`deploy_router.py`)

Creates nft meters, snapshot cron, firewall persistence.

**Step 1:** Create `deploy_router.py`:
- Uses `base64` encode to write remote files safely via SSH
- Deploys: `/usr/share/veggen/nft-accounting-init.sh`, `/usr/share/veggen/traffic-snapshot.sh`
- Updates: `/etc/firewall.user`, `/etc/cron.d/veggen-traffic`
- Idempotent — safe to rerun
- Uses same `VEGGEN_ROUTER_IP` and `VEGGEN_SSH_USER` env vars as `app.py`

**Step 2:** Test: `python3 deploy_router.py`
Verify: `ssh veggen@192.168.0.1 "nft list table inet fw4"` shows meters.

**Step 3:** Commit.

## Task 2: Traffic snapshot script (router-side)

Writes JSON line to `/etc/veggen/traffic.jsonl` every 15 minutes.

**Step 1:** The snapshot script:
- Queries both nft meters via `nft list meter`
- Parses MAC+bytes with python3 inline heredoc (avoids shell complexity)
- Appends to `/etc/veggen/traffic.jsonl`
- Format: `{"ts": 12345, "data": {"aa:bb:...": {"in": 123, "out": 456}}}`
- The snapshot script is defined as a Python string constant in `deploy_router.py` named `SNAPSHOT`. It uses the pattern:
```sh
#!/bin/sh
TS=$(date +%s)
mkdir -p /etc/veggen
/tmp/veggen_parse_meters.py "$TS" >> /etc/veggen/traffic.jsonl
```
- A companion script `/tmp/veggen_parse_meters.py` runs via python3:
```python
import json, re, subprocess, sys

def parse(cmd):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout
    return {m.group(1): int(m.group(2)) for m in re.finditer(r'([0-9a-f:]+)\s+counter packets \d+ bytes (\d+)', r) if m.group(1) != 'ff:ff:ff:ff:ff:ff'}

ts = int(sys.argv[1])
out = parse('nft list meter inet fw4 mac_outbound_traffic 2>/dev/null')
inf = parse('nft list meter inet fw4 mac_inbound_traffic 2>/dev/null')
merged = {}
for mac in set(out) | set(inf):
    merged[mac] = {"in": inf.get(mac, 0), "out": out.get(mac, 0)}
print(json.dumps({"ts": ts, "data": merged}))
```

**Step 2:** Deploy and verify: wait 15 min or run manually, check JSONL content.

**Step 3:** Commit.

## Task 3: Real-time endpoint (`/api/traffic/summary`)

**Step 1:** Add to `app.py`:
- `_parse_meter(name)` — parses `nft list meter` output via regex
- `_read_meters()` — returns `{"out": {mac: bytes}, "in": {mac: bytes}}`
- `_traffic_delta()` — computes bytes/sec from two consecutive reads
- `_bps_str(bps)` — formats as "X MB/s", "X KB/s", etc.
- Route: returns JSON keyed by MAC with `up`, `down`, `up_text`, `down_text`

**Step 2:** Test: `curl localhost:5000/api/traffic/summary`

**Step 3:** Commit.

## Task 4: History endpoint (`/api/traffic/history`)

**Step 1:** Add to `app.py`:
- `_bucket_seconds(period)` — returns bucket duration: day=3600, week=86400, month=86400, year=604800
- `_period_window(period)` — returns cutoff timestamp for period: day-1h, week-1w, month-30d, year-365d
- Route: `/api/traffic/history` with `mac` and `period` query params
- Implementation:
```python
raw = run_ssh_command("cat /etc/veggen/traffic.jsonl 2>/dev/null")
# Parse each line, filter to entries >= cutoff, delta-consecutive snapshots, bucket by period
```
- Response shape: `{"period": ..., "total_up": ..., "total_down": ..., "avg_up_per_day": ..., "avg_down_per_day": ..., "buckets": [{"ts": ..., "up": ..., "down": ...}]}`

**Step 2:** Test: `curl localhost:5000/api/traffic/history?mac=aa:bb:cc:dd:ee:ff&period=week`

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
