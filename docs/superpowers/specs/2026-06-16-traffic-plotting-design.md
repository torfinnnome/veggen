# Traffic Plotting Per MAC Address

## Problem

Veggen currently tracks device block/unblock state but has no visibility into per-device bandwidth usage. Adding traffic data helps understand which devices use the most bandwidth.

## Constraints

- OpenWrt router uses fw4/nftables (no iptables).
- nftable rules are lost on firewall reload (which happens on every block/unblock action).
- Per-host accounting module (`xt_ACCOUNT`) is **not** available on this router.
- Router has collectd/rrdtool installed but only collects system metrics, not per-host data.

## Architecture

Two layers:

1. **Router side** (OpenWrt): nftables meter + cron snapshot, no extra daemons.
2. **App side** (Flask): reads router data via SSH, aggregates, serves to frontend.

```
nft meter (live counters) → /usr/share/veggen/traffic-snapshot.sh → /var/run/veggen-traffic.jsonl (router)
                                                                         ↓ SSH
app.py → /api/traffic/summary (real-time) + /api/traffic/history (aggregated)
                                                                         ↓
index.html → compact row + expandable chart panel
```

## Router-Side Components

### 1. nftables Meter Rules

A single nftables meter in the `inet fw4` table creates per-MAC counters automatically:

```nft
meter mac_outbound_traffic { ether saddr counter } 
meter mac_inbound_traffic { ether daddr counter }
```

Inserted into the main `forward` chain **before** any zone jump:

```nft
iifname { "br-lan", "wt0" } meter mac_outbound_traffic { ether saddr counter }
oifname { "br-lan", "wt0" } meter mac_inbound_traffic { ether daddr counter }
```

This tracks outbound (source MAC) and inbound (destination MAC) traffic for all LAN devices. The meter auto-populates as packets match — no per-MAC config needed.

Data is tracked for:
- All LAN devices (not just `veggen-` prefixed), filtered server-side.
- Both directions: bytes up, bytes down.
- Real-time — counters accumulate since meter creation.

### 2. Firewall Persistence

A script `/usr/share/veggen/nft-accounting-init.sh` runs on every firewall start to recreate the meters. It's invoked via `/etc/firewall.user`, which fw4 sources automatically on start and reload.

If the script runs after rules are applied, it inserts meter rules into the `forward` chain at the correct position so traffic is captured before zone rules consume it.

### 3. Cron Snapshot

A cron entry `/etc/cron.d/veggen-traffic` runs every 15 minutes. It executes `/usr/share/veggen/traffic-snapshot.sh`, which:

1. Queries both nft meters via `nft list meter inet fw4 <name>`
2. Outputs a JSON line: `{ "ts": 1234567890, "data": { "aa:bb:cc:dd:ee:ff": { "in": 123456789, "out": 987654321 }, ... } }`
3. Appends to `/var/run/veggen-traffic.jsonl`
4. If entry count exceeds 100,000 (~3 months), rotate: truncate to last 100,000 entries

Data lifecycle:
- Every 15 minutes: 96 entries/day
- Per entry: ~2 KB (all LAN MACs)
- Monthly storage: ~6 MB
- File is truncated when entries exceed 100,000 (~3 months, ~250 MB on flash storage)
- If storage is limited, reduce rotation threshold and accept that "Year" may not fill completely

### 4. Router Setup Script

A Python script `deploy_router.py` deploys all router-side components via SSH using the existing `ssh` mechanism. It:
1. Creates `/usr/share/veggen/` directory
2. Writes `nft-accounting-init.sh` to `/usr/share/veggen/`
3. Writes `traffic-snapshot.sh` to `/usr/share/veggen/`
4. Creates/updates `/etc/firewall.user`
5. Creates `/etc/cron.d/veggen-traffic`
6. Runs init script immediately

It's idempotent — safe to rerun.

## App-Side Backend

### New API Endpoints

**`GET /api/traffic/summary`** — Returns real-time speed for each managed device.
- Queries nft meters via SSH (single SSH call fetches both meters).
- Compares current reading to previous reading (15-second interval stored in memory).
- Returns bytes/sec up/down per MAC address.
- Only includes devices returned by `get_devices()`.

Response shape:
```json
{
  "aa:bb:cc:dd:ee:01": { "up": 122880, "down": 2411520, "up_text": "120 KB/s", "down_text": "2.3 MB/s" },
  ...
}
```

**`GET /api/traffic/history?mac=AA:BB:CC:DD:EE:01&period=day`** — Returns aggregated history for a single device.
- `period` is one of: `day`, `week`, `month`, `year`.
- Fetches `/var/run/veggen-traffic.jsonl` from the router via SSH.
- Filters to the requested MAC and time window.
- Delta-calculates bytes between consecutive snapshots.
- Aggregates into time buckets (hourly for `day`, daily for `week`/`month`).
- Returns cumulative totals and per-bucket breakdown.

Response shape:
```json
{
  "period": "week",
  "mac": "aa:bb:cc:dd:ee:01",
  "total_up": 419430400,
  "total_down": 2254857830,
  "avg_up_per_day": 59918628,
  "avg_down_per_day": 322122547,
  "buckets": [
    { "ts": 1781642400, "up": 123456, "down": 987654 },
    ...
  ]
}
```

### Existing Changes

- `run_ssh_command` gains an optional `multi_line=True` mode for returning multi-line output without truncation (or the existing function is reused with appropriate output parsing).

## Frontend

### Layout Changes to `index.html`

1. **Add "Now" column** — Between "Device" and "Status". Shows real-time `↓ X MB/s` / `↑ Y KB/s`. Updated every 15 seconds.

2. **Expandable detail panel** — Click the device name row to expand. Shows:
   - Period selector: Day / Week / Month / Year (toggleable pills).
   - Total up and down for selected period, with daily average.
   - Bar chart rendering per-bucket up/down traffic.
   - Up uses a blue fill, down uses a red fill.

3. **Chart** — Uses Chart.js via CDN for the bar chart. One call per expand (data is not auto-refreshed in the panel; user can collapse/expand to refresh).

### Data Flow

- Every 15 seconds: fetch `/api/traffic/summary` → update "Now" column.
- On expand: fetch `/api/traffic/history?mac=X&period=day` → render detail panel.
- Period selector toggles: re-fetch for selected period.

## Error Handling

- If the router's nft meters are missing (not yet deployed), `/api/traffic/summary` returns an empty object — frontend shows "—" for all devices.
- If the snapshot is malformed, the endpoint logs a warning and returns an error to the frontend.
- SSH failures are handled by the existing `run_ssh_command` error handling (returns empty string).
- Frontend handles missing data gracefully: "—" for real-time speeds, "No data yet" for charts.

## Testing

- Router setup: verify `nft list meter` returns populated counters after any traffic flows.
- Cron: verify `/var/run/veggen-traffic.jsonl` grows with valid JSON lines every 15 minutes.
- API: `curl` both endpoints and verify JSON structure.
- Frontend: verify "Now" updates, expand/collapse, period selector.
