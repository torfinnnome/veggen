# All Hosts View — Design

> **Goal:** Show all network hosts (static + dynamic) alongside managed devices, with clickable traffic speeds to open charts.

## Navigation

Tab bar at top of page:
```
[Managed] [All Hosts]
```

- "Managed" is the existing view (veggen- devices grouped by kid, with block toggles)
- "All Hosts" shows every host on the network with traffic data
- Default tab: "Managed"

## All Hosts Table

Columns: Device | IP | MAC | Now

- Name from static DHCP (`uci show dhcp`), or "unknown" if only in dynamic leases
- "Now" (↓/↑ speeds) only shown for hosts that have traffic data in the meters
- Clicking ↓ or ↑ opens the same chart detail panel as the managed view

## API — `/api/all-hosts`

New endpoint that returns `[{name, ip, mac}]`:

1. Fetch static hosts: `uci show dhcp` (parse name, ip, mac)
2. Fetch dynamic leases: `cat /tmp/dhcp.leases` (parse ip, mac, name)
3. Deduplicate by MAC — static name wins, dynamic fills in missing hosts
4. Return combined list

No block status, no action columns.

## Frontend Changes

- Tab bar HTML + CSS in `index.html`
- `fetchAllHosts()` — calls `/api/all-hosts`, renders table
- On page load: fetch both `/api/devices` and `/api/all-hosts`
- Clicking speed text (↓/↑) calls `toggleDetail(dev)` — same chart logic as managed
- Tab switch toggles `display:none` on each table

## No Changes

- Traffic accounting backend (nft meters, SQLite, cron) — unchanged
- `/api/traffic/summary` and `/api/traffic/history` — unchanged
- Managed tab behavior — unchanged
