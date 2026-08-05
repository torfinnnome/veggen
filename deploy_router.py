#!/usr/bin/env python3
"""Generate setup commands for nlbwmon-based traffic accounting on OpenWrt router.

Run: python3 deploy_router.py > setup.sh
Then pipe to router: ssh root@router 'sh -s' < setup.sh

Uses nlbwmon (conntrack-based) instead of nft meters because nft meters in the
forward chain do not count traffic that is offloaded via the kernel flowtable
(software flow offload). nlbwmon reads conntrack counters, which the flowtable
synchronizes when the flowtable definition includes the `counter` statement
(fw4 default since OpenWrt 23.05.0). Requires software-only offload
(flow_offloading_hw=0); hardware offload bypasses conntrack counters entirely.
"""

import os


# ── Embedded router file contents ──────────────────────────────────────

# Reads cumulative per-MAC byte totals from the nlbwmon daemon and writes them
# into the same SQLite schema the app expects (mac_traffic). nlbwmon's counters
# are cumulative within the current accounting period (monthly by default), so
# the app's consecutive-delta aggregation works unchanged; resets at period
# rollover or daemon restart are handled by the app's max(curr - prev, 0).
PARSE_NLBWMON_PY = r"""import csv
import io
import sqlite3
import subprocess
import sys

# nlbw -c csv -g mac -o mac -q emits tab-separated rows:
#   mac  conns  rx_bytes  rx_pkts  tx_bytes  tx_pkts
# rx_bytes = traffic received by the host (download), tx_bytes = transmitted
# by the host (upload). The zero MAC marks unresolved/unknown hosts.
CMD = '/usr/sbin/nlbw -c csv -g mac -o mac -q 2>/dev/null'

def parse():
    stdout = subprocess.run(CMD, shell=True, capture_output=True, text=True).stdout
    rows = {}
    reader = csv.DictReader(io.StringIO(stdout), delimiter='\t')
    for row in reader:
        mac = (row.get('mac') or '').strip().lower()
        if not mac or mac == '00:00:00:00:00:00':
            continue
        try:
            rows[mac] = (int(row['rx_bytes']), int(row['tx_bytes']))
        except (KeyError, ValueError):
            continue
    return rows

ts = int(sys.argv[1])
data = parse()

db = sqlite3.connect('/etc/veggen/traffic.db')
cur = db.cursor()
cur.execute(
    'CREATE TABLE IF NOT EXISTS mac_traffic ('
    'ts INTEGER, mac TEXT, bytes_in INTEGER, bytes_out INTEGER, '
    'PRIMARY KEY (ts, mac))'
)
cur.execute('CREATE INDEX IF NOT EXISTS idx_mac_ts ON mac_traffic(mac, ts)')
for mac, (rx, tx) in data.items():
    cur.execute(
        'INSERT OR REPLACE INTO mac_traffic (ts, mac, bytes_in, bytes_out) VALUES (?, ?, ?, ?)',
        (ts, mac, rx, tx),
    )
db.commit()
db.close()
"""

SNAPSHOT_SH = r"""#!/bin/sh
TS=$(date +%s)
mkdir -p /etc/veggen
python3 /usr/share/veggen/parse_nlbwmon.py "$TS"

# Two-tier retention, run once per day:
#   1. Roll up the previous day's raw 5-min snapshots into per-MAC daily
#      totals (mac_traffic_daily), so per-day stats survive indefinitely.
#   2. Delete raw snapshots older than the retention window (default 14 days).
# The aggregation is cumulative-delta based, so the rollup must run before the
# raw rows are pruned (it needs consecutive raw rows to compute deltas).
RETENTION_SECONDS="${VEGGEN_RETENTION_SECONDS:-1209600}"
MARKER=/etc/veggen/.pruned-day
TODAY=$(date +%Y-%m-%d)
if [ "$(cat "$MARKER" 2>/dev/null)" != "$TODAY" ]; then
    python3 - "$RETENTION_SECONDS" <<'PYEOF'
import sqlite3
import sys
import time

retention = int(sys.argv[1])
now = int(time.time())
cutoff = now - retention

# Day boundary (UTC midnight) of the previous day: roll up everything strictly
# before today's midnight, so a day is complete before it is aggregated.
today_midnight = now - (now % 86400)
prev_day_start = today_midnight - 86400

# Ensure the daily table exists (idempotent; parse_nlbwmon creates the raw one).
db = sqlite3.connect('/etc/veggen/traffic.db')
cur = db.cursor()
cur.execute(
    'CREATE TABLE IF NOT EXISTS mac_traffic_daily ('
    'day INTEGER, mac TEXT, bytes_in INTEGER, bytes_out INTEGER, '
    'PRIMARY KEY (day, mac))'
)

# Roll up each complete previous day that has raw rows but no daily row yet.
# For each MAC, consecutive-delta sums over the day's raw rows (same clamping
# as the app's aggregation) give that day's bytes. Iterate from the previous
# day back to the oldest day with raw data, so nothing is lost when raw rows
# are pruned (including on first deploy, when history predates the window).
oldest = cur.execute('SELECT MIN(ts) FROM mac_traffic').fetchone()[0]
oldest_day = (oldest // 86400) * 86400 if oldest is not None else prev_day_start
for day_start in range(prev_day_start, oldest_day - 1, -86400):
    day_end = day_start + 86400
    cur.execute(
        'SELECT COUNT(*) FROM mac_traffic_daily WHERE day = ?', (day_start,)
    )
    if cur.fetchone()[0] > 0:
        continue
    rows = cur.execute(
        'SELECT mac, ts, bytes_out, bytes_in FROM mac_traffic '
        'WHERE ts >= ? AND ts < ? ORDER BY mac, ts',
        (day_start, day_end),
    ).fetchall()
    if not rows:
        continue
    totals = {}
    prev_mac = None
    prev_ts = None
    prev_out = None
    prev_in = None
    for mac, ts, out, inb in rows:
        if mac == prev_mac and prev_ts is not None:
            d_out = out - prev_out
            d_in = inb - prev_in
            if d_out < 0:
                d_out = 0
            if d_in < 0:
                d_in = 0
            t = totals.setdefault(mac, [0, 0])
            t[0] += d_out
            t[1] += d_in
        prev_mac, prev_ts, prev_out, prev_in = mac, ts, out, inb
    for mac, (out, inb) in totals.items():
        cur.execute(
            'INSERT OR REPLACE INTO mac_traffic_daily '
            '(day, mac, bytes_in, bytes_out) VALUES (?, ?, ?, ?)',
            (day_start, mac, inb, out),
        )

db.commit()

# Prune raw snapshots older than the retention window.
cur.execute('DELETE FROM mac_traffic WHERE ts < ?', (cutoff,))
db.commit()
# Reclaim free pages so the file shrinks instead of just marking rows dead.
cur.execute('VACUUM')
db.close()
PYEOF
    echo "$TODAY" > "$MARKER"
fi
"""

CRON_ENTRY = "*/5 * * * * /usr/share/veggen/traffic-snapshot.sh"

# nlbwmon config: ensure the LAN subnet is monitored. The default package
# config already lists 'lan', but we append it idempotently so the setup works
# even if the config was customized.
NLBWMON_CONFIG = """
config nlbwmon
	option commit_interval '24h'
	option refresh_interval '30s'
	option database_directory '/var/lib/nlbwmon'
	option database_generations '10'
	option database_interval '1'
	option database_limit '10000'
	option protocol_database '/usr/share/nlbwmon/protocols'
	list local_network 'lan'
"""


def _load_traffic_aggregate():
    """Read the router-side aggregation helper from the repo."""
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "traffic_aggregate.py")) as f:
        return f.read()


def heredoc(path, content, chmod=None):
    """Return heredoc commands to write content to path."""
    dirn = path.rsplit("/", 1)[0]
    lines = [
        f"mkdir -p '{dirn}'",
        f"cat > '{path}' <<'EOF'",
        content.rstrip(),
        "EOF",
    ]
    if chmod:
        lines.append(f"chmod {chmod} {path}")
    return "\n".join(lines)


def _append_if_missing(marker, path, content):
    """Append content if marker not found. _FW_EOF must be at column 0."""
    lines = [
        f"if ! grep -q {marker} {path} 2>/dev/null; then",
        f"cat >> {path} <<'_FW_EOF'",
        content.rstrip(),
        "_FW_EOF",
        "fi",
    ]
    return "\n".join(lines)


def generate():
    """Generate setup commands."""
    blocks = [
        "#!/bin/sh",
        "# Veggen traffic accounting setup (nlbwmon) — run as root on router",
        "",
        "# 1. Install nlbwmon",
        "opkg update",
        "opkg install nlbwmon",
        "",
        "# 2. Create data directory",
        "mkdir -p /etc/veggen",
        "chown veggen:veggen /etc/veggen",
        "",
        "# 3. Configure nlbwmon to monitor the LAN subnet",
        heredoc("/etc/config/nlbwmon", NLBWMON_CONFIG),
        "",
        "# 4. Start nlbwmon daemon",
        "/etc/init.d/nlbwmon enable",
        "/etc/init.d/nlbwmon restart",
        "",
        "# 5. Deploy scripts",
        heredoc("/usr/share/veggen/parse_nlbwmon.py", PARSE_NLBWMON_PY, "+r"),
        "",
        heredoc("/usr/share/veggen/traffic-snapshot.sh", SNAPSHOT_SH, "+rx"),
        "",
        heredoc("/usr/share/veggen/traffic_aggregate.py", _load_traffic_aggregate(), "+r"),
        "",
        "# 6. Install cron job (append to /etc/crontabs/root, idempotent)",
        _append_if_missing(
            '"veggen-traffic-snapshot"',
            "/etc/crontabs/root",
            f"# veggen-traffic-snapshot\n{CRON_ENTRY}\n",
        ),
        "",
        "# 7. Remove obsolete nft accounting table (migration from nft meters)",
        "/usr/sbin/nft delete table inet veggen 2>/dev/null || true",
        "",
        "# 8. Remove obsolete firewall persistence hook",
        "sed -i '/# veggen-traffic-accounting/d' /etc/firewall.user 2>/dev/null || true",
        "",
        '# Done',
        'echo "Veggen traffic accounting setup (nlbwmon) complete."',
    ]
    return "\n".join(blocks)


if __name__ == "__main__":
    print(generate())
