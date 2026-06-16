#!/usr/bin/env python3
"""Deploy nft traffic accounting to the OpenWrt router."""

import base64
import os
import subprocess

ROUTER_IP = os.environ.get("VEGGEN_ROUTER_IP", "192.168.0.1")
SSH_USER = os.environ.get("VEGGEN_SSH_USER", "veggen")


def run_ssh(cmd):
    """Run command on router via SSH."""
    result = subprocess.run(
        ["ssh", f"{SSH_USER}@{ROUTER_IP}", cmd],
        capture_output=True, text=True, timeout=15,
    )
    return result.stdout


def _write_file(remote_path, content):
    """Write file to router via SSH using base64 encoding."""
    b64 = base64.b64encode(content.encode()).decode()
    dirname = os.path.dirname(remote_path)
    run_ssh(
        f"sudo mkdir -p {dirname} && "
        f'echo "{b64}" | base64 -d | sudo tee {remote_path} >/dev/null'
    )


# ── Embedded router file contents ──────────────────────────────────────

NFT_INIT_SH = r"""#!/bin/sh
# veggen nft accounting - re-created on each firewall reload
# Guard: only add rules if meters don't already exist
/sbin/nft list meter inet fw4 mac_outbound_traffic >/dev/null 2>&1 || \
  /sbin/nft add rule inet fw4 forward \
    iifname {"br-lan","wt0"} \
    meter mac_outbound_traffic { ether saddr counter }
/sbin/nft list meter inet fw4 mac_inbound_traffic >/dev/null 2>&1 || \
  /sbin/nft add rule inet fw4 forward \
    oifname {"br-lan","wt0"} \
    meter mac_inbound_traffic { ether daddr counter }
"""

PARSE_METERS_PY = r"""import re
import sqlite3
import subprocess
import sys

REGEX = r'([0-9a-f:]+)\s+counter packets \d+ bytes (\d+)'

def parse(cmd):
    stdout = subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout
    return {
        m.group(1): int(m.group(2))
        for m in re.finditer(REGEX, stdout)
        if m.group(1) != 'ff:ff:ff:ff:ff:ff'
    }

ts = int(sys.argv[1])
out = parse('/sbin/nft list meter inet fw4 mac_outbound_traffic 2>/dev/null')
inf = parse('/sbin/nft list meter inet fw4 mac_inbound_traffic 2>/dev/null')

db = sqlite3.connect('/etc/veggen/traffic.db')
cur = db.cursor()
cur.execute(
    'CREATE TABLE IF NOT EXISTS mac_traffic ('
    'ts INTEGER, mac TEXT, bytes_in INTEGER, bytes_out INTEGER, '
    'PRIMARY KEY (ts, mac))'
)
cur.execute('CREATE INDEX IF NOT EXISTS idx_mac_ts ON mac_traffic(mac, ts)')
for mac in set(out) | set(inf):
    cur.execute(
        'INSERT OR REPLACE INTO mac_traffic (ts, mac, bytes_in, bytes_out) VALUES (?, ?, ?, ?)',
        (ts, mac, inf.get(mac, 0), out.get(mac, 0)),
    )
db.commit()
db.close()
"""

SNAPSHOT_SH = r"""#!/bin/sh
TS=$(date +%s)
mkdir -p /etc/veggen
python3 /usr/share/veggen/parse_meters.py "$TS"
"""

CRON_JOB = r"""SHELL=/bin/sh
PATH=/usr/sbin:/usr/bin:/sbin:/bin
*/15 * * * * root /usr/share/veggen/traffic-snapshot.sh
"""


FIREWALL_USER_MARKER = "# veggen-traffic-accounting"


def _ensure_python_sqlite():
    """Install python3-sqlite if not available on router."""
    result = run_ssh("python3 -c 'import sqlite3' 2>&1 && echo ok")
    if "ok" in result:
        print("  ✓ python3-sqlite3 already available")
        return
    print("  → installing python3-sqlite...")
    run_ssh("opkg update && opkg install python3-sqlite")
    print("  ✓ python3-sqlite installed")


def _init_db():
    """Create traffic.db and schema on router."""
    run_ssh(
        "sudo mkdir -p /etc/veggen && "
        "python3 -c "
        "'import sqlite3; db = sqlite3.connect(\"/etc/veggen/traffic.db\"); "
        "db.execute(\"CREATE TABLE IF NOT EXISTS mac_traffic \"
        "(ts INTEGER, mac TEXT, bytes_in INTEGER, bytes_out INTEGER, \"
        "PRIMARY KEY (ts, mac))\"); "
        "db.execute(\"CREATE INDEX IF NOT EXISTS idx_mac_ts ON mac_traffic(mac, ts)\"); "
        "db.commit(); db.close()' 2>/dev/null"
    )
    print("  ✓ traffic.db initialized")


def _ensure_firewall_user():
    """Add veggen accounting init to /etc/firewall.user if not present."""
    found = run_ssh(
        f"sudo grep '{FIREWALL_USER_MARKER}' /etc/firewall.user 2>/dev/null && echo yes"
    )
    if found.strip() == "yes":
        print("  ✓ firewall.user already configured")
        return
    current = run_ssh("cat /etc/firewall.user 2>/dev/null || true")
    block = f"\n{FIREWALL_USER_MARKER}\n. /usr/share/veggen/nft-accounting-init.sh\n"
    _write_file("/etc/firewall.user", current + block)
    print("  ✓ firewall.user updated")


def deploy():
    """Deploy all components. Idempotent."""
    print("Deploying nft traffic accounting...")

    _ensure_python_sqlite()
    _init_db()

    _write_file("/usr/share/veggen/nft-accounting-init.sh", NFT_INIT_SH)
    run_ssh("sudo chmod +x /usr/share/veggen/nft-accounting-init.sh")
    print("  ✓ nft-accounting-init.sh")

    _write_file("/usr/share/veggen/parse_meters.py", PARSE_METERS_PY)
    print("  ✓ parse_meters.py")

    _write_file("/usr/share/veggen/traffic-snapshot.sh", SNAPSHOT_SH)
    run_ssh("sudo chmod +x /usr/share/veggen/traffic-snapshot.sh")
    print("  ✓ traffic-snapshot.sh")

    _ensure_firewall_user()

    _write_file("/etc/cron.d/veggen-traffic", CRON_JOB)
    print("  ✓ /etc/cron.d/veggen-traffic")

    print("Initializing meters...")
    run_ssh("sudo /usr/share/veggen/nft-accounting-init.sh")
    print("Done.")


if __name__ == "__main__":
    deploy()
