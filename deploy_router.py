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

PARSE_METERS_PY = r"""import json
import re
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
merged = {}
for mac in set(out) | set(inf):
    merged[mac] = {"in": inf.get(mac, 0), "out": out.get(mac, 0)}
print(json.dumps({"ts": ts, "data": merged}))
"""

SNAPSHOT_SH = r"""#!/bin/sh
TS=$(date +%s)
mkdir -p /etc/veggen
python3 /usr/share/veggen/parse_meters.py "$TS" >> /etc/veggen/traffic.jsonl
"""

CRON_JOB = r"""SHELL=/bin/sh
PATH=/usr/sbin:/usr/bin:/sbin:/bin
*/15 * * * * root /usr/share/veggen/traffic-snapshot.sh
"""


FIREWALL_USER_MARKER = "# veggen-traffic-accounting"


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
