#!/usr/bin/env python3
"""Generate setup commands for nft traffic accounting on OpenWrt router.

Run: python3 deploy_router.py > setup.sh
Then pipe to router: ssh root@router 'sh -s' < setup.sh
"""


# ── Embedded router file contents ──────────────────────────────────────

NFT_INIT_SH = r"""#!/bin/sh
# veggen nft accounting - re-created on each firewall reload
# Detect all LAN interfaces: bridge + wireless members
LAN_IFS=$(uci -q get network.lan.device 2>/dev/null | tr -d '"')
[ -z "$LAN_IFS" ] && LAN_IFS="br-lan"
# Add wireless members of the bridge (e.g. wt0)
for iface in $(brctl show 2>/dev/null | tail -n+3 | awk '{print $2}' | grep -v "^$"); do
    if ! echo "$LAN_IFS" | grep -qw "$iface"; then
        LAN_IFS="$LAN_IFS,$iface"
    fi
done
IFS=',' read -ra IF_ARR <<< "$LAN_IFS"
IF_SET=""
for i in "${!IF_ARR[@]}"; do
    [ $i -gt 0 ] && IF_SET="$IF_SET, "
    IF_SET="$IF_SET\"${IF_ARR[$i]}\""
done
# Remove old rules if they exist (to avoid duplicates on reload)
/usr/sbin/nft -a list chain inet fw4 forward 2>/dev/null | grep mac_outbound_traffic | grep -o 'handle [0-9]*' | awk '{print $2}' | while read h; do /usr/sbin/nft delete rule inet fw4 forward handle $h; done
/usr/sbin/nft -a list chain inet fw4 forward 2>/dev/null | grep mac_inbound_traffic | grep -o 'handle [0-9]*' | awk '{print $2}' | while read h; do /usr/sbin/nft delete rule inet fw4 forward handle $h; done
# Insert at top so they see all traffic before any accept/drop rules
/usr/sbin/nft insert rule inet fw4 forward \
    iifname { $IF_SET } \
    meter mac_outbound_traffic { ether saddr counter }
/usr/sbin/nft insert rule inet fw4 forward \
    oifname { $IF_SET } \
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
out = parse('/usr/sbin/nft list meter inet fw4 mac_outbound_traffic 2>/dev/null')
inf = parse('/usr/sbin/nft list meter inet fw4 mac_inbound_traffic 2>/dev/null')

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

CRON_ENTRY = "*/5 * * * * /usr/share/veggen/traffic-snapshot.sh"

FIREWALL_USER_MARKER = "# veggen-traffic-accounting"
FIREWALL_USER_APPEND = """
# veggen-traffic-accounting
. /usr/share/veggen/nft-accounting-init.sh
"""


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
        "# Veggen traffic accounting setup — run as root on router",
        "",
        "# 1. Create data directory",
        "mkdir -p /etc/veggen",
        "chown veggen:veggen /etc/veggen",
        "",
        "# 2. Deploy scripts",
        heredoc("/usr/share/veggen/nft-accounting-init.sh", NFT_INIT_SH, "+x"),
        "",
        heredoc("/usr/share/veggen/parse_meters.py", PARSE_METERS_PY, "+r"),
        "",
        heredoc("/usr/share/veggen/traffic-snapshot.sh", SNAPSHOT_SH, "+rx"),
        "",
        "# 3. Install cron job (append to /etc/crontabs/root, idempotent)",
        _append_if_missing(
            '"veggen-traffic-snapshot"',
            "/etc/crontabs/root",
            f"# veggen-traffic-snapshot\n{CRON_ENTRY}\n",
        ),
        "",
        "# 4. Firewall persistence (idempotent)",
        _append_if_missing(
            f'"{FIREWALL_USER_MARKER}"',
            "/etc/firewall.user",
            FIREWALL_USER_APPEND,
        ),
        "",
        "# 5. Initialize meters",
        "/usr/share/veggen/nft-accounting-init.sh",
        "",
        '# Done',
        'echo "Veggen traffic accounting setup complete."',
    ]
    return "\n".join(blocks)


if __name__ == "__main__":
    print(generate())