# Veggen

A simple web application to manage internet access for selected devices on an OpenWrt router, with optional per-device traffic accounting.

## Features
- Lists DHCP static hosts starting with the prefix `veggen-` (change `DHCP_PREFIX` in `app.py` to use a different prefix), grouped by kid.
- Displays real-time internet access status (Online/Blocked).
- Per-device toggles plus a per-kid bulk switch to block or unblock internet access using MAC-based firewall rules.
- **All Hosts** view: every host on the network (static DHCP entries and dynamic leases) with traffic columns.
- **Interfaces** view: per-interface traffic (WAN/LAN, etc.), with IP addresses.
- **Optional traffic accounting**: per-device bandwidth usage with historical diverging bar charts (download/upload over time) for day/week/month/year periods, period navigation, drag-to-zoom, live search, and dark mode.
- No database required for the core app; uses the router's UCI configuration as the source of truth (traffic accounting keeps a small SQLite database on the router).

## Prerequisites
- **OpenWrt Router**: Developed and tested on version **23.05.3**.
- **Compatibility**: Works with OpenWrt 22.03+ (Firewall4/nftables).
- **SSH Access**: Passwordless SSH access must be configured from the machine running this app to the router's `veggen` user (only needed for the default SSH mode — see [Running on the Router](#running-on-the-router-optional)).
- **Python 3.11+**: Installed on the host machine (or let `uv` manage it) — or on the router itself if you run the app there (OpenWrt 23.05 ships Python 3.11).

## Setup Router
To avoid running the app as `root`, create a restricted `veggen` user on your router:

1. SSH into your router as `root`.
2. Install the necessary tools:
   ```bash
   opkg update
   opkg install sudo shadow-useradd
   ```
3. Add the user: `useradd -m -s /bin/ash veggen`.
4. Add your public key to the new user:
   ```bash
   mkdir -p /home/veggen/.ssh
   # Copy your public key into this file:
   vi /home/veggen/.ssh/authorized_keys
   chown -R veggen:veggen /home/veggen/.ssh
   chmod 700 /home/veggen/.ssh
   chmod 600 /home/veggen/.ssh/authorized_keys
   ```
5. Configure `sudo` permissions by running `visudo` and adding:
   ```text
    veggen ALL=(ALL) NOPASSWD: /sbin/uci, /usr/sbin/nft, /etc/init.d/firewall
    ```

### DHCP Host Configuration

Devices to manage must be configured as static DHCP hosts with a name starting with `veggen-`. Format: `veggen-<kid>-<device-name>` (e.g., `veggen-olaf-iphone`).

```bash
uci set dhcp.olaf_iphone='host'
uci set dhcp.olaf_iphone.name='veggen-olaf-iphone'
uci set dhcp.olaf_iphone.ip='192.168.0.101'
uci set dhcp.olaf_iphone.mac='aa:bb:cc:dd:ee:ff'
uci commit dhcp
/etc/init.d/dhcp restart
```

## Setup & Run
1. Configure the application:
    ```bash
    export VEGGEN_PASSWORD="secret"      # required: password for the web login
    export VEGGEN_MODE=ssh               # optional: "ssh" (default) or "local"
    export VEGGEN_ROUTER_IP=192.168.0.1  # optional, ssh mode only (default shown)
    export VEGGEN_SSH_USER=veggen        # optional, ssh mode only (default shown)
    export VEGGEN_PORT=5000               # optional (default shown)
    ```
    Without `VEGGEN_PASSWORD` the login page shows "Server misconfigured".

2. Install dependencies and run the application:
    ```bash
    uv run app.py
    ```

3. Access the web interface:
    Open your browser, navigate to `http://localhost:5000`, and log in. The app binds to `0.0.0.0`, so it is also reachable from other devices on your LAN. Login is rate-limited (10 attempts per 60 s per IP).

## Running on the Router (Optional)

If your router has enough RAM/CPU you can run the app directly on the router instead of over SSH. This removes the SSH dependency and makes page loads faster, since all router commands then run locally.

1. Install Python and the app's dependencies on the router (as root):
   ```bash
   opkg update
   opkg install python3 python3-pip
   mkdir -p /usr/share/veggen/app
   python3 -m pip install --target /usr/share/veggen/app/deps "flask==3.1.3"
   ```
   If pip has to build C extensions for your architecture, also install `gcc` and `musl-dev`.

2. Copy the app to the router:
   ```bash
   chown -R veggen:veggen /usr/share/veggen/app
   scp -r app.py templates veggen@192.168.0.1:/usr/share/veggen/app/
   ```

3. Create `/etc/init.d/veggen` so the app starts on boot (as root):
   ```sh
   #!/bin/sh /usr/sbin/procd

   USE_PROCD=1
   APP=/usr/share/veggen/app

   start_service() {
       procd_open_instance
       procd_set_param user veggen veggen
       procd_set_param command /usr/bin/python3 $APP/app.py
       procd_set_param env VEGGEN_MODE=local
       procd_set_param env PYTHONPATH=$APP/deps
       procd_set_param env VEGGEN_PASSWORD=secret   # use your own password
       procd_set_param respawn
   }
   ```
   ```bash
   chmod +x /etc/init.d/veggen
   /etc/init.d/veggen enable
   /etc/init.d/veggen start
   ```

The app must run as the `veggen` user from the Setup Router section: all router commands keep their `sudo` prefix, which the existing sudoers entry permits. In local mode `VEGGEN_ROUTER_IP` and `VEGGEN_SSH_USER` are ignored, and the web interface is reachable at `http://<router-ip>:5000`. Traffic accounting works unchanged — `traffic_aggregate.py` is already deployed to the router.

## Web interface
Three tabs:
- **Managed**: `veggen-` devices grouped by kid (`veggen-<kid>-<device>`). Toggle a single device or the whole group with the kid-level switch.
- **All Hosts**: every host on the network (static DHCP hosts plus dynamic leases from `/tmp/dhcp.leases`, deduplicated by MAC).
- **Interfaces**: per-interface traffic (WAN/LAN, ...), with IP addresses, using synthetic MACs that map back to the logical interface name.

Controls:
- **Period selector** (Day/Week/Month/Year) sets the window for the traffic columns; "Day" means since local midnight.
- Expanding a device row opens a detail chart with period pills, prev/next period navigation, and zoom (drag a region or use the +/−/reset buttons).
- **Search** filters by name, IP, or MAC; the reload button refetches all data; the theme toggle (dark/light) is remembered per browser.

## Traffic Accounting (Optional)

Track per-device and per-interface bandwidth usage with historical charts (period totals — "Day" means since local midnight).

### Deploy to Router

1. Generate the setup script:
   ```bash
   python3 deploy_router.py > setup.sh
   ```

2. SSH into your router as `root` and paste the contents:
   ```bash
   ssh root@192.168.0.1 'sh -s' < setup.sh
   ```

This does the following (idempotent — safe to rerun):
- Installs and starts `nlbwmon` (conntrack-based accounting)
- Configures nlbwmon to monitor the LAN subnet
- Deploys `parse_nlbwmon.py` (nlbwmon counters plus cumulative byte counters for every network interface) and the `traffic-snapshot.sh` cron entrypoint to `/usr/share/veggen/`
- Deploys `traffic_aggregate.py` aggregation helper to `/usr/share/veggen/`
- The snapshot script also dumps logical interface names (WAN/LAN, ...) and their IPv4 addresses from ubus netifd to `/etc/veggen/iface_names.json` and `/etc/veggen/iface_ips.json` for the Interfaces view
- Creates `/etc/veggen/traffic.db` SQLite database
- Adds cron job (every 5 minutes) to `/etc/crontabs/root`
- Removes the obsolete nft meter table and `firewall.user` hook

> **Why nlbwmon?** nft meters in the `forward` chain do not count traffic that
> is offloaded via the kernel flowtable (software flow offload). nlbwmon reads
> conntrack counters, which the flowtable synchronizes when it includes the
> `counter` statement (fw4 default since OpenWrt 23.05.0). This requires
> software-only offload (`flow_offloading_hw=0`); hardware offload bypasses
> conntrack counters entirely.

### First Snapshot

The cron will begin collecting data automatically. To take an immediate snapshot:

```bash
ssh veggen@192.168.0.1 "/usr/share/veggen/traffic-snapshot.sh"
```

(If the app runs on the router itself, run `/usr/share/veggen/traffic-snapshot.sh` there directly.)

Wait ~15 minutes for data points to accumulate, then refresh the dashboard.

### Aggregation runs on the router

The history and batch-history endpoints do not transfer raw snapshot rows from
the router. Instead, the app invokes `traffic_aggregate.py` on the router, which
reads `/etc/veggen/traffic.db` locally, aggregates the raw snapshots into the
final chart data (per-bucket deltas, per-MAC totals, mbps conversion,
empty-bucket filling), and returns only that compact JSON. This keeps the
payload small regardless of how large the database grows.

### Retention

Raw 5-minute snapshots are kept for a rolling window (default 14 days) and
rolled up into per-MAC daily totals (`mac_traffic_daily`) that are kept
indefinitely, so per-day stats remain available for any device as far back as
you want. Once per day the snapshot script:

1. Rolls up each complete previous day's raw snapshots into one row per MAC
   per day (consecutive-delta sums, same counter-reset clamping as the app).
2. Deletes raw snapshots older than the window, then runs `VACUUM` to reclaim
   the freed space.

The `day` and `week` charts read the raw table (fine-grained buckets); the
`month` and `year` charts read the daily table (one value per day/week) and
merge in today's live delta-sum from the raw table, so they never report less
than the `week` chart within the same window.
Override the raw window with the `VEGGEN_RETENTION_SECONDS` environment
variable on the router (read by the snapshot script; default `1209600`), e.g.
by adding it to the cron entry in `/etc/crontabs/root`.

## How it works
- **Fetching**: The app runs `uci show dhcp` on the router (via SSH by default, or directly when running locally) to find managed hosts (configured prefix); the All Hosts view additionally reads dynamic leases from `/tmp/dhcp.leases`.
- **Status Check**: It checks for the presence of a firewall rule named `block_<sanitized_mac>`.
- **Blocking**: 
  - Adds a persistent UCI firewall rule.
  - Instantly inserts high-priority `nft` rules into both the `inet fw4 forward` and `inet fw4 input` chains, so new connections are dropped without waiting for the "established" state.
- **Unblocking**: Deletes the `nft` rules from both chains, removes the UCI rule, commits, and reloads the firewall.
