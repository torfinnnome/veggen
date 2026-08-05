# Veggen

A simple web application to manage internet access for selected devices on an OpenWrt router.

## Features
- Lists DHCP static hosts starting with the prefix `veggen-` (configurable).
- Displays real-time internet access status (Online/Blocked).
- Simple toggle to block or unblock internet access using MAC-based firewall rules.
- **Optional traffic accounting**: per-device bandwidth usage with historical diverging area charts (download/upload over time).
- No database required; uses the router's UCI configuration as the source of truth.

## Prerequisites
- **OpenWrt Router**: Developed and tested on version **23.05.3**.
- **Compatibility**: Works with OpenWrt 22.03+ (Firewall4/nftables).
- **SSH Access**: Passwordless SSH access must be configured from the machine running this app to the router's `veggen` user.
- **Python 3**: Installed on the host machine.

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
1. Install dependencies and run the application:
    ```bash
    uv run app.py
    ```

2. Access the web interface:
    Open your browser and navigate to `http://localhost:5000`.

## Traffic Accounting (Optional)

Track per-device bandwidth usage with real-time speeds and historical charts.

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
- Deploys `parse_nlbwmon.py` snapshot script to `/usr/share/veggen/`
- Deploys `traffic_aggregate.py` aggregation helper to `/usr/share/veggen/`
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

Wait ~15 minutes for data points to accumulate, then refresh the dashboard.

### Aggregation runs on the router

The history and batch-history endpoints do not transfer raw snapshot rows over
SSH. Instead, the app invokes `traffic_aggregate.py` on the router, which reads
`/etc/veggen/traffic.db` locally, aggregates the raw snapshots into the final
chart data (per-bucket deltas, per-MAC totals, mbps conversion, empty-bucket
filling), and returns only that compact JSON. This keeps the SSH payload small
regardless of how large the database grows.

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
`month` and `year` charts read the daily table (one value per day/week).
Override the raw window with the `VEGGEN_RETENTION_SECONDS` environment
variable (default `1209600`).

## How it works
- **Fetching**: The app runs `uci show dhcp` via SSH to find hosts with the configured prefix.
- **Status Check**: It checks for the presence of a firewall rule named `block_<sanitized_mac>`.
- **Blocking**: 
  - Adds a persistent UCI firewall rule.
  - Instantly inserts a high-priority `nft` rule to bypass "established" connection checks.
- **Unblocking**: Cleans up both the `nft` rule and the UCI configuration.
