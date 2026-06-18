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
- Creates nft meters for outbound/inbound traffic per MAC
- Deploys `parse_meters.py` snapshot script to `/usr/share/veggen/`
- Creates `/etc/veggen/traffic.db` SQLite database
- Adds cron job (every 5 minutes) to `/etc/crontabs/root`
- Adds `firewall.user` hook so meters survive firewall reloads

### First Snapshot

The cron will begin collecting data automatically. To take an immediate snapshot:

```bash
ssh veggen@192.168.0.1 "/usr/share/veggen/traffic-snapshot.sh"
```

Wait ~15 minutes for data points to accumulate, then refresh the dashboard.

## How it works
- **Fetching**: The app runs `uci show dhcp` via SSH to find hosts with the configured prefix.
- **Status Check**: It checks for the presence of a firewall rule named `block_<sanitized_mac>`.
- **Blocking**: 
  - Adds a persistent UCI firewall rule.
  - Instantly inserts a high-priority `nft` rule to bypass "established" connection checks.
- **Unblocking**: Cleans up both the `nft` rule and the UCI configuration.
