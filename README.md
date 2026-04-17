# Veggen

A simple web application to manage internet access for selected devices on an OpenWrt router.

## Features
- Lists DHCP static hosts starting with the prefix `veggen-` (configurable).
- Displays real-time internet access status (Online/Blocked).
- Simple toggle to block or unblock internet access using MAC-based firewall rules.
- No database required; uses the router's UCI configuration as the source of truth.

## Prerequisites
- **OpenWrt Router**: Developed and tested on version **23.05.3**.
- **Compatibility**: Works with OpenWrt 22.03+ (Firewall4/nftables).
- **SSH Access**: Passwordless SSH access must be configured from the machine running this app to the router's `veggen` user.
- **Python 3**: Installed on the host machine.

## Setup Router Security
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

## Setup & Run
1. Install dependencies and run the application:
   ```bash
   uv run app.py
   ```

2. Access the web interface:
   Open your browser and navigate to `http://localhost:5000`.

## How it works
- **Fetching**: The app runs `uci show dhcp` via SSH to find hosts with the configured prefix.
- **Status Check**: It checks for the presence of a firewall rule named `block_<sanitized_mac>`.
- **Blocking**: 
  - Adds a persistent UCI firewall rule.
  - Instantly inserts a high-priority `nft` rule to bypass "established" connection checks.
- **Unblocking**: Cleans up both the `nft` rule and the UCI configuration.
