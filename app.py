import json
import subprocess
import re
import os
import hmac
import time
from functools import wraps
from flask import Flask, render_template, jsonify, request, session, redirect, url_for

# Veggen Management Application
app = Flask(__name__)

# Security: Load secrets from environment variables (never hardcode)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(24).hex())
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

ROUTER_IP = os.environ.get("VEGGEN_ROUTER_IP", "192.168.0.1")
SSH_USER = os.environ.get("VEGGEN_SSH_USER", "veggen") # Use a restricted user instead of root
PASSWORD = os.environ.get("VEGGEN_PASSWORD", "") # Must be set via VEGGEN_PASSWORD env var
DHCP_PREFIX = "veggen-" # Prefix for devices to manage

_traffic_prev = {}
_traffic_ts = 0.0

# Simple in-memory rate limiter for login (failsafe against brute-force)
_failed_logins = {}  # ip -> list of timestamps
_RATE_LIMIT_ATTEMPTS = 10
_RATE_LIMIT_WINDOW = 60  # seconds

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

def run_ssh_command(command):
    """Executes a command on the router via SSH. 
    The command string should include 'sudo' where necessary.
    """
    ssh_cmd = ["ssh", f"{SSH_USER}@{ROUTER_IP}", command]
    try:
        result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=10)
        if result.stderr:
            filtered_stderr = "\n".join([l for l in result.stderr.splitlines() if "[!]" not in l])
            if filtered_stderr:
                print(f"SSH Debug (stderr): {filtered_stderr}")
        return result.stdout
    except Exception as e:
        print(f"Error executing SSH command: {e}")
        return ""

def sanitize_mac(mac):
    """Sanitizes MAC address for use in UCI rule names."""
    return mac.replace(":", "").lower()


def _parse_meter(name):
    """Runs nft list meter and returns {mac: bytes} for each entry."""
    output = run_ssh_command(f'/usr/sbin/nft list meter inet fw4 {name} 2>/dev/null')
    result = {}
    for line in output.splitlines():
        match = re.match(r'([0-9a-f:]+) counter packets \d+ bytes (\d+)', line)
        if match:
            mac, bytes_str = match.groups()
            if mac != "ff:ff:ff:ff:ff:ff":
                result[mac] = int(bytes_str)
    return result


def _read_meters():
    """Returns current meter readings as {"up": {mac: bytes}, "down": {mac: bytes}}."""
    return {
        "up": _parse_meter("mac_outbound_traffic"),
        "down": _parse_meter("mac_inbound_traffic"),
    }


def _traffic_delta():
    """Compares current meter readings to previous, returns delta per MAC."""
    global _traffic_prev, _traffic_ts

    current = _read_meters()
    now = time.time()

    if not _traffic_prev:
        _traffic_prev = current
        _traffic_ts = now
        return {}, 0.0

    elapsed = max(now - _traffic_ts, 0.1)

    delta = {}
    all_macs = (set(_traffic_prev["up"]) | set(_traffic_prev["down"]) |
                set(current["up"]) | set(current["down"]))
    for mac in all_macs:
        prev_up = _traffic_prev["up"].get(mac, 0)
        prev_down = _traffic_prev["down"].get(mac, 0)
        curr_up = current["up"].get(mac, 0)
        curr_down = current["down"].get(mac, 0)

        delta[mac] = {
            "up": max(curr_up - prev_up, 0),
            "down": max(curr_down - prev_down, 0),
        }

    _traffic_prev = current
    _traffic_ts = now

    return delta, elapsed


def _bps_str(delta_bytes, elapsed):
    """Formats bytes/s into human-readable string, returns rate string (e.g. '1.2 MB/s')."""
    if elapsed <= 0:
        return "0 B/s"
    bps = delta_bytes / elapsed
    if bps >= 1_000_000:
        return f"{bps / 1_000_000:.1f} MB/s"
    if bps >= 1_000:
        return f"{bps / 1_000:.0f} KB/s"
    return f"{bps:.0f} B/s"


def get_devices():
    """Fetches DHCP static hosts and their block status."""
    # uci show usually requires sudo to read /etc/config/firewall
    dhcp_output = run_ssh_command("sudo uci show dhcp")
    if not dhcp_output:
        print("DEBUG: No output from uci show dhcp")
    
    hosts = {}
    for line in dhcp_output.splitlines():
        match = re.match(r"dhcp\.(@host\[\d+\]|[a-zA-Z0-9_-]+)\.(\w+)='?([^']*)'?", line)
        if match:
            section, key, value = match.groups()
            if section not in hosts:
                hosts[section] = {}
            hosts[section][key] = value

    ctrl_devices = []
    for section, data in hosts.items():
        name = data.get("name", "")
        if name.startswith(DHCP_PREFIX):
            mac = data.get("mac", "")
            rule_name = f"block_{sanitize_mac(mac)}"
            if mac:
                # Run the shell logic as 'veggen', only sudo the uci command
                status_cmd = f"sudo uci show firewall | grep -q {rule_name} && echo 'blocked' || echo 'online'"
                status_output = run_ssh_command(status_cmd).strip()
                is_blocked = (status_output == "blocked")
                
                parts = name.split("-")
                kid = parts[1] if len(parts) > 1 else "Unknown"
                device_name = "-".join(parts[2:]) if len(parts) > 2 else "Device"
                
                ctrl_devices.append({
                    "id": section,
                    "kid": kid,
                    "device_name": device_name,
                    "full_name": name,
                    "mac": mac,
                    "ip": data.get("ip", "Unknown"),
                    "blocked": is_blocked
                })
    
    return ctrl_devices


def get_all_hosts():
    """Fetch all network hosts from static DHCP and dynamic leases, deduplicated by MAC."""
    result = {}

    # 1. Static hosts from uci
    dhcp_output = run_ssh_command("sudo uci show dhcp")
    if dhcp_output:
        hosts = {}
        for line in dhcp_output.splitlines():
            match = re.match(r"dhcp\.(@host\[\d+\]|[a-zA-Z0-9_-]+)\.(\w+)='?([^']*)'?", line)
            if match:
                section, key, value = match.groups()
                if section not in hosts:
                    hosts[section] = {}
                hosts[section][key] = value
        for section, data in hosts.items():
            mac = data.get("mac", "").lower()
            name = data.get("name", "")
            ip = data.get("ip", "")
            if mac and ip:
                result[mac] = {"name": name, "ip": ip, "mac": mac}

    # 2. Dynamic leases from /tmp/dhcp.leases
    leases_output = run_ssh_command("cat /tmp/dhcp.leases 2>/dev/null")
    if leases_output:
        for line in leases_output.splitlines():
            parts = line.split()
            if len(parts) >= 4:
                # Format: expiry ip mac name hostname
                ip, mac, name = parts[1], parts[2].lower(), parts[3]
                if mac and ip and mac not in result:
                    result[mac] = {"name": name if name else "unknown", "ip": ip, "mac": mac}

    return list(result.values())


def check_rate_limit():
    """Check if the client IP has exceeded login attempt limits."""
    client_ip = request.remote_addr or "unknown"
    now = time.time()

    # Clean old entries
    if client_ip in _failed_logins:
        _failed_logins[client_ip] = [
            t for t in _failed_logins[client_ip] if now - t < _RATE_LIMIT_WINDOW
        ]
        if not _failed_logins[client_ip]:
            del _failed_logins[client_ip]
            return

    # Check limit
    attempts = _failed_logins.get(client_ip, [])
    if len(attempts) >= _RATE_LIMIT_ATTEMPTS:
        return True  # Rate limited
    return False


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if check_rate_limit():
            return render_template("login.html", error="Too many attempts. Wait a moment.")

        password = request.form.get("password", "")
        if not PASSWORD:
            return render_template("login.html", error="Server misconfigured")

        if hmac.compare_digest(password, PASSWORD):
            _failed_logins.pop(request.remote_addr, None)
            session["logged_in"] = True
            return redirect(url_for("index"))

        # Track failed attempt
        client_ip = request.remote_addr or "unknown"
        _failed_logins.setdefault(client_ip, []).append(time.time())
        return render_template("login.html", error="Invalid password")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    return redirect(url_for("login"))

@app.route("/")
@login_required
def index():
    return render_template("index.html")

@app.route("/api/devices")
@login_required
def api_devices():
    return jsonify(get_devices())

@app.route("/api/all-hosts")
@login_required
def api_all_hosts():
    return jsonify(get_all_hosts())

@app.route("/api/toggle", methods=["POST"])
@login_required
def toggle_access():
    data = request.json or {}
    macs = data.get("macs", [])
    if "mac" in data:
        macs.append(data["mac"])
    
    action = data.get("action")
    
    if not macs or not action:
        return jsonify({"error": "Missing data"}), 400

    if action not in {"block", "unblock"}:
        return jsonify({"error": "Invalid action"}), 400

    commands = []
    for mac in macs:
        mac_norm = mac.strip().lower()
        if not re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", mac_norm):
            continue # Skip invalid MACs
        
        rule_name = f"block_{sanitize_mac(mac_norm)}"
        
        if action == "block":
            commands.append(
                f"sudo uci add firewall rule; "
                f"sudo uci set firewall.@rule[-1].name={rule_name}; "
                f"sudo uci set firewall.@rule[-1].src=lan; "
                f"sudo uci set firewall.@rule[-1].src_mac={mac_norm}; "
                f"sudo uci set firewall.@rule[-1].target=DROP; "
                f"sudo uci set firewall.@rule[-1].family=any; "
                f"sudo uci set firewall.@rule[-1].enabled=1; "
                f"sudo nft insert rule inet fw4 forward ether saddr {mac_norm} counter drop; "
                f"sudo nft insert rule inet fw4 input ether saddr {mac_norm} counter drop"
            )
        else:
            commands.append(
                f"for s in $(sudo uci show firewall | grep {rule_name} | cut -d. -f2 | cut -d= -f1 | uniq); do sudo uci delete firewall.$s; done; "
                f"for h in $(sudo nft list chain inet fw4 forward | grep -i {mac_norm} | grep -o 'handle [0-9]*' | awk '{{print $2}}'); do sudo nft delete rule inet fw4 forward handle $h; done; "
                f"for h in $(sudo nft list chain inet fw4 input | grep -i {mac_norm} | grep -o 'handle [0-9]*' | awk '{{print $2}}'); do sudo nft delete rule inet fw4 input handle $h; done"
            )
    
    if not commands:
        return jsonify({"error": "No valid MACs provided"}), 400

    # Join commands with commit and reload at the end
    full_command = " && ".join(commands)
    full_command += "; sudo uci commit firewall; sudo /etc/init.d/firewall reload"
    
    run_ssh_command(full_command)
    return jsonify({"success": True})


def _bucket_seconds(period):
    return {"day": 3600, "week": 86400, "month": 86400, "year": 604800}.get(period, 86400)


def _period_cutoff(period):
    now = time.time()
    return {
        "day": now - 86400,
        "week": now - 604800,
        "month": now - 2592000,
        "year": now - 31536000,
    }.get(period, now - 86400)


@app.route("/api/traffic/history")
@login_required
def traffic_history():
    """Returns aggregated traffic history for a device from SQLite."""
    mac = request.args.get("mac", "").lower()
    period = request.args.get("period", "day")

    if not re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
        return jsonify({"error": "Invalid MAC address"}), 400
    if period not in ("day", "week", "month", "year"):
        return jsonify({"error": "Invalid period"}), 400

    cutoff = _period_cutoff(period)
    bucket_size = _bucket_seconds(period)

    # Query SQLite on router via SSH for aggregated data
    query = (
        f"SELECT (ts / {bucket_size}) * {bucket_size} AS bucket_ts, "
        f"       MAX(bytes_out) - MIN(bytes_out) AS bytes_up, "
        f"       MAX(bytes_in) - MIN(bytes_in) AS bytes_down "
        f"FROM mac_traffic "
        f"WHERE mac = '{mac}' AND ts >= {int(cutoff)} "
        f"GROUP BY bucket_ts "
        f"ORDER BY bucket_ts"
    )
    raw = run_ssh_command(f"sqlite3 -separator '|' /etc/veggen/traffic.db '{query}' 2>/dev/null")
    if not raw:
        return jsonify(_empty_history(period, mac))

    buckets = []
    total_up = 0
    total_down = 0
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("|")
        if len(parts) < 3:
            continue
        try:
            bucket_ts = int(parts[0])
            bucket_up = max(0, int(parts[1]))
            bucket_down = max(0, int(parts[2]))
            buckets.append({"ts": bucket_ts, "up": bucket_up, "down": bucket_down})
            total_up += bucket_up
            total_down += bucket_down
        except (ValueError, IndexError):
            continue

    if not buckets:
        return jsonify(_empty_history(period, mac))

    span_days = max((buckets[-1]["ts"] - buckets[0]["ts"]) / 86400, 1)
    avg_up_per_day = int(total_up / span_days)
    avg_down_per_day = int(total_down / span_days)

    return jsonify({
        "period": period,
        "mac": mac,
        "total_up": total_up,
        "total_down": total_down,
        "avg_up_per_day": avg_up_per_day,
        "avg_down_per_day": avg_down_per_day,
        "buckets": buckets,
    })


def _empty_history(period, mac):
    return {
        "period": period,
        "mac": mac,
        "total_up": 0,
        "total_down": 0,
        "avg_up_per_day": 0,
        "avg_down_per_day": 0,
        "buckets": [],
    }


@app.route("/api/traffic/summary")
@login_required
def traffic_summary():
    """Returns real-time traffic rates for managed devices."""
    devices = get_devices()
    managed_macs = {dev["mac"] for dev in devices}

    delta, elapsed = _traffic_delta()

    if elapsed == 0:
        return jsonify({})

    result = {}
    for mac in managed_macs:
        dev_delta = delta.get(mac, {"up": 0, "down": 0})
        result[mac] = {
            "up": dev_delta["up"],
            "down": dev_delta["down"],
            "up_text": _bps_str(dev_delta["up"], elapsed),
            "down_text": _bps_str(dev_delta["down"], elapsed),
        }

    return jsonify(result)


@app.after_request
def set_security_headers(response):
    """Add security headers to every response."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
