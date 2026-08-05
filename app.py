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
        result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=30)
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


def _read_nlbwmon():
    """Runs nlbw -c csv and returns {mac: {"rx": bytes, "tx": bytes}}.

    nlbwmon reads conntrack counters, which the kernel flowtable synchronizes
    when the flowtable definition includes the `counter` statement (fw4 default
    since OpenWrt 23.05.0). This counts software-offloaded flows that nft meters
    in the forward chain miss. rx = traffic to the host (download), tx = traffic
    from the host (upload).
    """
    output = run_ssh_command('/usr/sbin/nlbw -c csv -g mac -o mac -q 2>/dev/null')
    result = {}
    for line in output.splitlines():
        fields = line.split('\t')
        if len(fields) < 6:
            continue
        mac = fields[0].strip().lower()
        if not mac or mac == "00:00:00:00:00:00":
            continue
        try:
            rx = int(fields[2])
            tx = int(fields[4])
        except ValueError:
            continue
        result[mac] = {"rx": rx, "tx": tx}
    return result


def _read_meters():
    """Returns current readings as {"up": {mac: bytes}, "down": {mac: bytes}}.

    up = traffic from the device (upload, nlbwmon tx), down = traffic to the
    device (download, nlbwmon rx).
    """
    data = _read_nlbwmon()
    return {
        "up": {mac: v["tx"] for mac, v in data.items()},
        "down": {mac: v["rx"] for mac, v in data.items()},
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
            mac = data.get("mac", "").lower()
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
                # Format: lease_time mac_addr ip_address hostname client_id
                mac, ip, name = parts[1].lower(), parts[2], parts[3]
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


@app.route("/api/traffic/history")
@login_required
def traffic_history():
    """Returns aggregated traffic history for a device.

    Aggregation runs on the router (traffic_aggregate.py) so only the final
    chart data crosses SSH, not the raw snapshot rows.
    """
    mac = request.args.get("mac", "").lower()
    period = request.args.get("period", "day")

    if not re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
        return jsonify({"error": "Invalid MAC address"}), 400
    if period not in ("day", "week", "month", "year"):
        return jsonify({"error": "Invalid period"}), 400

    raw = run_ssh_command(
        f"python3 /usr/share/veggen/traffic_aggregate.py history "
        f"--mac {mac} --period {period}"
    )
    if not raw:
        return jsonify(_empty_history(period, mac))
    try:
        data = json.loads(raw)
    except ValueError:
        return jsonify(_empty_history(period, mac))
    return jsonify(data)


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


@app.route("/api/traffic/batch-history")
@login_required
def traffic_batch_history():
    """Returns total traffic for all MACs in the selected period.

    Aggregation runs on the router (traffic_aggregate.py) so only the per-MAC
    totals cross SSH, not the raw snapshot rows.
    """
    period = request.args.get("period", "day")
    if period not in ("day", "week", "month", "year"):
        return jsonify({"error": "Invalid period"}), 400

    raw = run_ssh_command(
        f"python3 /usr/share/veggen/traffic_aggregate.py batch --period {period}"
    )
    if not raw:
        return jsonify({"period": period, "macs": {}})
    try:
        data = json.loads(raw)
    except ValueError:
        return jsonify({"period": period, "macs": {}})
    return jsonify(data)


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
    all_macs = managed_macs | set(delta.keys())
    for mac in all_macs:
        dev_delta = delta.get(mac, {"up": 0, "down": 0})
        result[mac] = {
            "up": dev_delta["up"],
            "down": dev_delta["down"],
            "up_text": _bps_str(dev_delta["up"], elapsed),
            "down_text": _bps_str(dev_delta["down"], elapsed),
        }

    return jsonify(result)


@app.route("/api/traffic/debug")
@login_required
def traffic_debug():
    """Debug endpoint to see raw meter data and deltas."""
    current = _read_meters()
    delta, elapsed = _traffic_delta()
    devices = get_devices()
    managed_macs = {dev["mac"] for dev in devices}
    return jsonify({
        "managed_macs": list(managed_macs),
        "meter_up_keys": list(current["up"].keys())[:5],
        "meter_down_keys": list(current["down"].keys())[:5],
        "delta_keys": list(delta.keys())[:5],
        "delta_sample": dict(list(delta.items())[:2]),
        "elapsed": elapsed,
        "prev_ts_age": time.time() - _traffic_ts,
    })


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
