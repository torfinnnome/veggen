# Traffic Column Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a "Traffic" column showing total traffic (down + up) for a selectable period to both Managed and All Hosts views, using a single batch API call.

**Architecture:** New `/api/traffic/batch-history` endpoint runs one SQLite query grouping by MAC. Frontend adds a shared period dropdown above the tab bar, a "Traffic" column to both tables, and a `fetchBatchTraffic()` function that populates all rows from one response.

**Tech Stack:** Python/Flask, vanilla JS, Pico CSS, Chart.js

---

### Task 1: `/api/traffic/batch-history` endpoint

**Files:**
- Modify: `app.py` — add route after `traffic_history()` (around line 408)

- [ ] **Step 1: Add route**

Add after `_empty_history()` function (after line 418):

```python
@app.route("/api/traffic/batch-history")
@login_required
def traffic_batch_history():
    """Returns total traffic for all MACs in the selected period via one SQLite query."""
    period = request.args.get("period", "day")
    if period not in ("day", "week", "month", "year"):
        return jsonify({"error": "Invalid period"}), 400

    cutoff = _period_cutoff(period)
    query = (
        f"SELECT mac, "
        f"       MAX(bytes_out) - MIN(bytes_out) AS total_up, "
        f"       MAX(bytes_in) - MIN(bytes_in) AS total_down "
        f"FROM mac_traffic "
        f"WHERE ts >= {int(cutoff)} "
        f"GROUP BY mac"
    )
    raw = run_ssh_command(
        f"python3 -c \"import sqlite3; db=sqlite3.connect('/etc/veggen/traffic.db');"
        f" [print('|'.join(str(x) for x in r)) for r in db.execute('''{query}''')]\""
    )
    if not raw:
        return jsonify({"period": period, "macs": {}})

    macs = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("|")
        if len(parts) < 3:
            continue
        try:
            macs[parts[0]] = {
                "up": max(0, int(parts[1])),
                "down": max(0, int(parts[2])),
            }
        except (ValueError, IndexError):
            continue

    return jsonify({"period": period, "macs": macs})
```

- [ ] **Step 2: Commit**

```bash
git add app.py
git commit -m "feat: add /api/traffic/batch-history endpoint for all-MAC totals"
```

### Task 2: Shared period dropdown and Traffic column in both views

**Files:**
- Modify: `templates/index.html`

- [ ] **Step 1: Add period dropdown CSS**

Add to `<style>` section after `.tab-btn.active` block (after line 101):

```css
.period-select {
    display: block;
    margin-bottom: 0.5rem;
    font-size: 0.85rem;
    padding: 0.25rem 0.5rem;
    width: auto;
}
.traffic-cell {
    font-size: 10px;
    white-space: nowrap;
    color: var(--pico-muted-color);
}
```

- [ ] **Step 2: Add period dropdown HTML**

Find the `<section id="device-list">` block (line 111). Replace the opening of the section with:

```html
<section id="device-list" aria-busy="true">
    <select id="period-select" class="period-select" onchange="onPeriodChange()">
        <option value="day">Day</option>
        <option value="week">Week</option>
        <option value="month">Month</option>
        <option value="year">Year</option>
    </select>
    <div class="tab-bar">
```

- [ ] **Step 3: Add "Traffic" column to Managed table header**

In the `<thead>` of `#main-table` (around line 119), add a `<th>` after the "Now" column:

```html
<th style="width: 110px;">Now</th>
<th style="width: 150px;">Traffic</th>
```

- [ ] **Step 4: Add "Traffic" column to All Hosts table header**

In the `<thead>` of `#allhosts-table` (around line 137), add a `<th>` after the "Now" column:

```html
<th style="width: 110px;">Now</th>
<th style="width: 150px;">Traffic</th>
```

- [ ] **Step 5: Add `onPeriodChange()` and `fetchBatchTraffic()` functions**

Add before `switchTab()` function (around line 325):

```javascript
var _batchTraffic = {};
var _currentPeriod = 'day';

function onPeriodChange() {
    _currentPeriod = document.getElementById('period-select').value;
    fetchBatchTraffic();
}

async function fetchBatchTraffic() {
    try {
        var res = await fetch('/api/traffic/batch-history?period=' + _currentPeriod);
        var data = await res.json();
        _batchTraffic = data.macs || {};
        updateTrafficCells();
    } catch (e) {
        console.error('Error fetching batch traffic:', e);
    }
}

function updateTrafficCells() {
    document.querySelectorAll('.traffic-cell[data-mac]').forEach(function(el) {
        var mac = el.getAttribute('data-mac');
        var t = _batchTraffic[mac];
        if (t && (t.up > 0 || t.down > 0)) {
            el.textContent = '\u2193' + _formatBytes(t.down) + ' + \u2191' + _formatBytes(t.up);
        } else {
            el.textContent = '';
        }
    });
}
```

- [ ] **Step 6: Add traffic cell to Managed view rows**

In `fetchDevices()`, after appending `nowTd` to `tr` (around line 466), add:

```javascript
const trafficTd = document.createElement('td');
trafficTd.className = 'traffic-cell';
trafficTd.setAttribute('data-mac', dev.mac);
tr.appendChild(trafficTd);
```

Update the `colspan` in the group header row's `td2` from `colspan="3"` to `colspan="4"`:

```javascript
td2.setAttribute('colspan', '4');
```

Update the empty row colspan from 4 to 5:

```javascript
emptyCell.setAttribute('colspan', '5');
```

- [ ] **Step 7: Add traffic cell to All Hosts rows**

In `fetchAllHosts()`, after appending `nowTd` to `tr` (around line 363), add:

```javascript
var trafficTd = document.createElement('td');
trafficTd.className = 'traffic-cell';
trafficTd.setAttribute('data-mac', host.mac);
tr.appendChild(trafficTd);
```

Update the `<th>` colspan in the All Hosts table header — add a 5th column. The header row is static HTML, update the "Loading..." row colspan from 4 to 5:

In `fetchAllHosts()`, change:
```javascript
cell.setAttribute('colspan', '5');
```

- [ ] **Step 8: Call `fetchBatchTraffic()` on page load**

At the bottom of the script (around line 535), add after `_pollTrafficSummary()`:

```javascript
fetchDevices();
fetchAllHosts();
_pollTrafficSummary();
setInterval(_pollTrafficSummary, 15000);
fetchBatchTraffic();
setTimeout(function() { setupSpeedClicks(); }, 100);
```

- [ ] **Step 9: Commit**

```bash
git add templates/index.html
git commit -m "feat: add Traffic column to both views with shared period dropdown"
```

### Task 3: Testing

- [ ] **Step 1: Start the app and verify**

```bash
uv run app.py
```

- [ ] **Step 2: Test `/api/traffic/batch-history`**

```bash
curl -s 'http://localhost:5000/api/traffic/batch-history?period=day' | python3 -m json.tool
```

Expected: JSON with `"period"` and `"macs"` keys, macs contain `"up"` and `"down"` values.

- [ ] **Step 3: Test UI**

Open `http://localhost:5000`:
- Verify period dropdown appears above tab bar
- Verify "Traffic" column appears in both Managed and All Hosts tables
- Verify traffic values show `↓X + ↑Y` format
- Verify changing period updates traffic values without page reload
- Verify empty cells for MACs with no traffic

- [ ] **Step 4: Commit if any fixes needed**

```bash
git add -A
git commit -m "fix: address testing findings"
```
