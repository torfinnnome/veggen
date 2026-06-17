# Traffic Sorting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Traffic column header in All Hosts view sortable — clicking cycles through descending, ascending, and unsorted order.

**Architecture:** In-memory sort of `_batchTraffic` data. Global `_allHostsSort` tracks state. Sort applied after rendering and after batch traffic updates.

**Tech Stack:** Vanilla JS

---

### Task 1: Traffic sorting in All Hosts view

**Files:**
- Modify: `templates/index.html`

- [ ] **Step 1: Add sortable header CSS**

Add to `<style>` section after `.traffic-cell`:

```css
.sortable-header {
    cursor: pointer;
    user-select: none;
}
.sortable-header:hover {
    color: var(--pico-primary);
}
```

- [ ] **Step 2: Make Traffic header clickable**

In the All Hosts table `<thead>`, change the Traffic header to:

```html
<th class="sortable-header" onclick="cycleTrafficSort()">Traffic</th>
```

- [ ] **Step 3: Add sort state and functions**

Add after `_batchTraffic` / `_currentPeriod` declarations:

```javascript
var _allHostsSort = 'name';
var _allHostsData = [];

function cycleTrafficSort() {
    if (_allHostsSort === 'name') _allHostsSort = 'traffic-desc';
    else if (_allHostsSort === 'traffic-desc') _allHostsSort = 'traffic-asc';
    else _allHostsSort = 'name';
    sortAllHosts();
}

function sortAllHosts() {
    var tbody = document.getElementById('allhosts-tbody');
    if (!tbody) return;
    var rows = Array.from(tbody.querySelectorAll('tr.device-row'));
    if (rows.length === 0) return;

    rows.sort(function(a, b) {
        var macA = a.querySelector('td:nth-child(3)').textContent;
        var macB = b.querySelector('td:nth-child(3)').textContent;
        var nameA = a.querySelector('td:nth-child(1)').textContent;
        var nameB = b.querySelector('td:nth-child(1)').textContent;

        if (_allHostsSort === 'name') return nameA.localeCompare(nameB);

        var totalA = (_batchTraffic[macA] ? _batchTraffic[macA].up + _batchTraffic[macA].down : 0);
        var totalB = (_batchTraffic[macB] ? _batchTraffic[macB].up + _batchTraffic[macB].down : 0);
        return _allHostsSort === 'traffic-desc' ? totalB - totalA : totalA - totalB;
    });

    rows.forEach(function(row) { tbody.appendChild(row); });
    var th = document.querySelector('#allhosts-table .sortable-header');
    if (th) {
        if (_allHostsSort === 'traffic-desc') th.textContent = 'Traffic \u2193';
        else if (_allHostsSort === 'traffic-asc') th.textContent = 'Traffic \u2191';
        else th.textContent = 'Traffic';
    }
}
```

- [ ] **Step 4: Call `sortAllHosts()` after rendering and after batch update**

In `fetchAllHosts()`, after `tbody.appendChild(tr)` loop completes (after `setupSpeedClicks();` line), add:

```javascript
sortAllHosts();
```

In `updateTrafficCells()`, after updating all cell text, add:

```javascript
sortAllHosts();
```

- [ ] **Step 5: Commit**

```bash
git add templates/index.html
git commit -m "feat: sortable Traffic column in All Hosts view"
```

### Task 2: Testing

- [ ] **Step 1: Verify JS syntax**

```bash
node -e "..." # verify script block
```

- [ ] **Step 2: Test UI**
  - Verify clicking Traffic header cycles: sorted desc → sorted asc → unsorted
  - Verify arrow updates in header text
  - Verify sort persists after period change

- [ ] **Step 3: Commit if any fixes needed**

```bash
git add -A
git commit -m "fix: address sorting testing findings"
```
