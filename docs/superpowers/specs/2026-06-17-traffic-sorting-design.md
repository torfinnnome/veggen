# All Hosts Traffic Sorting Design

**Goal:** Make the Traffic column header in All Hosts view sortable — clicking cycles through descending, ascending, and unsorted order.

## Architecture

### Sort States
- Default: sorted by device name (current behavior)
- Click 1: sort by total traffic (down + up) descending, header shows "Traffic ↓"
- Click 2: sort by total traffic ascending, header shows "Traffic ↑"
- Click 3: reset to name sort, header shows "Traffic" (no arrow)

### Implementation
- Sort is in-memory only — no API call needed
- `_batchTraffic` already has all data needed
- `fetchAllHosts()` calls `sortAllHosts()` after rendering
- `fetchBatchTraffic()` calls `sortAllHosts()` after updating cells
- A global `_allHostsSort` tracks current sort state: `'name'`, `'traffic-desc'`, `'traffic-asc'`

### CSS
- `.sortable-header` class with `cursor: pointer` and hover effect
