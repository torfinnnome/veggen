# All Hosts Traffic Column Design

**Goal:** Add a "Traffic" column to the All Hosts view showing total traffic (down + up) for a selectable period, using a single batch API call.

## Architecture

### Period Dropdown
- Placed at the top of the All Hosts tab, above the table
- Simple `<select>` element with options: Day, Week, Month, Year
- Changing the period triggers a single batch fetch and updates all rows

### Traffic Column
- New column after "Now", header: "Traffic" — added to **both** Managed and All Hosts views
- Shows `↓X + ↑Y` format (e.g., `↓1.2 GB + ↑340 MB`)
- Empty cell if no traffic data for the MAC in the selected period

### Period Dropdown
- Moves to a shared location at the top of the page (above the tab bar) so it applies to both views

### Batch API: `GET /api/traffic/batch-history?period=day`
- Single SQLite query grouping by MAC to get per-MAC totals for the period
- Returns `{ "period": "day", "macs": { "aa:bb:cc:dd:ee:ff": { "down": 1234567, "up": 345678 } } }`
- One SSH round-trip regardless of number of hosts

## Data Flow
1. Page loads → Managed tab shows, `fetchDevices()` + `fetchBatchTraffic(period)` fire
2. Batch response populates traffic cells in both views
3. User switches tab → traffic data already cached, no refetch
4. Dropdown change → calls `fetchBatchTraffic(newPeriod)` once, updates both views in-place

## Performance
- 1 SSH call to router for history (vs. 25+ individual calls)
- No per-row API calls
- Traffic data cached in memory, only refetched on period change
