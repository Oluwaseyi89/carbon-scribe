# Summary
Wire live uptime to `UptimeStatsCards` — Uptime percentage cards display static mock values instead of data fetched from `fetchUptimeApi`.

## Social Media Link
Let's collaborate on [Discord](https://discord.gg/uzSSvXUzY). And ensure to star our [repo](https://github.com/carbon-scribe/project-portal).

## Problem Statement
Confirmed in `project-portal-web/src/components/monitoring/dashboard/UptimeStatsCards.tsx`, `project-portal-web/src/lib/store/health/health.api.ts`, and `project-portal-web/src/lib/store/health/healthSlice.ts`:

1. **Static mock data displayed**: `UptimeStatsCards` uses hardcoded values like `overallUptime = 99.9` and `P99 Latency = '142ms'` instead of fetched data.

2. **Uptime API not called**: `fetchUptimeApi()` exists in `health.api.ts` but is never called by `UptimeStatsCards` or the health slice.

3. **Uptime stats stored but unused**: `uptimeStats` field exists in `healthSlice` state but is not referenced in the component.

4. **No fetching of uptime data in component**: Component only uses `detailedStatus` from store, not `uptimeStats` or `fetchUptimeStats()` action.

5. **Missing period aggregation**: `uptimeStats` likely contains `7d`, `30d`, `90d` values but component only uses `30d` hardcoded.

6. **No error handling for uptime fetch**: `fetchUptimeStats()` has error handling but errors are not surfaced to UI.

7. **No loading state for uptime**: Component shows skeleton only for `detailedStatus`, not for `uptimeStats` fetch.

8. **No refresh mechanism**: Uptime data not automatically refreshed or updated.

9. **P99 latency not from metrics**: Hardcoded `'142ms'` instead of fetching from `metrics` API.

10. **No service-level uptime breakdown**: Component shows aggregate only, no per-service uptime.

11. **No historical comparison**: No display of uptime trend or comparison with previous periods.

12. **SLA status hardcoded**: `overallUptime >= 99.9` uses hardcoded threshold instead of configurable SLA target.

## Required Changes
1. Call `fetchUptimeStats()` when component mounts or when `detailedStatus` is loaded.

2. Use `uptimeStats` from store instead of hardcoded `99.9` value.

3. Add loading state for `uptimeStats` fetch.

4. Add error handling with fallback to cached value or default.

5. Display period-specific uptime: `7d`, `30d`, `90d` from API response.

6. Fetch P99 latency from `metrics` API instead of hardcoding.

7. Add auto-refresh for uptime data (every 60 seconds).

8. Add `SLA_TARGET` constant from environment or config.

9. Display uptime trend indicator (up/down from previous period).

10. Add tooltip with detailed uptime breakdown.

11. Show per-service uptime on hover or click.

12. Add empty state for when uptime data is unavailable.

## Acceptance Criteria
1. `UptimeStatsCards` displays live uptime from `fetchUptimeApi`.
2. `30d` uptime value updates when API returns new data.
3. `7d` and `90d` uptime values displayed or accessible.
4. Loading skeleton shows while fetching uptime data.
5. Error state displays when uptime fetch fails.
6. P99 latency comes from metrics API (not hardcoded).
7. Auto-refresh updates uptime every 60 seconds.
8. SLA status uses configurable threshold from environment.
9. Uptime trend shows change from previous period.
10. Tooltip shows detailed uptime breakdown.
11. Per-service uptime accessible on interaction.
12. No static mock values remain in the component.

## Directory to Work on:
`project-portal/project-portal-web/`