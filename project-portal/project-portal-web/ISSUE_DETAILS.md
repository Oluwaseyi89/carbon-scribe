## 46. Wire live health data to `SystemStatusBanner`

### Problem Statement
The `SystemStatusBanner` component currently renders with hardcoded static status strings, rather than consuming live health data from the `detailedStatus` property in the health Zustand slice. This results in inaccurate or stale status information being shown to users, undermining trust in the system's observability features.

### Context
- The health Zustand slice manages live system health data, including service status, uptime, and alerts.
- `SystemStatusBanner` is intended to display real-time system health, but is not wired to the global state.
- Accurate, live health status is critical for user awareness, operational transparency, and incident response.

### Requirements
- Refactor `SystemStatusBanner` to consume the `detailedStatus` property from the health Zustand slice.
- Ensure the banner updates reactively as health data changes (e.g., via polling, WebSocket, or background refresh).
- Remove all hardcoded or static status strings from the component.
- Display key health indicators (e.g., overall status, affected services, last updated time) using live data.
- Add loading and error states for when health data is unavailable or fails to load.
- Add tests to verify correct data binding, reactivity, and UI rendering.
- Update documentation and code comments as needed.

### Acceptance Criteria
- [ ] `SystemStatusBanner` displays live health data from the Zustand slice.
- [ ] The banner updates reactively as health data changes.
- [ ] No hardcoded or static status strings remain in the component.
- [ ] Loading and error states are handled gracefully.
- [ ] Tests verify correct data binding and UI updates.
- [ ] Documentation is updated if necessary.

### Definition of Done
- All requirements and acceptance criteria are met.
- Code is reviewed, merged, and deployed to staging.
- No critical bugs or regressions are present.
- Stakeholders confirm that the banner reflects live system health accurately.

### Directory to Work On
- `project-portal/project-portal-web`
