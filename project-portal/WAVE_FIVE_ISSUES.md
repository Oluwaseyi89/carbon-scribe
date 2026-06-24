# WAVE FIVE ISSUES — CarbonScribe Project Portal
> 150 issues for `project-portal-backend` + 150 issues for `project-portal-web`
> Current state → Production. Each issue has an actionable title and one-sentence description.

---

## `project-portal-backend` — 150 Issues

### 🔴 Monitoring Module (All Behind `//go:build future`)



10. **Wire alert notification dispatch** — `internal/monitoring/alerts/notifications.go` is future-gated and alerts never trigger any downstream delivery even if the engine were live.



12. **Implement biomass estimator** — `internal/monitoring/processing/biomass_estimator.go` is future-tagged and biomass data cannot be produced for credit verification.

13. **Implement analytics trends service** — `internal/monitoring/analytics/trends.go` is future-gated so historical trend reports cannot be generated from monitoring data.

14. **Implement analytics performance service** — `internal/monitoring/analytics/performance.go` is future-tagged and performance benchmarks against SLA thresholds are unavailable.

---

### 🔴 Notifications Module (All Behind `//go:build future`)


18. **Build notification rules engine** — `internal/notifications/rules/engine.go` is future-tagged so no automated rules can trigger notifications from platform events.

19. **Build notification rules evaluator** — `internal/notifications/rules/evaluator.go` is future-gated and without it rule predicates are never checked against incoming events.

20. **Implement notification rules scheduler** — `internal/notifications/rules/scheduler.go` is future-gated, meaning time-based notification schedules (daily digests, weekly reports) cannot fire.

21. **Build notification template manager** — `internal/notifications/templates/manager.go` is future-tagged and there is no way to create or update notification templates at runtime.

22. **Build notification template renderer** — `internal/notifications/templates/renderer.go` is future-gated so template variable interpolation never executes.

23. **Build notification template store** — `internal/notifications/templates/store.go` is future-gated and templates cannot be persisted or read from any storage backend.

24. **Implement WebSocket connection handler (Lambda)** — `lambda_handlers/connect.go` is future-gated, leaving the AWS API Gateway WebSocket connection lifecycle unhandled.

25. **Implement WebSocket disconnect handler (Lambda)** — `lambda_handlers/disconnect.go` is future-gated, so disconnected sockets are never cleaned from the connection registry.

26. **Implement WebSocket default route handler (Lambda)** — `lambda_handlers/default.go` is future-gated, blocking all non-connect/disconnect WebSocket frame routing.

27. **Build WebSocket connection manager** — `internal/notifications/websocket/manager.go` is future-gated and no in-memory or Redis-backed connection registry exists.

28. **Build WebSocket router** — `internal/notifications/websocket/router.go` is future-gated so inbound WebSocket messages cannot be dispatched to topic handlers.

---

### 🔴 Background Workers (All Behind `//go:build future`)




32. **Implement breach monitor worker** — `cmd/workers/breach_monitor.go` is future-gated and geofence breach detection is never evaluated on a continuous basis.

33. **Implement data cleanup worker** — `cmd/workers/cleanup_worker.go` is future-gated so expired tokens, soft-deleted records, and temp uploads are never purged.

34. **Implement compliance audit worker** — `cmd/workers/compliance_audit_worker.go` is future-gated and scheduled compliance audit report generation never runs.

35. **Implement compliance request processor worker** — `cmd/workers/compliance_request_worker.go` is future-gated, leaving GDPR requests in `received` status indefinitely.

36. **Implement compliance retention worker** — `cmd/workers/compliance_retention_worker.go` is future-gated and data retention policies are never enforced on aging records.

37. **Implement invoice generation worker** — `cmd/workers/invoice_worker.go` is future-gated so invoices for completed payments are never automatically generated and emailed.

38. **Implement data retention enforcement worker** — `cmd/workers/retention_worker.go` is future-gated and user data is retained indefinitely beyond configured policy windows.

---

### 🔴 AWS Service Packages (All Behind `//go:build future`)



41. **Implement SES email delivery client** — `pkg/aws/ses_client.go` is future-gated and no transactional email can be sent via AWS Simple Email Service.

42. **Implement SNS push notification client** — `pkg/aws/sns_client.go` is future-gated, blocking mobile push and cross-service fan-out notifications.

43. **Implement EventBridge event bus client** — `pkg/events/event_bridge.go` is future-gated so platform events cannot be published to the AWS event bus for downstream services.

44. **Implement MQTT IoT telemetry client** — `pkg/iot/mqtt_client.go` is future-gated and no soil sensor or methane detector data can flow in via MQTT broker.

45. **Implement WebSocket protocol codec package** — `pkg/websocket/protocol.go` is future-gated and WS message framing/encoding is undefined.

46. **Implement WebSocket authentication package** — `pkg/websocket/auth.go` is future-gated so WebSocket upgrade requests are never authenticated.

---

### 🟠 Minting & Tokenization

47. **Remove mock contract client from production mint path** — `minting/service.go` falls back to `mockContractClient` when no admin private key is configured, silently producing fake token IDs in production.

48. **Replace placeholder owner Stellar address in minting** — A literal comment "placeholder address for demonstration" is used as the token recipient instead of the project's registered Stellar wallet address.

49. **Replace placeholder GeoHash in minting metadata** — The carbon asset GeoHash is a zero-value byte array rather than a hash of the project's actual registered boundary polygon.

50. **Move minting to an async background job** — The Soroban transaction submission blocks the HTTP handler for the full network round-trip duration, creating timeout risk under load.

51. **Add exponential backoff to Soroban RPC retry loop** — The minting retry loop retries immediately on every failure, hammering the RPC endpoint and exhausting rate limits.

---

### 🟠 Stellar / Soroban Integration

52. **Switch minting contract RPC URL from testnet to mainnet** — `defaultSorobanRPCURL` in `minting/service.go` points to `soroban-testnet.stellar.org`, which will mint to the wrong network in production.

53. **Switch methodology contract RPC URL from testnet to mainnet** — `defaultSorobanRPCURL` in `methodology/contract_client.go` also points to testnet, causing live methodologies to be registered on the wrong Stellar network.

54. **Replace MockSorobanClient in inventory service with live RPC** — `inventory.NewMockSorobanClient()` is wired into `main.go` and returns fake token balances to real users querying credit holdings.

55. **Complete XDR response decoding in Soroban inventory client** — The `BalanceOf` method in `soroban_client.go` returns an error for non-integer XDR types, making balance queries fragile for non-standard assets.

56. **Add transaction fee bump logic for Soroban operations** — No fee bump account or max fee strategy is defined, risking transaction failures under network congestion.

57. **Implement Stellar asset trustline setup for new buyers** — No endpoint creates a trustline on a buyer's Stellar account before attempting a carbon credit transfer, which will always fail.

---

### 🟠 Integration Module

58. **Encrypt integration credentials before database persistence** — `RegisterConnection` has an inline comment acknowledging credentials are saved plaintext; field-level encryption must be applied.

59. **Implement real outbound connectivity test for each provider** — `TestConnection` simulates success with a hardcoded 45 ms dummy latency value instead of making an actual network request to the provider.

60. **Implement webhook delivery retry queue** — `TriggerWebhook` has no retry mechanism, so a single failed webhook delivery is permanently lost.

61. **Add HMAC-SHA256 signature validation for incoming webhooks** — No signature header is verified on inbound webhook payloads, allowing any external party to forge platform events.

62. **Add PKCE and state parameter validation to OAuth callback** — The OAuth callback endpoint accepts `code` without verifying the `state` anti-CSRF parameter, enabling authorization code injection.

---

### 🟠 Compliance & GDPR

63. **Implement GDPR deletion request processor** — Deletion requests are accepted and stored but no background job ever executes the anonymization or hard deletion of user data.

64. **Implement GDPR data export pipeline** — Export requests are persisted but no process generates the JSON/CSV data package and delivers it to the requesting user.

65. **Implement GDPR correction processor** — Correction requests are stored in the database but no service applies the requested data corrections to the affected records.

66. **Audit-log all privacy request status transitions** — Status changes on GDPR requests are not written to the immutable cryptographic audit log, violating Article 30 record-keeping requirements.

67. **Enforce consent expiry during data processing operations** — Stored user consents are never checked for expiry before processing personal data, creating silent regulatory violations over time.

---

### 🟠 Quality Scoring

68. **Fix nil database injection in RecalculateScore** — `methodology.NewRepository(nil)` is called with a nil `*gorm.DB` in the quality scoring service, which will panic at runtime when the endpoint is called.

69. **Make scoring weights configurable per methodology type** — Quality score weights (registry authority, data quality, etc.) are hardcoded numbers that ignore the specific methodology registered for the project.

70. **Persist a history record on every score recalculation** — The service computes a new score but does not write to the `quality_score_history` table, making audit trails incomplete.

---

### 🟠 Search & Elasticsearch

71. **Trigger Elasticsearch reindex on project create/update** — Projects are persisted via GORM without any hook or event that pushes changes to the Elasticsearch index.

72. **Create index mappings on service startup** — No `CreateIndex` call with explicit field mappings is made at boot; dynamic mappings produce incorrect field types for numeric filters.

73. **Index document content for full-text search** — Uploaded PDFs and verification documents are stored in S3 but never parsed and indexed in Elasticsearch.

74. **Replace offset pagination with cursor-based pagination in search** — The search endpoint uses `from`/`size` offset pagination which degrades severely past 10,000 results.

---

### 🟠 Authentication

75. **Add email verification step to registration flow** — Registered users are immediately set to active status without verifying email ownership.

76. **Implement account lockout after repeated failed login attempts** — No brute-force protection exists; an attacker can attempt unlimited credential guesses without throttling.

77. **Implement password reset request and confirm flow** — No password reset token creation or confirmation endpoint exists in the auth module.

78. **Rotate refresh tokens on each use** — Refresh tokens are long-lived and not invalidated on use, enabling token replay if a refresh token is intercepted.

79. **Implement full SEP-10 challenge-response compliance** — The Stellar authenticator verifies signatures but does not enforce all SEP-10 spec requirements (domain, web auth endpoint, timebounds).

---

### 🟠 Security Hardening

80. **Add per-route rate limiting middleware** — No rate limiting is applied to any endpoint so a single IP can flood the login, minting, or payment APIs.

81. **Enforce maximum request body size** — No `http.MaxBytesReader` or Gin body limit is set, enabling denial-of-service through arbitrarily large request payloads.

82. **Validate uploaded document MIME type by content inspection** — MIME type is derived from the file extension rather than by reading magic bytes, enabling file type spoofing.

83. **Add security response headers middleware** — No `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, or `Strict-Transport-Security` headers are set on any response.

84. **Restrict CORS allowed origins from environment config** — The CORS middleware uses a wildcard origin allowlist; production should restrict to known frontend domains from configuration.

---

### 🟡 Database & Migrations

85. **Add migration files for monitoring module tables** — There are no `.sql` migration files in `database/migrations/` for any monitoring-related table.

86. **Add database index on `project_methodologies.project_id`** — Methodology lookups by project during credit calculation perform full table scans with no supporting index.

87. **Add database index on financing payments by project** — Payment queries filtered by `project_id` have no index, causing slow queries as the payments table grows.

88. **Enable foreign key constraints in GORM auto-migrate** — GORM's `AutoMigrate` does not create FK constraints, so referential integrity violations can silently corrupt relational data.

89. **Add composite index on compliance records for soft-delete filtering** — Soft-deleted compliance records are included in query results unless manually filtered, and there is no index supporting the `deleted_at IS NULL` predicate efficiently.

90. **Add TTL-indexed expiry column on inventory cache table** — The credit inventory cache has no indexed expiry column, so expired rows are never efficiently identified for invalidation.

---

### 🟡 Geospatial



---

### 🟡 Financing

95. **Wire Stripe payment intent creation to financing endpoints** — The `pkg/billing/stripe_client.go` file exists but no charge or payment-intent flow is called from any financing handler.

96. **Implement Stellar payout for revenue distribution** — Revenue distribution records are created with beneficiary splits but no Stellar payment operation is ever submitted to execute the payout.

97. **Replace hardcoded price quotes with pricing oracle** — Forward sale price quotes return static values rather than fetching live carbon credit pricing from an external data source.

98. **Generate and store forward sale contract PDF** — The contract hash is computed and stored, but no PDF document is generated and attached to the agreement record.

99. **Validate deposit payment status before marking forward sale active** — The deposit boolean field is toggled by the API caller without any payment gateway confirmation, allowing fraudulent activation.

100. **Implement Stripe webhook endpoint for async payment status** — No `/webhooks/stripe` endpoint exists to reactively update payment records from Stripe's asynchronous event stream.

---

### 🟡 Collaboration

101. **Add pagination to activity timeline list endpoint** — The activity timeline handler returns all records for a project with no `limit`/`offset`, risking OOM on high-activity projects.

102. **Enforce maximum comment thread nesting depth** — Comment threads allow unlimited recursive nesting with no depth cap, enabling malformed data that can cause stack overflows in recursive renderers.

103. **Trigger email notification on task assignment** — Assigning a task to a team member calls the collaboration service but does not dispatch any notification through the notifications module.

104. **Implement file attachment scan on resource library upload** — Documents uploaded to the collaboration resource library are stored directly to S3 without any malware or content scanning step.

---

### 🟡 Observability & Production Readiness

105. **Replace `log.Printf` with a structured leveled logger** — All logging across every module uses the stdlib `log` package without levels, making it impossible to filter noise in production.

106. **Instrument HTTP handlers with OpenTelemetry tracing spans** — The OTel SDK packages are listed in `go.mod` but no spans are created in any handler, leaving distributed traces empty.

107. **Export business KPI metrics via OpenTelemetry** — No custom counters or histograms track credits minted, payments processed, or users registered for operational monitoring.

108. **Add real dependency health checks to the `/health` endpoint** — The health endpoint reports `"status": "healthy"` unconditionally without probing DB, Elasticsearch, or MongoDB connectivity.

109. **Add a `/metrics` Prometheus endpoint** — No metrics scrape endpoint exists for infrastructure monitoring tools to collect request rates or latencies.

110. **Add `HEALTHCHECK` instruction to Dockerfile** — The Dockerfile contains no `HEALTHCHECK` directive, so Docker and Kubernetes cannot detect an unhealthy container.

111. **Validate all required secrets on application startup** — The service starts successfully even with empty JWT secret, Stripe key, or DB password environment variables, deferring failures to runtime.

112. **Tune GORM database connection pool for production** — GORM's default pool (`MaxOpenConns=0`, unlimited) provides no backpressure and can exhaust database connections under load.

113. **Implement graceful HTTP request draining on SIGTERM** — The server shuts down on `SIGINT` by immediately stopping the listener without waiting for in-flight requests to complete.

114. **Add idempotency key support for payment creation endpoints** — Payment endpoints have no idempotency key header check, so a client retrying after a network error can create duplicate charges.

---

### 🟡 Testing Gaps

115. **Add unit tests for the financing service layer** — No `_test.go` files exist in `internal/financing/` outside of the tokenization sub-package.

116. **Add integration tests for geospatial API endpoints** — No integration tests cover the full request-to-database flow for the geospatial module endpoints.

117. **Add unit tests for the compliance service** — No test files exist under `internal/compliance/` despite GDPR processing being a legally sensitive code path.

118. **Add unit tests for the notifications service** — No test files exist in `internal/notifications/` and the template rendering logic is entirely untested.

119. **Add assertions to Elasticsearch indexer tests** — `internal/search/indexer_test.go` contains setup but no assertion on whether documents are actually indexed correctly.

120. **Add load tests for the synchronous minting endpoint** — There is no performance baseline establishing how many concurrent minting requests the synchronous handler can sustain.

---

### 🟡 Code Quality & Correctness

121. **Refactor minting service to inject project repository instead of direct DB query** — Minting directly queries the database for project data to avoid circular dependency, creating an implicit dependency that bypasses the service layer.

122. **Fix concurrent map write in mock methodology contract client** — The mock client uses an unsynchronized `map[int]MethodologyMeta` that will cause a data race under concurrent test execution.

123. **Standardize error wrapping with `%w` across all packages** — Dozens of `fmt.Errorf` calls across service layers omit `%w`, breaking `errors.Is` and `errors.As` unwrapping for callers.

124. **Replace hardcoded magic numbers with named constants** — Hardcoded values like `45` ms dummy latency, platform fee percentages, and retry counts are scattered without explanation or named constants.

125. **Propagate request context to all GORM database calls** — Several repository methods call GORM without passing `ctx`, preventing request cancellation from reaching the database driver.

---

### 🟡 Documents Module

126. **Implement IPFS uploader in the legacy `document` package** — `internal/document/ipfs_uploader.go` is future-gated and the `document` package (separate from `documents`) has no working implementation.

127. **Implement PDF generator in the legacy `document` package** — `internal/document/pdf_generator.go` is future-gated; the `documents` package falls back to `ExportPDFPlaceholder` which returns a literal string.

128. **Remove duplicate `document` vs `documents` package ambiguity** — Two separate packages (`internal/document` and `internal/documents`) exist for similar functionality, creating confusion and maintenance overhead.

---

### 🟡 Settings Module

129. **Implement profile avatar CDN upload pipeline** — The profile settings endpoint accepts a photo URL but performs no upload to the CDN; the caller must supply a pre-hosted URL.

130. **Enforce billing plan feature limits via middleware** — Billing settings record a plan tier but no middleware or service layer checks enforce usage limits based on the plan.

---

### 🟡 Reports Module

131. **Implement scheduled report email delivery** — The report scheduler persists `ReportSchedule` records but no worker or cron job triggers email delivery of scheduled report outputs.

132. **Use the `xuri/excelize` dependency for Excel export** — The excelize library is declared in `go.mod` but is referenced nowhere in the reports export handler.

133. **Implement live benchmark dataset ingestion from external registries** — Benchmark datasets are served as static fixtures with no pipeline ingesting current data from Verra or Gold Standard.

---

### 🟡 Methodology Module

134. **Implement on-chain methodology metadata retrieval** — The methodology contract client can mint methodology NFTs but has no implemented `GetMetadata` function to read them back from the contract.

135. **Implement on-chain methodology token burning** — No `Burn` function is implemented in the methodology contract client despite it being a required lifecycle operation.

136. **Add batch methodology validation endpoint** — Only single-methodology validation exists; bulk onboarding of many projects against multiple methodologies has no batch API.

---

### 🟡 Financing — Deeper

137. **Implement formal tokenization workflow state machine** — State transitions (calculated → minting → minted → verified) are unconstrained, allowing any caller to set any status directly.

138. **Enforce methodology cap validator for concurrent mint jobs** — The cap validator is called once per job at job creation time but does not hold a lock during the async Soroban transaction, enabling over-issuance under race conditions.

139. **Validate beneficiary Stellar address format before storing** — Revenue distribution beneficiary addresses are stored without checking they are valid Stellar public keys (G... format).

---

### 🟡 Auth — Deeper

140. **Add multi-factor authentication (TOTP) support** — No TOTP or SMS MFA factor is implemented in the auth module, leaving high-value accounts protected by password alone.

141. **Implement enterprise SAML/SSO federation** — Authentication is JWT-only with no SAML 2.0 or OIDC federation support needed for enterprise customer onboarding.

142. **Write all auth events to the immutable audit log** — Login, logout, token refresh, and password change events are not written to the cryptographic audit trail in `pkg/cryptography`.

143. **Implement explicit session revocation endpoint** — No endpoint allows a user or admin to invalidate a specific refresh token or revoke all active sessions.

144. **Enforce role-based route guards for all protected API groups** — JWT claims carry a `role` field but several sensitive route groups (financing, compliance) do not verify role in their middleware chain.

---

### 🟡 Collaboration — Deeper

145. **Implement real-time presence tracking** — No WebSocket subscription mechanism tracks which users are currently viewing a project, so the collaboration UI has no live presence indicators.

146. **Add `X-User-ID` audit trail for collaboration mutations** — Comment creation and task assignment calls accept `user_id` from the request body rather than extracting it from the verified JWT claim.

147. **Return project membership check before allowing task creation** — The task creation endpoint does not verify that the acting user is a member of the project, allowing cross-project task injection.

148. **Add maximum resource file size validation in resource library handler** — The resource library upload endpoint has no server-side file size cap, enabling storage exhaustion uploads.

149. **Paginate team members list endpoint** — The team members endpoint returns all members of a project in a single response with no pagination, which degrades for large teams.

150. **Add cascade delete for collaboration data when a project is deleted** — Deleting a project leaves orphaned tasks, comments, and invitations in the database because no cascade rule is enforced.

---
---

## `project-portal-web` — 150 Issues

### 🔴 Empty / Stub Files (Zero Implementation)


---

### 🔴 Missing Pages / Routes


9. **Create developer project verification page** — `/developer/projects/[id]/verification/` directory exists with no `page.tsx`, blocking the verification workflow.


13. **Create carbon credit marketplace page** — The sidebar links reference a marketplace but no route, layout, or page component exists for it.

14. **Create Stellar transaction history page** — There is no page for viewing on-chain retirement and transfer history despite the backend `/api/v1/stellar` endpoints being available.

15. **Create user profile page at `/profile`** — No `/profile` route exists; users can only update profile data through the Settings page tab and cannot view a standalone profile.

16. **Create credit portfolio page for project owners** — No dedicated page displays a project owner's minted token portfolio, on-chain balances, or retirement certificates.

---

### 🔴 Stellar / Blockchain UI Wiring

17. **Wire `carbonTokens.ts` to TokenizationWizard complete step** — After minting, the wizard does not call any frontend Stellar function to confirm the transaction on-chain before marking the step complete.

18. **Display minting transaction hash as a Stellar Expert link** — The minting API response includes `mint_transaction_hash` but the TokenizationWizard does not show it as a clickable Stellar Explorer URL.

19. **Implement Stellar wallet connect button for SEP-10 login** — The backend supports SEP-10 challenge-response authentication but there is no wallet connect button or flow in the login page UI.

20. **Add Stellar address format validation to wallet fields** — Any text is accepted in wallet address inputs without validating that it is a valid Stellar public key (`G...` format, 56 characters).

---

### 🟠 State Management Gaps

24. **Compose integrations slice into the main store** — The integrations slice lives in `store/` root but is not included in the main `lib/store/store.ts` composed store, creating a separate store instance.



29. **Persist `currentProjectId` across page reloads** — The selected project ID in the collaboration slice is in-memory only and cleared on page reload, requiring manual re-navigation.

30. **Fix race condition between store rehydration and token refresh** — `onRehydrateStorage` fires `refreshSession` before the `setHydrated` call completes, potentially using a stale auth state for the refresh.

---

### 🟠 API Client Issues


32. **Add Authorization header to `integration.api.ts` fetch calls** — The integration API similarly uses raw `fetch` without the auth header, leaving all integration CRUD endpoints unauthenticated from the frontend.


34. **Deduplicate concurrent identical API requests** — Multiple components mounting simultaneously issue the same API call without deduplication, creating redundant network traffic.

36. **Validate that API base URL uses HTTPS in production builds** — No check prevents the `NEXT_PUBLIC_API_URL` from being an insecure `http://` URL in a production deployment.

37. **Add retry logic with backoff for network failures** — Transient network errors result in immediate failures with no automatic retry mechanism in the API client layer.

---

### 🟠 Authentication UI

38. **Implement email verification prompt after registration** — Successful registration redirects immediately to the portal without displaying any email verification prompt or holding the session.

39. **Add password strength indicator to registration form** — The registration form accepts passwords of any length with no visual strength meter or minimum complexity feedback.

40. **Build forgot-password and reset-password pages** — No `/forgot-password` or `/reset-password` routes or page components exist in the application.

41. **Add MFA setup and entry flow to auth pages** — No TOTP or SMS multi-factor authentication prompt exists in the login or security settings flow.

42. **Redirect to originally requested URL after login** — The login handler always redirects to `/` regardless of the protected URL the user originally attempted to visit.

43. **Show session expiry countdown before token expiration** — No UI warning is shown to the user before their session expires; the next API call simply fails silently.

44. **Add CAPTCHA to registration and login forms** — No bot protection (reCAPTCHA, hCaptcha, or Cloudflare Turnstile) is applied to public authentication endpoints.

45. **Prevent back-navigation to login after authenticated redirect** — Authenticated users can press the browser back button to reach the login page, causing a confusing double-login state.

---

### 🟠 Monitoring Components Wiring


47. **Wire live uptime to `UptimeStatsCards`** — Uptime percentage cards display static mock values instead of data fetched from `fetchUptimeApi`.

48. **Wire live service data to `ComponentStatusGrid`** — The grid renders placeholder tiles without calling `fetchServicesApi` or binding to the `services` slice state.

49. **Wire live alert count to `ActiveAlertsWidget`** — The widget shows a hardcoded zero count instead of the `.length` of the `alerts` array from the health store.

50. **Populate `AlertDetailModal` with alert data from health store** — The modal renders a generic container without populating any fields from the selected `SystemAlert` object.

51. **Wire `AlertHistoryTimeline` to a paginated alert history endpoint** — The timeline renders empty; no backend call is made to retrieve historical alert records.

52. **Connect `AcknowledgeAlertButton` to `acknowledgeAlert` action** — The button renders but its click handler does not dispatch `acknowledgeAlert` from the health slice or call the API.

53. **Wire `ServiceHealthTable` to live service health data** — The table renders placeholder rows without binding to the `services` array from the health store.

54. **Persist `HealthCheckConfigurator` form submissions to backend** — The configurator form submits changes locally only; no API call saves the new health check configuration.

55. **Wire `CheckResultsTimeline` to health check results endpoint** — No `fetchChecksHistory` API call exists; the timeline renders perpetually empty.

56. **Bind `MetricsTimeSeries` chart to health store metrics data** — The chart component renders an empty container without binding the `metrics` array from the health slice to the Recharts series.

57. **Fix `MetricSelector` to re-render chart on selection change** — Selecting a metric updates component-local state but the parent chart does not observe the change and re-render.

58. **Implement `ChartExport` download handler** — The export button has an `onClick` handler that logs a "not implemented" message instead of converting the chart to an image.

59. **Wire `DependencyGraph` to live dependency data** — The graph renders static example nodes instead of the `dependencies` array returned by `fetchDependenciesApi`.

60. **Connect `NodeDetailPanel` to selected node from dependency graph** — The panel shows generic placeholder text regardless of which graph node the user has selected.

61. **Wire `DailyReportViewer` to reports API** — The viewer renders a date picker with no API call to fetch and display the selected day's monitoring report.

62. **Compute `SLATracker` percentages from live uptime API** — SLA compliance percentages are hardcoded instead of being calculated from the `uptimeStats` object in the health store.

63. **Fetch maintenance schedules for `MaintenanceCalendar`** — The calendar renders empty with no call to a maintenance schedule endpoint, making scheduled downtime invisible to users.

64. **Bind `UptimeChart` to historical uptime API data** — The chart is rendered with dummy static data points rather than data from `fetchUptimeApi`.

---

### 🟠 Financing Components Wiring

65. **Implement `PaymentManagement` component with live API** — The payment management UI renders form fields but makes no API calls for payment history listing, initiation, or status updates.

66. **Add real-time status polling to `TokenizationStatus`** — Minting status is updated only on manual refresh; no interval polling or WebSocket subscription tracks in-progress minting jobs.

67. **Add forward sale contract PDF download button** — The `ForwardSale` component shows the contract hash but provides no button to download the actual PDF contract document.

68. **Populate buyer dropdown in `ForwardSale` from team members API** — The buyer ID field is a free-text input instead of a dropdown populated from `fetchMembers` in the collaboration API.

---

### 🟠 Reports Components Wiring

69. **Trigger `fetchReports` on `ReportsList` mount** — The reports list renders empty without calling the `listReports` action on component mount.

70. **Submit sharing permissions from `ReportSharing` to API** — The sharing modal renders checkboxes for roles but clicking save does not call any API endpoint to persist the permissions.

71. **Poll running execution status in `ExecutionHistory`** — Running executions show a static spinner badge; no interval re-fetch updates the status until the page is manually refreshed.

72. **Wire `ScheduleForm` submit to report scheduling API action** — The form submits locally but the API call to `apiCreateSchedule` is never dispatched through the reports store.

73. **Add server-side pagination to `DatasetExplorer` table** — The dataset table renders all returned rows with no pagination controls, causing the DOM to bloat for large datasets.

74. **Implement export file download handler in `ExecutionHistory`** — The download icon in each execution row dispatches no API call to retrieve the output file from the backend.

75. **Call `apiFetchBenchmarkDatasets` from `BenchmarkComparison`** — Datasets in the benchmark comparison view are rendered from a local static array rather than the live datasets API.

---

### 🟠 Settings Components Wiring

76. **Add confirmation dialog before API key revocation in `APIKeysTab`** — The revoke button deletes an API key immediately without presenting any confirmation prompt to the user.

77. **Embed Stripe Elements in `BillingTab` for payment method updates** — The billing tab shows plan information and a "Update Payment Method" button, but no Stripe payment form is embedded.

78. **Wire GDPR export button in `ComplianceTab` to submission API** — The data export button renders but dispatches no API call to submit a GDPR export request to the backend.

79. **Persist notification channel preferences from `NotificationsTab` to API** — Notification toggles update local React state only; no API call saves preferences to the backend settings service.

80. **Pass PKCE state parameter in `IntegrationsTab` OAuth connect flow** — The OAuth integration connect button builds an authorization URL with no `state` parameter, enabling CSRF on the callback.

81. **Implement avatar upload in `ProfileTab`** — The profile tab renders a file input for the avatar but performs no upload operation; the avatar URL is only editable as a plain text field.

82. **Build 2FA setup wizard in `ProfileTab` security section** — The security settings section mentions two-factor authentication but contains no setup flow, QR code generation, or backup codes component.

---

### 🟠 Map / Geospatial Components

83. **Integrate Mapbox GL JS SDK into `CarbonMap`** — The Mapbox GL library is not installed in `package.json`, making it impossible to render an interactive map without adding the dependency and implementation.

84. **Add GeoJSON polygon drawing tool to `CarbonMap`** — No draw control exists for users to define project land boundaries on the map interactively.

85. **Implement satellite vs. base map layer toggle in `CarbonMap`** — No layer switcher control allows toggling between the satellite raster layer and a standard base map.

86. **Render NDVI heatmap overlay on map** — Despite backend NDVI tile endpoints existing, no NDVI raster layer is added to any map view.

87. **Implement time-lapse date range slider in `TimeLapseViewer`** — The component file is empty; the entire time-lapse satellite imagery browsing feature is absent.

---

### 🟠 Projects Components

88. **Open edit form when pencil icon is clicked on project detail page** — The edit icon renders on the project detail page header but its click handler does not open any edit form or modal.

89. **Render financing components in project financing tab** — The financing tab name appears in the detail page tab list but its panel renders no content.

90. **Render monitoring components in project monitoring tab** — The monitoring tab renders an empty panel with no components or data.

91. **Add verification status section to project detail page** — The project detail page has no section for credit verification status, audit results, or verification document links.

92. **Debounce project filter input to avoid per-keystroke API calls** — The filter input in the projects list triggers a full API refetch on every character typed without debounce.

93. **Add multi-select and bulk actions to projects list** — No multi-select checkbox or bulk archive/export action exists in the projects list page.

94. **Validate project area against uploaded GeoJSON polygon area** — The hectares input accepts any value without cross-checking against the calculated area of the uploaded boundary geometry.

---

### 🟠 Collaboration Components

95. **Subscribe to WebSocket for real-time comment updates** — New comments posted by other users are only visible after a manual page refresh; no WebSocket listener exists.

96. **Add edit and delete actions to existing comment items** — Comments can be created but no edit pencil or delete trash icon exists on an already-posted comment.

97. **Add Markdown rendering to comment display** — Comment text is rendered as plain text rather than formatted Markdown, stripping any formatting users intend.

98. **Trigger task due-date reminder notification from the frontend** — Task due dates are set but no frontend logic calls the notification API to schedule reminder alerts.

99. **Implement drag-and-drop card reordering within `TaskBoard` columns** — Task cards within a column cannot be reordered by dragging; the board layout is static once loaded.

100. **Add upload progress bar to `ResourceUploader`** — The uploader shows a loading spinner but no percentage progress indicator during file transfer.

101. **Restrict upload file types in `ResourceUploader`** — The file input accepts any MIME type including executables; no `accept` attribute or client-side validation restricts type.

102. **Show real-time typing indicator in `CommentForm`** — No typing indicator is shown to other team members when a user is composing a comment.

---

### 🟡 Accessibility

103. **Add `aria-label` to all icon-only buttons** — Across the UI, dozens of icon buttons (edit, delete, close, expand) have no `aria-label`, making them inaccessible to screen readers.

104. **Implement full keyboard navigation for the portal sidebar** — The sidebar cannot be fully navigated using only a keyboard; focus management between nav items is broken.

105. **Add focus trap to all modal dialogs** — `InviteUserModal`, `DeleteProjectDialog`, and `TaskDetailModal` do not trap keyboard focus within the overlay, allowing tab to escape to background content.

106. **Restore visible focus rings on interactive elements** — Tailwind's `outline-none` utility is applied broadly, removing focus rings without providing an accessible alternative.

107. **Fix color contrast for colored status badges** — Green success, amber warning, and red error badges on the project list and task board do not meet the WCAG AA 4.5:1 contrast ratio.

108. **Add `alt` text to all decorative and informational images** — Several project thumbnail images and icon SVGs throughout the portal have empty or missing `alt` attributes.

---

### 🟡 Performance

109. **Implement route-based code splitting for Reports and Analytics pages** — The full module code for these heavy pages is bundled in the main chunk, inflating initial page load size.

110. **Use Next.js `<Image>` for all user-uploaded thumbnails and avatars** — User profile photos and project thumbnails are rendered with `<img>` tags, missing automatic optimization, resizing, and lazy loading.

111. **Memoize costly Zustand slice selectors with `useShallow`** — Several components subscribe to large store slices with object selectors, triggering re-renders on every unrelated state update.

112. **Add virtual scrolling to the projects list** — All fetched project cards are mounted in the DOM simultaneously without virtualization, causing layout thrashing for users with large project portfolios.

113. **Lazy-load Recharts library on chart-containing pages only** — Recharts is imported at module scope in pages that may not even render a chart, adding unnecessary weight to the initial bundle.

114. **Debounce window resize event handlers in map components** — Resize listeners in map and chart components fire on every pixel of movement without debounce, causing excessive layout recalculation.

---

### 🟡 Security

115. **Add Content Security Policy to `next.config.ts` headers** — No CSP header is configured in the Next.js headers config, leaving the app vulnerable to cross-site scripting injection.

116. **Sanitize user-generated comment content before rendering** — Comment text from the API is rendered directly into the DOM without DOMPurify sanitization, enabling stored XSS.

117. **Validate post-login redirect URLs to prevent open redirect** — The redirect URL parameter accepted after login is not validated against an allowlist, enabling phishing via crafted redirect URLs.

118. **Replace the ineffective `xss-clean` package** — `xss-clean` is a server-side Express middleware that has no effect in a Next.js/React client-side application and should be removed.

119. **Add CSRF double-submit cookie or `SameSite=Strict` enforcement** — Mutating requests from the frontend do not include a CSRF token; relying on SameSite alone is insufficient for cross-origin form submissions.

120. **Redact sensitive fields from Zustand `persist` storage** — The Zustand persist configuration writes `token`, `refreshToken`, and `user` to `localStorage` without encrypting them.

---

### 🟡 Testing Gaps

121. **Add unit tests for `TokenizationWizard` multi-step state logic** — The wizard has complex multi-step form state with API calls at each step but no associated test file exists.

122. **Add unit tests for `ForwardSale` component** — The forward sale pricing and submission form has no test coverage despite handling financial transaction data.

123. **Add unit tests for `auth.slice` actions** — Login, logout, refresh, and hydration behaviors in the auth slice are entirely untested.

124. **Add integration tests for the projects Zustand slice** — No tests verify that the projects slice correctly serializes requests, handles pagination, or processes error responses from the backend.

125. **Add Playwright E2E test for the project creation flow** — No E2E test covers the create project → project detail → invite team member workflow.

126. **Add Playwright E2E test for the full tokenization wizard** — No E2E test covers the credit calculation → review → mint → complete flow.

127. **Add Playwright E2E test for protected route auth redirect** — No E2E test verifies that unauthenticated access to a protected route redirects to login.

128. **Fix test setup global Axios mock leaking between suites** — `test/setup.ts` installs a global Axios/fetch mock that affects unrelated test suites, causing false positives and false failures.

---

### 🟡 Next.js / Production Config

129. **Configure `images.remotePatterns` in `next.config.ts`** — No image domain allowlist is set, blocking Next.js `<Image>` from loading any external avatar or thumbnail URLs.

130. **Add environment variable schema validation (Zod) on startup** — The app starts and loads pages even when `NEXT_PUBLIC_API_URL` or other required env vars are undefined.

131. **Enable `reactStrictMode` in `next.config.ts`** — Strict mode is not enabled, hiding React lifecycle correctness bugs that would surface during double-invocation of effects.

132. **Add security response headers to `vercel.json`** — The vercel deployment config has no `headers` block setting `X-Frame-Options`, `X-Content-Type-Options`, or `Referrer-Policy`.

133. **Enable `strictNullChecks` in `tsconfig.json`** — Strict null checking is not enabled, allowing potential null dereferences to pass type checking silently.

134. **Replace all `any` types in geospatial and API client files** — `geometry: any`, `response.data: any`, and similar annotations across the API layer bypass TypeScript's type safety.

135. **Add ESLint configuration for consistent code quality** — No `.eslintrc` or ESLint entry in `package.json` is configured; code quality linting is absent entirely.

136. **Add Prettier for consistent code formatting** — No Prettier configuration or format script is defined, resulting in inconsistent code style across contributors.

---

### 🟡 UI / UX Polish

137. **Show empty state illustration in `DatasetExplorer` when no datasets exist** — When the dataset list is empty the table renders an empty `<tbody>` with no empty-state illustration or call-to-action.

138. **Add progress toast for long-running operations (minting, report runs)** — Minting and report execution show only a static loading spinner; no progress steps or percentage indicator is displayed during the wait.

139. **Add pagination controls to execution history list** — The execution history table renders all past runs without pagination, overflowing the layout as history grows.

140. **Paginate the full activity timeline in project detail** — The activity timeline fetches and renders all project events in a single response with no load-more or infinite scroll.

141. **Standardize loading skeleton component across all pages** — Some pages use hand-written `animate-pulse` divs, others use `ProjectLoadingSkeleton`, and some have no skeleton at all.

142. **Reset financing form and show created record after forward sale submission** — After a forward sale is submitted successfully, only a toast is shown; the form does not clear or navigate to the newly created agreement.

143. **Expose a dark mode toggle in the portal navbar** — `ThemeContext` is defined and can be consumed but no toggle control is surfaced in the navigation bar or settings page.

144. **Add breadcrumb trail to project detail and developer sub-pages** — No breadcrumb component exists, leaving users without navigational context when deep in project sub-pages.

145. **Fix active link highlighting for nested routes in `PortalSidebar`** — The active state is computed with an exact path match which fails to highlight parent route links when on child routes.

146. **Wire `DeleteProjectDialog` confirm button keyboard shortcut (Enter/Escape)** — The dialog renders confirm and cancel buttons but Enter and Escape keyboard bindings are not implemented.

147. **Add unread notification badge to portal navbar** — There is no notification indicator dot, counter badge, or bell icon in the navbar reflecting unread notifications.

148. **Add print media styles for report pages** — Report pages have no `@media print` stylesheet; printing a report produces an unstyled, unusable browser printout.

149. **Add internationalization (i18n) framework setup** — The portal has no i18n configuration despite serving a global audience of land managers, developers, and buyers across many languages.

150. **Implement user profile detail page at `/profile` route** — No standalone profile page exists; users must navigate into Settings to view or edit their own information.
