# agent-service — Implementation Issues

150 issue titles for turning the `agent-service` scaffold into a working service, grouped by area. Each title has a one-sentence description. Numbers are stable IDs for cross-referencing, not a required creation order — see the scaffold's `TODO` comments for where each maps to code.

Entries already filed as GitHub issues (labeled `agent-service`) are removed from this list to avoid duplicate creation — their number is left retired rather than reused. See issues [#573](https://github.com/CarbonScribe/carbon-scribe/issues/573)–[#582](https://github.com/CarbonScribe/carbon-scribe/issues/582) for #3, #23, #31, #38, #51, #63, #75, #87, #99, #114.

## Foundation & Infra (1–14)

1. **Add Dockerfile for agent-service** — Package the service into a production container image following the health-check pattern used in corporate-platform-backend.
2. **Add docker-compose entry for local development** — Let contributors run agent-service alongside corporate-platform and project-portal with one command.
4. **Add readiness check for Anthropic API reachability** — Verify the Anthropic client can reach the API before reporting the service ready.
5. **Add readiness check for corporate-platform-backend reachability** — Confirm the upstream service is reachable before marking agent-service ready to serve traffic.
6. **Add readiness check for project-portal-backend reachability** — Confirm the upstream Go service is reachable before marking agent-service ready to serve traffic.
7. **Add structured JSON logging** — Replace ad-hoc `console.log`/`console.error` calls with a structured logger (e.g. pino) for production log aggregation.
8. **Add request ID propagation middleware** — Generate or forward a request ID on every inbound call and attach it to all downstream logs and audit entries.
9. **Add graceful shutdown handling** — Close the HTTP server and flush pending audit-log writes on SIGTERM/SIGINT.
10. **Add environment variable validation on startup** — Fail fast with a clear error if required env vars are missing or malformed, instead of surfacing failures at request time.
11. **Extend `.env.example` as new config lands** — Add entries for rate limits, timeouts, and log level as those features are introduced.
12. **Set up Kubernetes deployment manifest** — Add a `k8s/deployment.yaml` mirroring the liveness/readiness probe configuration documented in `implementation.md`.
13. **Add request timeout middleware** — Enforce a maximum per-request duration so a stuck LLM call cannot hang a connection indefinitely.
14. **Document local development setup in agent-service** — Add a README covering install, env setup, and how to run against local corporate-platform/project-portal instances.

## LLM Client & Reliability (15–22)

15. **Add retry/backoff configuration to the Anthropic client** — Tune `maxRetries`/timeout on the shared client in `src/llm/client.ts` for production traffic.
16. **Add per-agent cost logging** — Record `usage.input_tokens`/`output_tokens` per run so LLM spend is attributable to a specific agent and requester.
17. **Add a token-budget guard per agent run** — Cap max tool-call iterations/tokens per request to prevent a runaway agentic loop from generating unbounded cost.
18. **Add prompt-caching to shared system prompts** — Apply `cache_control` to each agent's system prompt since it's static across requests.
19. **Handle Anthropic typed errors distinctly** — Catch `RateLimitError`, `APIConnectionError`, and `APIStatusError` separately in each agent and map them to distinct HTTP responses.
20. **Add a circuit breaker for the Anthropic client** — Stop issuing new LLM calls temporarily after repeated failures, instead of retrying into a known outage.
21. **Add streaming support for long-running agent runs** — Let long compliance-report drafts stream partial output back to the caller instead of blocking until completion.
22. **Pin and document the Claude model version per agent** — Decide whether all four agents share `AGENT_MODEL` or need per-agent model overrides, and document the choice.

## Audit Log (23–29)

24. **Record full tool-call inputs/outputs in the audit log** — Extend `AgentAuditEntry` to capture tool arguments and results, not just tool names.
25. **Link agent-service audit entries to corporate-platform's audit-trail module** — Decide whether agent decisions should be pushed into the existing `audit-trail` service so compliance history lives in one place.
26. **Add an audit log query endpoint** — Expose a read API so support/compliance staff can look up what an agent did for a given `requestId`.
27. **Add an audit log retention policy** — Define and implement how long agent audit entries are kept, matching whatever policy `project-portal-backend/internal/compliance/retention` already uses.
28. **Redact sensitive fields in audit log entries** — Ensure company financial data or PII isn't written to logs in plaintext.
29. **Add audit log write failure handling** — Decide what happens to an agent run if the audit write itself fails (block the response? log a fallback warning?).

## Guardrails & Approval (30–37)

30. **Design the human-approval workflow for `needs-approval` results** — Define what UI/API a reviewer uses to approve or reject a drafted agent action.
32. **Add an approval-decision audit trail** — Record who approved or rejected an agent-drafted action, and when.
33. **Add an "auto-approved" path for low-risk read-only actions** — Allow actions with no side effects (e.g. a discovery search) to skip the approval gate while mutating actions never do.
34. **Add rate limiting on approval requests** — Prevent a single agent from flooding the approval queue with runs.
35. **Add a rejection-feedback loop** — Let a reviewer's rejection reason be fed back into a follow-up agent run instead of being a dead end.
36. **Write guardrail unit tests covering every action type** — Ensure `checkApproval` behaves correctly for each of the four agents' action types.
37. **Document the guardrail policy for contributors** — Explain in-repo why agents draft/recommend only and never auto-execute financial or on-chain actions.

## Auth & Middleware (38–45)

39. **Add per-caller rate limiting** — Reuse or mirror corporate-platform-backend's `rate-limit` module to cap requests per calling service/user.
40. **Add request body size limits** — Protect the service from oversized payloads in `express.json()`.
41. **Add CORS configuration** — Decide which origins are allowed to call agent-service directly, if any.
42. **Add Helmet security headers** — Match corporate-platform-backend's use of `helmet` for baseline HTTP hardening.
43. **Add request validation middleware using the existing Zod schemas** — Validate `AgentRunRequest` bodies at the route boundary instead of trusting the cast in each controller.
44. **Add an API-key mechanism for external callers** — Decide if any caller outside corporate-platform/project-portal needs access, and if so how it's authenticated.
45. **Write tests for the auth middleware** — Cover missing token, wrong token, and valid token cases for `requireInternalAuth`.

## Shared Types & Contracts (46–50)

46. **Publish `AgentRunRequest`/`AgentRunResult` as a shared npm package** — Let corporate-platform-backend (TypeScript) import the same types instead of redeclaring them.
47. **Generate a Go-compatible schema for project-portal** — Since project-portal-backend is Go, produce an OpenAPI/JSON-schema contract it can codegen from.
48. **Add an OpenAPI spec for agent-service's own routes** — Document `/agents/*/run` request/response shapes for API consumers.
49. **Version the agent run API** — Decide on a versioning strategy (`/v1/agents/...`) before external callers depend on the current shape.
50. **Add a shared `AgentCitation` validation rule** — Enforce that compliance-facing agents cannot return `status: "drafted"` without at least one citation.

## Corporate-Platform Client (51–62)

52. **Implement `listMarketplaceCredits(filters)`** — Back the discovery agent's `search_marketplace_credits` tool with a real marketplace query.
53. **Implement `getComplianceFramework(framework)`** — Fetch framework-specific reporting requirements from the `csrd`/`cbam`/`corsia`/`sbti`/`ghg-protocol` modules.
54. **Implement `getRetirementHistory(companyId)`** — Back the compliance-report agent's evidence-gathering tool.
55. **Implement `getAuditTrailEntries(companyId, period)`** — Pull prior audit-trail records into compliance-report evidence.
56. **Add auth token injection for corporate-platform client calls** — Ensure the client sends whatever credential corporate-platform-backend's guards expect, once decided in issue #38.
57. **Add retry logic to the corporate-platform HTTP client** — Handle transient 5xx/network failures from corporate-platform-backend gracefully.
58. **Add response schema validation for corporate-platform client calls** — Validate responses with Zod so a backend contract change fails loudly instead of silently.
59. **Add a mock/fixture mode for the corporate-platform client** — Let agent developers run agents locally without a live corporate-platform-backend instance.
60. **Write integration tests against a corporate-platform-backend test instance** — Verify the client's real HTTP calls against actual API contracts, not just mocks.
61. **Add pagination support for portfolio/marketplace list endpoints** — Handle large result sets from corporate-platform-backend without truncating agent context.
62. **Add request/response logging for corporate-platform client calls** — Make it possible to debug what data an agent actually saw when investigating a bad output.

## Project-Portal Client (63–74)

64. **Implement `getProject(projectId)`** — Fetch project details for both the PDD-draft and alert-triage agents.
65. **Implement `getMonitoringAlerts(projectId, since)`** — Back the alert-triage agent's correlation tool.
66. **Implement `getSatelliteTimeseries(projectId, metric)`** — Fetch NDVI/biomass time series for alert-triage correlation.
67. **Implement `getIoTSensorReadings(projectId, since)`** — Fetch soil/methane/wildlife sensor data for alert-triage correlation.
68. **Implement `getWeatherContext(projectId, since)`** — Fetch weather data so alert-triage can distinguish seasonal variation from genuine events.
69. **Add auth token injection for project-portal client calls** — Ensure the client sends whatever credential project-portal-backend's `internal/auth` package expects.
70. **Add retry logic to the project-portal HTTP client** — Handle transient 5xx/network failures from project-portal-backend gracefully.
71. **Add response schema validation for project-portal client calls** — Validate responses with Zod so a Go backend contract change fails loudly instead of silently.
72. **Add a mock/fixture mode for the project-portal client** — Let agent developers run agents locally without a live project-portal-backend instance.
73. **Write integration tests against a project-portal-backend test instance** — Verify the client's real HTTP calls against actual API contracts, not just mocks.
74. **Add request/response logging for project-portal client calls** — Make it possible to debug what data an agent actually saw when investigating a bad output.

## Discovery Agent (75–86)

76. **Finish `search_marketplace_credits` tool implementation** — Call the real `listMarketplaceCredits` client method once issue #52 lands.
77. **Add a `get_company_preferences` tool** — Let the discovery agent fetch a buyer's saved compliance framework and co-benefit priorities instead of requiring them in every request.
78. **Add citation enforcement to discovery agent output** — Reject or flag any recommendation that doesn't reference a specific marketplace credit ID.
79. **Add a discovery-agent evaluation harness** — Build a small labeled set of buyer queries and expected shortlist quality to catch prompt regressions.
80. **Add pagination/result-limiting to discovery output** — Cap the shortlist size so the agent doesn't return an unusably long list.
81. **Add price-sensitivity handling to the discovery prompt** — Ensure the agent respects `maxPricePerTonne` as a hard constraint, not a soft preference.
82. **Write unit tests for `discovery.tools.ts`** — Test `search_marketplace_credits` input validation independent of the LLM loop.
83. **Write integration tests for `POST /agents/discovery/run`** — Cover the full request/response cycle including auth and audit logging.
84. **Add explainability output to discovery results** — Require the agent to state why each shortlisted credit fits the stated criteria, not just list them.
85. **Handle the empty-results case gracefully** — Define what the discovery agent returns when no credits match the buyer's criteria.
86. **Add discovery-agent response caching** — Cache identical buyer-criteria queries for a short TTL to reduce redundant LLM calls.

## PDD-Draft Agent (87–98)

88. **Finish `match_methodology` tool implementation** — Call the real `getMethodologies` client method once issue #63 lands.
89. **Add a `get_documentation_requirements` tool** — Fetch the specific document checklist for a matched methodology.
90. **Add missing-documentation flagging to PDD output** — Ensure the agent explicitly lists what's missing rather than drafting around gaps.
91. **Add a PDD section-completeness check** — Validate that every required PDD section is either drafted or explicitly flagged as incomplete before returning.
92. **Add multi-language support consideration for PDD drafting** — Decide whether farmer-submitted project data may arrive in non-English languages and how the agent should handle it.
93. **Write unit tests for `pdd-draft.tools.ts`** — Test `match_methodology` input validation independent of the LLM loop.
94. **Write integration tests for `POST /agents/pdd-draft/run`** — Cover the full request/response cycle including auth and audit logging.
95. **Add a PDD-draft evaluation harness** — Build a labeled set of project submissions and expected methodology matches to catch regressions.
96. **Add hallucination guardrails for numeric estimates** — Ensure the agent never invents carbon-removal figures it wasn't given grounded data for.
97. **Add a draft-to-PDF export path** — Let a completed PDD draft be exported in the same format `pkg/pdf` already produces for other documents.
98. **Handle partial/malformed project submissions** — Define agent behavior when required onboarding fields are missing entirely.

## Compliance-Report Agent (99–113)

100. **Finish `get_company_retirement_evidence` tool implementation** — Call the real evidence-gathering client methods once issues #54–55 land.
101. **Implement CSRD-specific report drafting logic** — Map gathered evidence into the CSRD report structure.
102. **Implement CBAM-specific report drafting logic** — Map gathered evidence into the CBAM report structure.
103. **Implement CORSIA-specific report drafting logic** — Map gathered evidence into the CORSIA report structure.
104. **Implement SBTi-specific report drafting logic** — Map gathered evidence into the SBTi report structure.
105. **Implement GHG Protocol-specific report drafting logic** — Map gathered evidence into the GHG Protocol Scope 1/2/3 report structure.
106. **Enforce `status: "needs-approval"` on every compliance-report output** — Add a test guaranteeing this agent can never return anything else, given the regulatory stakes.
107. **Add gap/inconsistency flagging to compliance-report output** — Require the agent to explicitly list evidence gaps rather than silently omitting sections.
108. **Add per-framework citation requirements** — Ensure every factual claim in a drafted report links back to a specific retirement/portfolio record.
109. **Write unit tests for `compliance-report.tools.ts`** — Test `get_company_retirement_evidence` input validation independent of the LLM loop.
110. **Write integration tests for `POST /agents/compliance-report/run`** — Cover the full request/response cycle including auth and audit logging.
111. **Add a compliance-report evaluation harness** — Build labeled evidence sets per framework and grade drafted-report accuracy against them.
112. **Add legal/compliance sign-off review before enabling in production** — Since this agent's output has regulatory exposure, get compliance-team review before pilot.
113. **Add reporting-period validation** — Reject requests where `periodStart`/`periodEnd` don't align with the framework's required reporting cycle.

## Alert-Triage Agent (114–125)

115. **Finish `get_monitoring_signals` tool implementation** — Call the real satellite/IoT/weather client methods once issues #64–68 land.
116. **Add an escalation-decision output field** — Have the agent return a clear escalate/suppress/needs-more-data verdict, not just prose.
117. **Wire escalation to project-portal's notification pipeline** — Once approved, actually push a confirmed alert into `internal/notifications`.
118. **Add a false-positive feedback loop** — Let a human's "this wasn't real" correction be logged and used to tune future triage decisions.
119. **Add a triage-latency budget** — Since alerts are time-sensitive, cap how long this agent run is allowed to take before falling back to the existing rule-based alert.
120. **Write unit tests for `alert-triage.tools.ts`** — Test `get_monitoring_signals` input validation independent of the LLM loop.
121. **Write integration tests for `POST /agents/alert-triage/run`** — Cover the full request/response cycle including auth and audit logging.
122. **Add an alert-triage evaluation harness** — Build a labeled set of historical alerts (true positive/seasonal/sensor fault) and grade triage accuracy against them.
123. **Add a sensor-fault classification path** — Let the agent distinguish "sensor fault" from "no event" as distinct outcomes with different follow-up actions.
124. **Add multi-project batch triage support** — Let one run triage several pending alerts at once instead of one HTTP call per alert.
125. **Document the triage agent's relationship to the existing rule-based alerting** — Clarify in-repo that this agent supplements, not replaces, existing alert rules.

## Testing (126–135)

126. **Add a shared test-fixture library for agent requests** — Centralize sample `AgentRunRequest` payloads used across all four agents' test suites.
127. **Add end-to-end tests spanning agent-service → corporate-platform-backend** — Run against a docker-composed stack to catch cross-service contract drift.
128. **Add end-to-end tests spanning agent-service → project-portal-backend** — Run against a docker-composed stack to catch cross-service contract drift.
129. **Add test coverage reporting to CI** — Extend `.github/workflows/agent-service.yml` with a coverage step and a minimum-coverage gate.
130. **Add contract tests for the Anthropic tool schemas** — Verify each `betaZodTool` input schema stays in sync with what its `run` function expects.
131. **Add load testing for concurrent agent runs** — Establish how many simultaneous LLM-backed requests the service can handle before degrading.
132. **Add a test double for the Anthropic client** — Let agent logic be tested without making real API calls, for fast CI runs.
133. **Add snapshot tests for each agent's system prompt** — Catch accidental prompt-wording regressions during refactors.
134. **Add tests for the audit log's failure modes** — Verify agent runs behave correctly when the audit sink is unavailable.
135. **Add a smoke-test script for post-deploy verification** — Hit `/health` and each agent's `/run` endpoint after a deploy to confirm the service came up correctly.

## CI/CD & DevOps (136–144)

136. **Add a security-scanning step to CI** — Run `npm audit` or a dependency-vulnerability scanner as part of `agent-service.yml`.
137. **Add a Dockerfile build-and-push step to CI** — Publish a container image on merge to `main`, once issue #1 lands.
138. **Add branch-protection-friendly required-status-check naming** — Confirm the workflow's job name is registered as a required check for `agent-service/**` PRs.
139. **Add a staging deployment workflow** — Auto-deploy agent-service to a staging environment on merge to `develop`.
140. **Add secrets management for `ANTHROPIC_API_KEY` in CI/CD** — Wire the key into GitHub Actions secrets and the deployment target's secret store, not `.env` files.
141. **Add a lockfile-drift check to CI** — Fail the build if `package-lock.json` is out of sync with `package.json`.
142. **Add Prettier formatting check as a separate CI step** — Currently folded into lint; consider splitting so formatting failures are distinguishable from rule violations.
143. **Add a bundle-size or cold-start-time check** — Track agent-service's Node startup time so it doesn't regress as dependencies grow.
144. **Add Dependabot configuration for agent-service** — Keep `@anthropic-ai/sdk`, `express`, and other dependencies patched automatically.

## Docs & Onboarding (145–150)

145. **Write a CONTRIBUTING guide for agent-service** — Explain the tool-runner pattern, guardrail philosophy, and how to add a new agent.
146. **Document the four agents' system prompts and their rationale** — Capture why each prompt is worded the way it is, so future edits don't erode the safety framing.
147. **Add an architecture diagram showing agent-service's place in the 7-layer platform** — Visualize how it calls into corporate-platform and project-portal as tool providers.
148. **Document the guardrail/approval model for non-engineering stakeholders** — Give compliance and product a plain-language explanation of what agents can and cannot do autonomously.
149. **Add a runbook for on-call** — Cover common failure modes (Anthropic API outage, upstream backend down, audit sink failure) and how to respond.
150. **Document how to add a fifth agent** — Write a step-by-step guide using the existing four as a template, for when the platform needs a new agent capability.
