# Team and Community Integration Issues

This backlog was generated from a scan of:
- Backend: Gin collaboration and project modules in project-portal-backend
- Frontend: Next.js Team UI, collaboration store/API wiring, and collaboration components in project-portal-web

## Backend-Frontend Correlation Snapshot

### Already Correlated (existing API + frontend client/store)
- GET /api/v1/collaboration/projects/:id/members <-> fetchMembersApi / fetchMembers
- DELETE /api/v1/collaboration/projects/:id/members/:userId <-> removeMemberApi / removeMember
- POST /api/v1/collaboration/projects/:id/invite <-> inviteUserApi / inviteUser
- GET /api/v1/collaboration/projects/:id/invitations <-> fetchInvitationsApi / fetchInvitations
- GET /api/v1/collaboration/projects/:id/activities <-> fetchActivitiesApi / fetchActivities
- GET /api/v1/collaboration/projects/:id/comments <-> fetchCommentsApi / fetchComments
- POST /api/v1/collaboration/comments <-> createCommentApi / createComment
- GET /api/v1/collaboration/projects/:id/tasks <-> fetchTasksApi / fetchTasks
- POST /api/v1/collaboration/tasks <-> createTaskApi / createTask
- PATCH /api/v1/collaboration/tasks/:id <-> updateTaskApi / updateTask
- GET /api/v1/collaboration/projects/:id/resources <-> fetchResourcesApi / fetchResources
- POST /api/v1/collaboration/resources <-> createResourceApi / createResource

### Gaps Found
- Collaboration routes exist in backend but are not registered in API bootstrap.
- Dedicated Team page at /team is hard-coded and not connected to store or backend.
- Team page community features (stats, events, training, resources) have no backend endpoints yet.
- No dedicated team/collaboration hooks layer in frontend; components call store actions directly.
- Authorization context is not consistently enforced in team management UI and backend endpoint behavior.
- Team member payloads are insufficient for rich Team cards (display name/avatar/email/phone/location).
- Invitation lifecycle is incomplete for frontend workflows (resend, revoke, accept/decline).
- Team lists are missing server-side pagination/filter/search contracts required for scale.
- Team/community features lack dedicated end-to-end test coverage.

---

## Issues For Contributors

## 1) Register Collaboration Routes in Backend API Bootstrap (P0)
- Type: Backend bug fix
- Problem:
  - Collaboration endpoints are defined in internal/collaboration/routes.go, but not registered in cmd/api/main.go.
  - Frontend calls /api/v1/collaboration/* and will fail if routes are unavailable.
- Scope:
  - Wire collaboration.NewRepository, collaboration.NewService, collaboration.NewHandler in bootstrap.
  - Call collaboration.RegisterRoutes(router, collaborationHandler) or refactor to router group style under /api/v1.
  - Ensure health/root endpoint docs reflect correct collaboration path.
- Acceptance Criteria:
  - /api/v1/collaboration/projects/:id/members responds from running server.
  - Existing frontend collaboration actions (members/invitations/tasks/comments/resources) return successful responses in local dev.
  - API route listing in root endpoint is consistent with actual mounted paths.

## 2) Add API Contract Tests for Collaboration Endpoints (P0)
- Type: Backend tests
- Problem:
  - Current regression risk is high; route registration issue was not caught.
- Scope:
  - Add integration tests to verify endpoint registration and response codes for key collaboration routes.
  - Include smoke test for create comment, create task, and invite user payload validation.
- Acceptance Criteria:
  - Tests fail if collaboration routes are not mounted.
  - CI catches path regressions and payload/validation regressions.

## 3) Integrate Team Page (/team) with Real Team Data (P1)
- Type: Frontend integration
- Problem:
  - app/(portal)/team/page.tsx uses local arrays for teamMembers and does not call backend.
- Scope:
  - Replace hard-coded teamMembers with store data from collaboration members endpoints.
  - Use selected project context (or add project selector tied to project IDs).
  - Reuse existing collaboration components where possible (TeamMembersList, PendingInvitationsList, InviteUserModal).
- Acceptance Criteria:
  - Team member list reflects backend data for selected project.
  - Search and project filter operate on fetched entities.
  - Invite/remove actions update UI via store and backend responses.

## 4) Build Team and Community API Surface for /team Features (P1)
- Type: Backend feature
- Problem:
  - Team page includes community stats, events, training status, and resource summaries that have no matching backend endpoints.
- Scope:
  - Add endpoints under /api/v1/team or /api/v1/community for:
    - community stats summary
    - upcoming events
    - training/certification records
    - team resource categories summary
  - Define models and repository methods for each domain.
- Acceptance Criteria:
  - New endpoints return non-mock data and are documented.
  - Frontend can retrieve and render these sections without local mock arrays.

## 5) Wire Community Stats and Events UI to Backend (P1)
- Type: Frontend integration
- Problem:
  - communityStats and upcomingEvents in Team page are static.
- Scope:
  - Add store slice/api client methods for stats and events.
  - Replace hard-coded sections with fetched data and loading/empty/error states.
  - Support create event and view all events actions.
- Acceptance Criteria:
  - Stats cards and events list are API-driven.
  - Actions are functional and not placeholder buttons.
  - Error and loading states are visible and consistent with existing UX patterns.

## 6) Wire Training and Certification Table to Backend (P1)
- Type: Full-stack integration
- Problem:
  - Training progress table is static and disconnected from members/tasks.
- Scope:
  - Add backend training endpoints and persistence for assignments and certification status.
  - Add frontend APIs/store methods and replace static training rows.
  - Implement assign training action and progress updates.
- Acceptance Criteria:
  - Table rows come from backend.
  - Assign training updates backend and reflects in UI refresh.
  - Certification state and progress are persisted.

## 7) Introduce Collaboration Hooks Layer for Team Domain (P2)
- Type: Frontend architecture
- Problem:
  - There is no hooks abstraction; components trigger store logic directly, reducing reusability and testability.
- Scope:
  - Add hooks such as useTeamMembers, useProjectInvitations, useProjectTasks, useProjectResources, useCommunityStats, useCommunityEvents.
  - Centralize fetch-on-mount patterns and selectors.
- Acceptance Criteria:
  - Team/collaboration components consume hooks rather than duplicating useEffect fetch logic.
  - Hook unit tests cover loading, success, and error states.

## 8) Enforce Role-Based Team Management Rules End-to-End (P2)
- Type: Full-stack security/authorization
- Problem:
  - Frontend manage permissions are inferred from any member role in the list, not current user role context.
  - Backend handlers do not show explicit role authorization checks in collaboration operations.
- Scope:
  - Frontend: derive canManage from authenticated user membership role for current project.
  - Backend: enforce permissions for invite/remove/update actions.
  - Add 403 handling in UI and API clients.
- Acceptance Criteria:
  - Non-managers cannot see or execute restricted team actions.
  - Backend rejects unauthorized operations even if frontend is bypassed.
  - UI shows clear unauthorized feedback.

## 9) Add Team/Community Telemetry and Audit Events (P3)
- Type: Full-stack observability
- Problem:
  - Team/community actions lack consistent telemetry for product and compliance analysis.
- Scope:
  - Emit structured activity/audit events for invite, remove, training assign/complete, event create/update.
  - Add frontend tracking hooks for key user actions in Team tab.
- Acceptance Criteria:
  - Key team/community actions are traceable in logs/activity streams.
  - Event schema is documented and consistent.

## 10) Document Team Integration Contracts and Developer Onboarding (P3)
- Type: Documentation
- Problem:
  - New contributors lack a single source of truth for team/community API contracts and frontend integration points.
- Scope:
  - Add docs describing endpoint contracts, payload shapes, store flow, and UI mapping.
  - Include local setup and test commands for team/community features.
- Acceptance Criteria:
  - Contributors can implement a Team feature without reverse-engineering multiple files.
  - Docs include examples for at least one read and one write flow.

## 11) Add Auth Middleware and Identity-Derived Writes for Collaboration (P1)
- Type: Backend security/architecture
- Problem:
  - Collaboration handlers currently accept critical identity fields from request body in write flows.
  - This allows impersonation risk and inconsistent actor attribution.
- Scope:
  - Protect collaboration routes with auth middleware.
  - Derive actor user ID from token/context for create comment/task/resource and activity logging.
  - Ignore or reject user-provided identity fields that should be server-controlled.
- Acceptance Criteria:
  - Authenticated user identity is used for created_by/uploaded_by/user_id actor fields.
  - Anonymous requests receive 401 for protected collaboration endpoints.
  - Activity log user attribution is consistent and server-generated.

## 12) Enrich Team Member API with User Profile Data (P1)
- Type: Backend feature
- Problem:
  - Team UI requires member display data (name, avatar, contact, location), but collaboration member records currently expose mostly IDs/role metadata.
- Scope:
  - Add response DTO or joined query that includes profile fields from auth/settings user profile sources.
  - Keep backward compatibility for existing members endpoint consumers.
- Acceptance Criteria:
  - Team member response includes display-ready fields for cards/tables.
  - Team UI no longer needs to render raw user IDs as primary member identity.
  - Existing consumers continue to function.

## 13) Implement Invitation Lifecycle Endpoints and UI Actions (P1)
- Type: Full-stack feature
- Problem:
  - Team workflows need more than create/list invitations to be operational.
- Scope:
  - Backend: add resend, revoke/cancel, and accept/decline invitation endpoints.
  - Frontend: add action buttons and state transitions in pending invitation components.
  - Ensure invitation status transitions are validated server-side.
- Acceptance Criteria:
  - Invitation status updates are persisted and reflected in UI without manual refresh.
  - Invalid transitions are rejected with clear errors.
  - Invite lifecycle supports admin and invited-user actions.

## 14) Add Team List Pagination, Filtering, and Search Contracts (P2)
- Type: Full-stack performance/usability
- Problem:
  - Team page currently uses client-side filtering of static/mock data and lacks scalable query contracts.
- Scope:
  - Backend: add query params for pagination, role/status/project filters, and text search.
  - Frontend: wire search/filter controls in Team page to API query params and store state.
- Acceptance Criteria:
  - Team list supports server-driven pagination and filtering.
  - URL/state is preserved for current search/filter selections.
  - Large member sets remain responsive.

## 15) Create Team/Community Normalized Slice in Store (P2)
- Type: Frontend architecture
- Problem:
  - Existing collaboration slice is project-tab oriented and does not model the full Team page domain (events/training/community summaries) cohesively.
- Scope:
  - Add dedicated team slice (or modular extension) for members, stats, events, training records, filters, and pagination metadata.
  - Prevent state collisions with existing project collaboration tabs.
- Acceptance Criteria:
  - Team page reads from a single cohesive state module.
  - Existing project collaboration tabs continue to work without regressions.
  - State updates are predictable and testable.

## 16) Add Realtime Updates for Team and Collaboration Activity (P2)
- Type: Full-stack feature
- Problem:
  - Team and collaboration views are pull-based only and can become stale during active multi-user operations.
- Scope:
  - Emit events for invitation updates, member changes, task/comment/resource mutations.
  - Subscribe frontend Team and project collaboration views to updates (websocket or SSE).
- Acceptance Criteria:
  - Team/invitation/activity/task sections update without manual refresh.
  - Reconnect and fallback behavior is handled gracefully.

## 17) Add Full Team/Community Test Matrix (P1)
- Type: Full-stack QA
- Problem:
  - Existing coverage does not validate end-to-end team workflows across backend and frontend.
- Scope:
  - Backend integration tests for authz, lifecycle transitions, pagination, and validation.
  - Frontend component/store tests for loading/error/success paths.
  - E2E tests for invite member, remove member, event create, and training assignment journeys.
- Acceptance Criteria:
  - CI executes Team feature test suite and fails on regressions.
  - At least one critical happy path and one permissions failure path are covered per core flow.

## 18) Add Data Migration and Seed Strategy for Team Community Features (P3)
- Type: Backend/data operations
- Problem:
  - New community/events/training models need schema rollout and dev/staging seed data for realistic testing.
- Scope:
  - Add migrations for new tables/indices.
  - Add non-production seed data for team members, events, and training records.
  - Document rollback strategy.
- Acceptance Criteria:
  - Fresh environment can run migrations and load seed data reliably.
  - Team page renders meaningful non-mock records in local/staging.

---

## Suggested Implementation Order
1. Issue 1 (route registration fix)
2. Issue 2 (contract tests)
3. Issue 11 (auth middleware and identity-derived writes)
4. Issue 12 (member profile enrichment)
5. Issue 3 (real team members on Team page)
6. Issue 13 (invitation lifecycle)
7. Issues 4-6 (community/events/training backend + UI)
8. Issue 14 (pagination/filter/search contracts)
9. Issue 8 (role-based authorization hardening)
10. Issues 15-16 (state architecture and realtime)
11. Issue 17 (full test matrix)
12. Issues 9-10 and 18 (telemetry/docs/data ops)

## Notes For Reviewers
- Collaboration endpoint/type shapes are mostly aligned between backend models and frontend types.
- The biggest immediate blocker is endpoint availability from route registration.
- The largest product gap is the /team page, which is currently mock-first and needs API-backed implementation.
