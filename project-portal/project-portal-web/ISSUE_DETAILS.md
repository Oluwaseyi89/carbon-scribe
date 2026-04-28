# Objective:
Ensure all user-triggered mutations (create, update, delete actions) provide immediate feedback via toast notifications, improving clarity and user confidence in the application.

## Background
Currently, some actions—such as project creation, integration connect/disconnect, and other mutations—do not provide toast notifications to inform users of success or failure. This can leave users uncertain about the outcome of their actions. Consistent toast notifications enhance UX by confirming actions, surfacing errors, and guiding next steps.

## Tasks
1. **Audit All Mutation Actions**
   - Identify all places where users perform mutations (create, update, delete, connect, disconnect, etc.).
   - Document which actions currently lack toast notifications.

2. **Design Standard Toast Notification Patterns**
   - Define standard toast types (success, error, info, warning) and their appearance.
   - Specify message structure: concise, actionable, and context-aware.
   - Ensure toasts are accessible (screen reader friendly, keyboard dismissible).

3. **Implement Toast Notifications for All Mutations**
   - Add toast notifications to all mutation actions, including but not limited to:
     - Project creation, update, deletion
     - Integration connect/disconnect
     - Settings changes
     - API key management
     - Billing actions
   - Ensure both success and error states are handled.

4. **Consistency & UX**
   - Use a single toast notification system/component throughout the app.
   - Avoid duplicate or excessive notifications.
   - Allow users to dismiss toasts manually; auto-dismiss after a short duration.

5. **Testing & Validation**
   - Test all mutation flows to ensure toasts appear as expected for both success and error cases.
   - Validate accessibility and responsiveness of toast notifications.

6. **Documentation**
   - Document toast notification usage, patterns, and guidelines for future mutations.
   - Provide examples for adding toasts to new features.

## Acceptance Criteria
- All mutation actions provide clear toast notifications for both success and error outcomes.
- Toasts are consistent, accessible, and non-intrusive.
- Documentation is updated with toast notification best practices.

---

## Directory to Work On:

`project-portal/project-portal-web`
