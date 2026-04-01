import { test, expect } from '@playwright/test';

test.describe('Team Member Management', () => {
  test.beforeEach(async ({ page }) => {
    // Login as a project manager
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', 'manager@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('/dashboard');
    
    // Navigate to team page
    await page.goto('/team');
    await page.waitForLoadState('networkidle');
  });

  test('should display team members list', async ({ page }) => {
    // Check that team members are displayed
    await expect(page.locator('[data-testid="team-members-list"]')).toBeVisible();
    
    // Check for member cards
    const memberCards = page.locator('[data-testid="member-card"]');
    await expect(memberCards.first()).toBeVisible();
    
    // Check member information is displayed
    await expect(page.locator('[data-testid="member-name"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="member-role"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="member-joined-date"]').first()).toBeVisible();
  });

  test('should invite new team member', async ({ page }) => {
    // Click invite button
    await page.click('[data-testid="invite-member-button"]');
    
    // Wait for modal to appear
    await expect(page.locator('[data-testid="invite-modal"]')).toBeVisible();
    
    // Fill invitation form
    await page.fill('[data-testid="invite-email-input"]', 'newmember@example.com');
    await page.selectOption('[data-testid="invite-role-select"]', 'Contributor');
    
    // Submit invitation
    await page.click('[data-testid="send-invitation-button"]');
    
    // Wait for modal to close
    await expect(page.locator('[data-testid="invite-modal"]')).not.toBeVisible();
    
    // Check for success message
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Invitation sent successfully');
    
    // Check that invitation appears in invitations list
    await page.click('[data-testid="invitations-tab"]');
    await expect(page.locator('[data-testid="invitation-card"]').filter({ hasText: 'newmember@example.com' })).toBeVisible();
  });

  test('should remove team member with confirmation', async ({ page }) => {
    // Find a non-owner member
    const memberCard = page.locator('[data-testid="member-card"]').filter({ hasText: 'Contributor' }).first();
    
    // Click remove button
    await memberCard.locator('[data-testid="remove-member-button"]').click();
    
    // Wait for confirmation dialog
    await expect(page.locator('[data-testid="confirmation-dialog"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-dialog"]')).toContainText('Are you sure you want to remove');
    
    // Confirm removal
    await page.click('[data-testid="confirm-remove-button"]');
    
    // Wait for success message
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Member removed successfully');
    
    // Verify member is no longer in list
    await expect(memberCard).not.toBeVisible();
  });

  test('should not allow removing owner', async ({ page }) => {
    // Find owner member card
    const ownerCard = page.locator('[data-testid="member-card"]').filter({ hasText: 'Owner' }).first();
    
    // Remove button should not be visible for owner
    await expect(ownerCard.locator('[data-testid="remove-member-button"]')).not.toBeVisible();
  });

  test('should show loading states during operations', async ({ page }) => {
    // Test loading state when fetching members
    await page.goto('/team');
    await expect(page.locator('[data-testid="loading-skeleton"]')).toBeVisible();
    
    // Wait for loading to complete
    await page.waitForSelector('[data-testid="team-members-list"]', { state: 'visible' });
    await expect(page.locator('[data-testid="loading-skeleton"]')).not.toBeVisible();
    
    // Test loading state during member removal
    const memberCard = page.locator('[data-testid="member-card"]').filter({ hasText: 'Contributor' }).first();
    await memberCard.locator('[data-testid="remove-member-button"]').click();
    await page.click('[data-testid="confirm-remove-button"]');
    
    // Check for loading state on button
    await expect(memberCard.locator('[data-testid="remove-member-button"]')).toBeDisabled();
    await expect(memberCard.locator('[data-testid="loading-spinner"]')).toBeVisible();
  });

  test('should handle errors gracefully', async ({ page }) => {
    // Mock network error for member removal
    await page.route('/api/collaboration/projects/*/members/*', route => route.abort());
    
    const memberCard = page.locator('[data-testid="member-card"]').filter({ hasText: 'Contributor' }).first();
    await memberCard.locator('[data-testid="remove-member-button"]').click();
    await page.click('[data-testid="confirm-remove-button"]');
    
    // Check for error message
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Failed to remove member');
    
    // Check for retry button
    await expect(page.locator('[data-testid="retry-button"]')).toBeVisible();
  });

  test('should support search and filtering', async ({ page }) => {
    // Test search functionality
    await page.fill('[data-testid="search-input"]', 'John');
    
    // Should filter members
    const memberCards = page.locator('[data-testid="member-card"]');
    const visibleMembers = await memberCard.count();
    
    // Clear search
    await page.fill('[data-testid="search-input"]', '');
    
    // All members should be visible again
    await expect(page.locator('[data-testid="member-card"]')).toHaveCountGreaterThan(visibleMembers);
    
    // Test project filter
    await page.click('[data-testid="project-filter-dropdown"]');
    await page.click('[data-testid="project-option"]:has-text("Kenyan Agroforestry")');
    
    // Should filter by project
    await expect(page.locator('[data-testid="member-card"]').filter({ hasText: 'Kenyan Agroforestry' })).toBeVisible();
  });

  test('should display member statistics', async ({ page }) => {
    // Check team statistics section
    await expect(page.locator('[data-testid="team-stats"]')).toBeVisible();
    await expect(page.locator('[data-testid="total-members-count"]')).toBeVisible();
    await expect(page.locator('[data-testid="active-members-count"]')).toBeVisible();
    await expect(page.locator('[data-testid="pending-invitations-count"]')).toBeVisible();
    
    // Verify counts are numbers
    const totalMembersText = await page.locator('[data-testid="total-members-count"]').textContent();
    expect(totalMembersText).toMatch(/\d+/);
  });

  test('should support pagination for large teams', async ({ page }) => {
    // Mock large team data
    await page.addInitScript(() => {
      // Mock API to return paginated data
      window.mockTeamMembers = Array.from({ length: 50 }, (_, i) => ({
        id: `member-${i}`,
        user_id: `user-${i}`,
        name: `Team Member ${i}`,
        role: i % 4 === 0 ? 'Owner' : i % 3 === 0 ? 'Manager' : i % 2 === 0 ? 'Contributor' : 'Viewer',
        joined_at: '2023-01-01T00:00:00Z',
      }));
    });
    
    // Check pagination controls
    await expect(page.locator('[data-testid="pagination-controls"]')).toBeVisible();
    await expect(page.locator('[data-testid="next-page-button"]')).toBeVisible();
    
    // Navigate to next page
    await page.click('[data-testid="next-page-button"]');
    
    // Verify page changed
    await expect(page.locator('[data-testid="current-page"]')).toContainText('2');
  });
});

test.describe('Team Invitation Lifecycle', () => {
  test.beforeEach(async ({ page }) => {
    // Login as a project manager
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', 'manager@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('/dashboard');
    
    // Navigate to team page
    await page.goto('/team');
    await page.click('[data-testid="invitations-tab"]');
    await page.waitForLoadState('networkidle');
  });

  test('should create and display new invitation', async ({ page }) => {
    // Click invite button
    await page.click('[data-testid="invite-member-button"]');
    
    // Fill invitation form
    await page.fill('[data-testid="invite-email-input"]', 'newuser@example.com');
    await page.selectOption('[data-testid="invite-role-select"]', 'Contributor');
    await page.click('[data-testid="send-invitation-button"]');
    
    // Wait for modal to close
    await expect(page.locator('[data-testid="invite-modal"]')).not.toBeVisible();
    
    // Check invitation appears in list
    await expect(page.locator('[data-testid="invitation-card"]').filter({ hasText: 'newuser@example.com' })).toBeVisible();
    await expect(page.locator('[data-testid="invitation-status"]').filter({ hasText: 'Pending' })).toBeVisible();
  });

  test('should resend pending invitation', async ({ page }) => {
    // Find a pending invitation
    const invitationCard = page.locator('[data-testid="invitation-card"]').filter({ hasText: 'Pending' }).first();
    
    // Click resend button
    await invitationCard.locator('[data-testid="resend-invitation-button"]').click();
    
    // Wait for confirmation dialog
    await expect(page.locator('[data-testid="confirmation-dialog"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-dialog"]')).toContainText('Resend invitation');
    
    // Confirm resend
    await page.click('[data-testid="confirm-resend-button"]');
    
    // Check for success message
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Invitation resent successfully');
    
    // Verify expiry date was updated
    const expiryDate = await invitationCard.locator('[data-testid="invitation-expiry"]').textContent();
    expect(expiryDate).toMatch(/\d{1,2}\/\d{1,2}\/\d{4}/); // MM/DD/YYYY format
  });

  test('should cancel pending invitation', async ({ page }) => {
    // Find a pending invitation
    const invitationCard = page.locator('[data-testid="invitation-card"]').filter({ hasText: 'Pending' }).first();
    
    // Click cancel button
    await invitationCard.locator('[data-testid="cancel-invitation-button"]').click();
    
    // Wait for confirmation dialog
    await expect(page.locator('[data-testid="confirmation-dialog"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-dialog"]')).toContainText('Cancel invitation');
    
    // Confirm cancellation
    await page.click('[data-testid="confirm-cancel-button"]');
    
    // Check for success message
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Invitation cancelled successfully');
    
    // Verify invitation status changed to cancelled
    await expect(invitationCard.locator('[data-testid="invitation-status"]')).toHaveText('Cancelled');
  });

  test('should not allow actions on accepted invitations', async ({ page }) => {
    // Find an accepted invitation
    const invitationCard = page.locator('[data-testid="invitation-card"]').filter({ hasText: 'Accepted' }).first();
    
    // Action buttons should not be visible
    await expect(invitationCard.locator('[data-testid="resend-invitation-button"]')).not.toBeVisible();
    await expect(invitationCard.locator('[data-testid="cancel-invitation-button"]')).not.toBeVisible();
  });

  test('should not allow actions on expired invitations', async ({ page }) => {
    // Find an expired invitation
    const invitationCard = page.locator('[data-testid="invitation-card"]').filter({ hasText: 'Expired' }).first();
    
    // Action buttons should not be visible
    await expect(invitationCard.locator('[data-testid="resend-invitation-button"]')).not.toBeVisible();
    await expect(invitationCard.locator('[data-testid="cancel-invitation-button"]')).not.toBeVisible();
  });

  test('should display invitation statistics', async ({ page }) => {
    // Check invitation statistics
    await expect(page.locator('[data-testid="invitation-stats"]')).toBeVisible();
    await expect(page.locator('[data-testid="pending-count"]')).toBeVisible();
    await expect(page.locator('[data-testid="accepted-count"]')).toBeVisible();
    await expect(page.locator('[data-testid="expired-count"]')).toBeVisible();
    await expect(page.locator('[data-testid="cancelled-count"]')).toBeVisible();
    
    // Verify counts are numbers
    const pendingCount = await page.locator('[data-testid="pending-count"]').textContent();
    expect(pendingCount).toMatch(/\d+/);
  });

  test('should filter invitations by status', async ({ page }) => {
    // Test status filter dropdown
    await page.click('[data-testid="invitation-status-filter"]');
    
    // Filter by pending
    await page.click('[data-testid="status-option"]:has-text("Pending")');
    
    // Should only show pending invitations
    const visibleInvitations = page.locator('[data-testid="invitation-card"]');
    const pendingInvitations = visibleInvitations.filter({ hasText: 'Pending' });
    const acceptedInvitations = visibleInvitations.filter({ hasText: 'Accepted' });
    
    await expect(pendingInvitations).toHaveCount(await visibleInvitations.count());
    await expect(acceptedInvitations).toHaveCount(0);
    
    // Reset filter
    await page.click('[data-testid="invitation-status-filter"]');
    await page.click('[data-testid="status-option"]:has-text("All")');
  });

  test('should handle invitation errors gracefully', async ({ page }) => {
    // Mock network error for invitation creation
    await page.route('/api/collaboration/projects/*/invite', route => route.abort());
    
    // Try to create invitation
    await page.click('[data-testid="invite-member-button"]');
    await page.fill('[data-testid="invite-email-input"]', 'error@example.com');
    await page.selectOption('[data-testid="invite-role-select"]', 'Contributor');
    await page.click('[data-testid="send-invitation-button"]');
    
    // Check for error message
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Failed to send invitation');
    
    // Check for retry button
    await expect(page.locator('[data-testid="retry-button"]')).toBeVisible();
  });
});

test.describe('Team Permissions and Access Control', () => {
  test('manager should see management options', async ({ page }) => {
    // Login as manager
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', 'manager@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('/dashboard');
    
    await page.goto('/team');
    await page.waitForLoadState('networkidle');
    
    // Should see invite button
    await expect(page.locator('[data-testid="invite-member-button"]')).toBeVisible();
    
    // Should see remove buttons for non-owners
    const contributorCard = page.locator('[data-testid="member-card"]').filter({ hasText: 'Contributor' }).first();
    await expect(contributorCard.locator('[data-testid="remove-member-button"]')).toBeVisible();
  });

  test('contributor should not see management options', async ({ page }) => {
    // Login as contributor
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', 'contributor@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('/dashboard');
    
    await page.goto('/team');
    await page.waitForLoadState('networkidle');
    
    // Should not see invite button
    await expect(page.locator('[data-testid="invite-member-button"]')).not.toBeVisible();
    
    // Should not see remove buttons
    const memberCards = page.locator('[data-testid="member-card"]');
    await expect(memberCards.locator('[data-testid="remove-member-button"]')).not.toBeVisible();
  });

  test('viewer should have read-only access', async ({ page }) => {
    // Login as viewer
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', 'viewer@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('/dashboard');
    
    await page.goto('/team');
    await page.waitForLoadState('networkidle');
    
    // Should see team members but no management options
    await expect(page.locator('[data-testid="team-members-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="invite-member-button"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="member-card"]').locator('[data-testid="remove-member-button"]')).not.toBeVisible();
  });

  test('owner should have full management access', async ({ page }) => {
    // Login as owner
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', 'owner@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('/dashboard');
    
    await page.goto('/team');
    await page.waitForLoadState('networkidle');
    
    // Should see all management options
    await expect(page.locator('[data-testid="invite-member-button"]')).toBeVisible();
    
    // Should see remove buttons for non-owners
    const contributorCard = page.locator('[data-testid="member-card"]').filter({ hasText: 'Contributor' }).first();
    await expect(contributorCard.locator('[data-testid="remove-member-button"]')).toBeVisible();
    
    // Owner should not be removable
    const ownerCard = page.locator('[data-testid="member-card"]').filter({ hasText: 'Owner' }).first();
    await expect(ownerCard.locator('[data-testid="remove-member-button"]')).not.toBeVisible();
  });

  test('should handle unauthorized access attempts', async ({ page }) => {
    // Login as contributor
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', 'contributor@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('/dashboard');
    
    await page.goto('/team');
    await page.waitForLoadState('networkidle');
    
    // Try to access invite endpoint directly
    const response = await page.request.post('/api/collaboration/projects/project-1/invite', {
      email: 'unauthorized@example.com',
      role: 'Contributor'
    });
    
    // Should be forbidden
    expect(response.status()).toBe(403);
    
    // Try to access remove endpoint directly
    const removeResponse = await page.request.delete('/api/collaboration/projects/project-1/members/user-123');
    
    // Should be forbidden
    expect(removeResponse.status()).toBe(403);
  });
});

test.describe('Team Performance and Responsiveness', () => {
  test('should load team page quickly', async ({ page }) => {
    // Login
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', 'manager@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('/dashboard');
    
    // Measure load time
    const startTime = Date.now();
    await page.goto('/team');
    await page.waitForSelector('[data-testid="team-members-list"]', { state: 'visible' });
    const loadTime = Date.now() - startTime;
    
    // Should load within 2 seconds
    expect(loadTime).toBeLessThan(2000);
  });

  test('should handle large team lists efficiently', async ({ page }) => {
    // Mock large team data
    await page.addInitScript(() => {
      window.mockTeamMembers = Array.from({ length: 100 }, (_, i) => ({
        id: `member-${i}`,
        user_id: `user-${i}`,
        name: `Team Member ${i}`,
        role: i % 4 === 0 ? 'Owner' : i % 3 === 0 ? 'Manager' : i % 2 === 0 ? 'Contributor' : 'Viewer',
        joined_at: '2023-01-01T00:00:00Z',
      }));
    });
    
    // Login and navigate
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', 'manager@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('/dashboard');
    
    const startTime = Date.now();
    await page.goto('/team');
    await page.waitForSelector('[data-testid="team-members-list"]', { state: 'visible' });
    const renderTime = Date.now() - startTime;
    
    // Should render large list within reasonable time
    expect(renderTime).toBeLessThan(1000);
    
    // Should have pagination
    await expect(page.locator('[data-testid="pagination-controls"]')).toBeVisible();
  });

  test('should be responsive on mobile devices', async ({ page }) => {
    // Set mobile viewport
    await page.setViewportSize({ width: 375, height: 667 });
    
    // Login
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', 'manager@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('/dashboard');
    
    await page.goto('/team');
    await page.waitForLoadState('networkidle');
    
    // Should have mobile layout
    await expect(page.locator('[data-testid="mobile-layout"]')).toBeVisible();
    await expect(page.locator('[data-testid="mobile-menu-button"]')).toBeVisible();
    
    // Team members should be stacked vertically
    const memberCards = page.locator('[data-testid="member-card"]');
    const firstCard = memberCards.first();
    await expect(firstCard.locator('[data-testid="member-info"]')).toBeVisible();
    await expect(firstCard.locator('[data-testid="member-actions"]')).toBeVisible();
  });

  test('should handle network interruptions gracefully', async ({ page }) => {
    // Login
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', 'manager@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('/dashboard');
    
    // Go offline
    await page.context().setOffline(true);
    
    await page.goto('/team');
    
    // Should show offline state
    await expect(page.locator('[data-testid="offline-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="retry-button"]')).toBeVisible();
    
    // Go back online
    await page.context().setOffline(false);
    
    // Click retry
    await page.click('[data-testid="retry-button"]');
    
    // Should load successfully
    await expect(page.locator('[data-testid="team-members-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="offline-message"]')).not.toBeVisible();
  });
});
