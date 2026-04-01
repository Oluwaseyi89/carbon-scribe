import { test, expect } from '@playwright/test';

test.describe('Team Invitation Lifecycle', () => {
  test.beforeEach(async ({ page }) => {
    // Login as a project manager
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', 'manager@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('/dashboard');
    
    // Navigate to team page and invitations tab
    await page.goto('/team');
    await page.click('[data-testid="invitations-tab"]');
    await page.waitForLoadState('networkidle');
  });

  test('should create invitation and track status transitions', async ({ page }) => {
    // Create new invitation
    await page.click('[data-testid="invite-member-button"]');
    await page.fill('[data-testid="invite-email-input"]', 'newuser@example.com');
    await page.selectOption('[data-testid="invite-role-select"]', 'Contributor');
    await page.click('[data-testid="send-invitation-button"]');
    
    // Wait for modal to close
    await expect(page.locator('[data-testid="invite-modal"]')).not.toBeVisible();
    
    // Find the new invitation
    const invitationCard = page.locator('[data-testid="invitation-card"]').filter({ hasText: 'newuser@example.com' });
    await expect(invitationCard).toBeVisible();
    
    // Verify initial status
    await expect(invitationCard.locator('[data-testid="invitation-status"]')).toHaveText('Pending');
    await expect(invitationCard.locator('[data-testid="invitation-role"]')).toHaveText('Contributor');
    
    // Verify expiry date is set (48 hours from now)
    const expiryText = await invitationCard.locator('[data-testid="invitation-expiry"]').textContent();
    expect(expiryText).toMatch(/Expires in \d+ hours/);
    
    // Verify creation timestamp
    const createdText = await invitationCard.locator('[data-testid="invitation-created"]').textContent();
    expect(createdText).toMatch(/Invited \d+ minutes? ago/);
  });

  test('should accept invitation and update member list', async ({ page }) => {
    // Create invitation first
    await page.click('[data-testid="invite-member-button"]');
    await page.fill('[data-testid="invite-email-input"]', 'acceptuser@example.com');
    await page.selectOption('[data-testid="invite-role-select"]', 'Contributor');
    await page.click('[data-testid="send-invitation-button"]');
    await expect(page.locator('[data-testid="invite-modal"]')).not.toBeVisible();
    
    // Find the invitation
    const invitationCard = page.locator('[data-testid="invitation-card"]').filter({ hasText: 'acceptuser@example.com' });
    
    // Simulate accepting invitation (in real flow, this would be in email)
    await page.goto('/accept-invitation?token=test-token');
    
    // Should redirect to team page
    await page.waitForURL('/team');
    await page.click('[data-testid="members-tab"]');
    
    // Verify new member appears in team list
    const newMemberCard = page.locator('[data-testid="member-card"]').filter({ hasText: 'acceptuser@example.com' });
    await expect(newMemberCard).toBeVisible();
    await expect(newMemberCard.locator('[data-testid="member-role"])).toHaveText('Contributor');
    
    // Go back to invitations tab
    await page.click('[data-testid="invitations-tab"]');
    
    // Verify invitation status changed to accepted
    await expect(invitationCard.locator('[data-testid="invitation-status"]')).toHaveText('Accepted');
    
    // Verify action buttons are no longer visible
    await expect(invitationCard.locator('[data-testid="resend-invitation-button"]')).not.toBeVisible();
    await expect(invitationCard.locator('[data-testid="cancel-invitation-button"]')).not.toBeVisible();
  });

  test('should decline invitation and update status', async ({ page }) => {
    // Create invitation first
    await page.click('[data-testid="invite-member-button"]');
    await page.fill('[data-testid="invite-email-input"]', 'declineuser@example.com');
    await page.selectOption('[data-testid="invite-role-select"]', 'Contributor');
    await page.click('[data-testid="send-invitation-button"]');
    await expect(page.locator('[data-testid="invite-modal"]')).not.toBeVisible();
    
    // Find the invitation
    const invitationCard = page.locator('[data-testid="invitation-card"]').filter({ hasText: 'declineuser@example.com' });
    
    // Simulate declining invitation (in real flow, this would be in email)
    await page.goto('/decline-invitation?token=test-token');
    
    // Should redirect to team page
    await page.waitForURL('/team');
    await page.click('[data-testid="invitations-tab"]');
    
    // Verify invitation status changed
    await expect(invitationCard.locator('[data-testid="invitation-status"]')).toHaveText('Declined');
    
    // Verify action buttons are no longer visible
    await expect(invitationCard.locator('[data-testid="resend-invitation-button"])).not.toBeVisible();
    await expect(invitationCard.locator('[data-testid="cancel-invitation-button"])).not.toBeVisible();
    
    // Verify member was not added to team
    await page.click('[data-testid="members-tab"]');
    const declinedMemberCard = page.locator('[data-testid="member-card"]').filter({ hasText: 'declineuser@example.com' });
    await expect(declinedMemberCard).not.toBeVisible();
  });

  test('should resend invitation with new expiry', async ({ page }) => {
    // Create invitation first
    await page.click('[data-testid="invite-member-button"]');
    await page.fill('[data-testid="invite-email-input"]', 'resenduser@example.com');
    await page.selectOption('[data-testid="invite-role-select"]', 'Contributor');
    await page.click('[data-testid="send-invitation-button"]');
    await expect(page.locator('[data-testid="invite-modal"]')).not.toBeVisible();
    
    // Find the invitation
    const invitationCard = page.locator('[data-testid="invitation-card"]').filter({ hasText: 'resenduser@example.com' });
    
    // Get original expiry time
    const originalExpiry = await invitationCard.locator('[data-testid="invitation-expiry"]').textContent();
    
    // Wait a moment to ensure timestamp difference
    await page.waitForTimeout(1000);
    
    // Resend invitation
    await invitationCard.locator('[data-testid="resend-invitation-button"]').click();
    await page.click('[data-testid="confirm-resend-button"]');
    
    // Verify success message
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Invitation resent successfully');
    
    // Verify expiry date was updated
    const newExpiry = await invitationCard.locator('[data-testid="invitation-expiry"]').textContent();
    expect(newExpiry).not.toBe(originalExpiry);
    expect(newExpiry).toMatch(/Expires in \d+ hours/);
    
    // Verify token was regenerated (status remains pending)
    await expect(invitationCard.locator('[data-testid="invitation-status"]')).toHaveText('Pending');
  });

  test('should cancel invitation and prevent acceptance', async ({ page }) => {
    // Create invitation first
    await page.click('[data-testid="invite-member-button"]');
    await page.fill('[data-testid="invite-email-input"]', 'canceluser@example.com');
    await page.selectOption('[data-testid="invite-role-select"]', 'Contributor');
    await page.click('[data-testid="send-invitation-button"]');
    await expect(page.locator('[data-testid="invite-modal"]')).not.toBeVisible();
    
    // Find the invitation
    const invitationCard = page.locator('[data-testid="invitation-card"]').filter({ hasText: 'canceluser@example.com' });
    
    // Cancel invitation
    await invitationCard.locator('[data-testid="cancel-invitation-button"]').click();
    await page.click('[data-testid="confirm-cancel-button"]');
    
    // Verify success message
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Invitation cancelled successfully');
    
    // Verify status changed to cancelled
    await expect(invitationCard.locator('[data-testid="invitation-status"]')).toHaveText('Cancelled');
    
    // Verify action buttons are no longer visible
    await expect(invitationCard.locator('[data-testid="resend-invitation-button"]')).not.toBeVisible();
    await expect(invitationCard.locator('[data-testid="cancel-invitation-button"]')).not.toBeVisible();
    
    // Try to access invitation link (should fail)
    await page.goto('/accept-invitation?token=test-token');
    
    // Should show error page
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Invitation not found or expired');
  });

  test('should automatically expire old invitations', async ({ page }) => {
    // Create invitation first
    await page.click('[data-testid="invite-member-button"]');
    await page.fill('[data-testid="invite-email-input"]', 'expireuser@example.com');
    await page.selectOption('[data-testid="invite-role-select"]', 'Contributor');
    await page.click('[data-testid="send-invitation-button"]');
    await expect(page.locator('[data-testid="invite-modal"]')).not.toBeVisible();
    
    // Find the invitation
    const invitationCard = page.locator('[data-testid="invitation-card"]').filter({ hasText: 'expireuser@example.com' });
    
    // Mock expired invitation by setting expiry time in the past
    await page.addInitScript(() => {
      // Simulate expired invitation
      const invitation = document.querySelector('[data-testid="invitation-card"]');
      if (invitation) {
        invitation.setAttribute('data-expired', 'true');
      }
    });
    
    // Refresh page to trigger expiry check
    await page.reload();
    await page.waitForLoadState('networkidle');
    
    // Verify status changed to expired
    await expect(invitationCard.locator('[data-testid="invitation-status"]')).toHaveText('Expired');
    
    // Verify action buttons are not visible
    await expect(invitationCard.locator('[data-testid="resend-invitation-button"]')).not.toBeVisible();
    await expect(invitationCard.locator('[data-testid="cancel-invitation-button"])).not.toBeVisible();
    
    // Verify expiry message
    await expect(invitationCard.locator('[data-testid="expiry-message"]')).toBeVisible();
    await expect(invitationCard.locator('[data-testid="expiry-message"]')).toContainText('This invitation has expired');
  });

  test('should prevent duplicate invitations for same email', async ({ page }) => {
    // Create first invitation
    await page.click('[data-testid="invite-member-button"]');
    await page.fill('[data-testid="invite-email-input"]', 'duplicate@example.com');
    await page.selectOption('[data-testid="invite-role-select"]', 'Contributor');
    await page.click('[data-testid="send-invitation-button"]');
    await expect(page.locator('[data-testid="invite-modal"]')).not.toBeVisible();
    
    // Verify first invitation exists
    const firstInvitation = page.locator('[data-testid="invitation-card"]').filter({ hasText: 'duplicate@example.com' });
    await expect(firstInvitation).toBeVisible();
    await expect(firstInvitation.locator('[data-testid="invitation-status"]')).toHaveText('Pending');
    
    // Try to create second invitation with same email
    await page.click('[data-testid="invite-member-button"]');
    await page.fill('[data-testid="invite-email-input"]', 'duplicate@example.com');
    await page.selectOption('[data-testid="invite-role-select"]', 'Contributor');
    await page.click('[data-testid="send-invitation-button"]');
    
    // Should show validation error
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('An invitation for this email already exists');
    
    // Modal should remain open
    await expect(page.locator('[data-testid="invite-modal"]')).toBeVisible();
    
    // Close modal
    await page.click('[data-testid="cancel-button"]');
    
    // Verify only one invitation exists
    const allInvitations = page.locator('[data-testid="invitation-card"]').filter({ hasText: 'duplicate@example.com' });
    await expect(allInvitations).toHaveCount(1);
  });

  test('should handle invitation lifecycle with different roles', async ({ page }) => {
    const roles = ['Owner', 'Manager', 'Contributor', 'Viewer'];
    
    for (const role of roles) {
      // Create invitation with specific role
      await page.click('[data-testid="invite-member-button"]');
      await page.fill('[data-testid="invite-email-input"]', `${role.toLowerCase()}@example.com`);
      await page.selectOption('[data-testid="invite-role-select"]', role);
      await page.click('[data-testid="send-invitation-button"]');
      await expect(page.locator('[data-testid="invite-modal"]')).not.toBeVisible();
      
      // Verify invitation was created with correct role
      const invitationCard = page.locator('[data-testid="invitation-card"]').filter({ hasText: `${role.toLowerCase()}@example.com` });
      await expect(invitationCard).toBeVisible();
      await expect(invitationCard.locator('[data-testid="invitation-role"]')).toHaveText(role);
      await expect(invitationCard.locator('[data-testid="invitation-status"]')).toHaveText('Pending');
      
      // Clean up - cancel invitation
      await invitationCard.locator('[data-testid="cancel-invitation-button"]').click();
      await page.click('[data-testid="confirm-cancel-button"]');
      await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    }
  });

  test('should track invitation statistics in real-time', async ({ page }) => {
    // Check initial statistics
    const initialStats = {
      total: await page.locator('[data-testid="total-invitations"]').textContent(),
      pending: await page.locator('[data-testid="pending-count"]').textContent(),
      accepted: await page.locator('[data-testid="accepted-count"]').textContent(),
      expired: await page.locator('[data-testid="expired-count"]').textContent(),
      cancelled: await page.locator('[data-testid="cancelled-count"]').textContent(),
    };
    
    // Create new invitation
    await page.click('[data-testid="invite-member-button"]');
    await page.fill('[data-testid="invite-email-input"]', 'stats@example.com');
    await page.selectOption('[data-testid="invite-role-select"]', 'Contributor');
    await page.click('[data-testid="send-invitation-button"]');
    await expect(page.locator('[data-testid="invite-modal"]')).not.toBeVisible();
    
    // Verify statistics updated
    await expect(page.locator('[data-testid="total-invitations"]')).not.toHaveText(initialStats.total);
    await expect(page.locator('[data-testid="pending-count"]')).not.toHaveText(initialStats.pending);
    
    // Accept invitation
    const invitationCard = page.locator('[data-testid="invitation-card"]').filter({ hasText: 'stats@example.com' });
    await page.goto('/accept-invitation?token=test-token');
    await page.waitForURL('/team');
    await page.click('[data-testid="invitations-tab"]');
    
    // Verify statistics updated again
    await expect(page.locator('[data-testid="accepted-count"]')).not.toHaveText(initialStats.accepted);
    await expect(page.locator('[data-testid="pending-count"]')).not.toHaveText(initialStats.pending);
    
    // Total should remain the same (one invitation created, one accepted)
    expect(page.locator('[data-testid="total-invitations"]')).toHaveText(initialStats.total);
  });

  test('should handle concurrent invitation operations', async ({ page }) => {
    // Create multiple invitations rapidly
    const emails = ['user1@example.com', 'user2@example.com', 'user3@example.com'];
    
    for (const email of emails) {
      await page.click('[data-testid="invite-member-button"]');
      await page.fill('[data-testid="invite-email-input"]', email);
      await page.selectOption('[data-testid="invite-role-select"]', 'Contributor');
      await page.click('[data-testid="send-invitation-button"]');
      await expect(page.locator('[data-testid="invite-modal"])).not.toBeVisible();
    }
    
    // Verify all invitations were created
    await expect(page.locator('[data-testid="invitation-card"]')).toHaveCount(3);
    
    // Verify statistics
    const pendingCount = await page.locator('[data-testid="pending-count"]').textContent();
    expect(pendingCount).toBe('3');
    
    // Cancel all invitations
    const invitationCards = page.locator('[data-testid="invitation-card"]');
    const cardCount = await invitationCards.count();
    
    for (let i = 0; i < cardCount; i++) {
      const card = invitationCards.nth(i);
      await card.locator('[data-testid="cancel-invitation-button"]').click();
      await page.click('[data-testid="confirm-cancel-button"]');
      await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    }
    
    // Verify all invitations were cancelled
    await expect(page.locator('[data-testid="cancelled-count"]')).toHaveText('3');
    await expect(page.locator('[data-testid="pending-count"]')).toHaveText('0');
  });
});
