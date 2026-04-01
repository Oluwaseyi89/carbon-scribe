import { test, expect } from '@playwright/test';

test.describe('Team Permissions and Access Control', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page
    await page.goto('/login');
  });

  test('should enforce role-based access control', async ({ page }) => {
    // Test as different roles
    const roles = [
      { email: 'owner@example.com', password: 'password123', expectedAccess: 'full' },
      { email: 'manager@example.com', password: 'password123', expectedAccess: 'management' },
      { email: 'contributor@example.com', password: 'password123', expectedAccess: 'limited' },
      { email: 'viewer@example.com', password: 'password123', expectedAccess: 'readonly' },
    ];

    for (const role of roles) {
      // Login with specific role
      await page.fill('[data-testid="email-input"]', role.email);
      await page.fill('[data-testid="password-input"]', role.password);
      await page.click('[data-testid="login-button"]');
      await page.waitForURL('/dashboard');
      
      // Navigate to team page
      await page.goto('/team');
      await page.waitForLoadState('networkidle');
      
      // Verify access based on role
      switch (role.expectedAccess) {
        case 'full':
          // Owner should see all management options
          await expect(page.locator('[data-testid="invite-member-button"]')).toBeVisible();
          await expect(page.locator('[data-testid="team-settings-button"]')).toBeVisible();
          await expect(page.locator('[data-testid="export-team-button"]')).toBeVisible();
          
          // Should be able to remove non-owners
          const contributorCard = page.locator('[data-testid="member-card"]').filter({ hasText: 'Contributor' }).first();
          if (await contributorCard.count() > 0) {
            await expect(contributorCard.locator('[data-testid="remove-member-button"]')).toBeVisible();
          }
          break;
          
        case 'management':
          // Manager should see invite and remove options
          await expect(page.locator('[data-testid="invite-member-button"]')).toBeVisible();
          await expect(page.locator('[data-testid="team-settings-button"]')).not.toBeVisible();
          await expect(page.locator('[data-testid="export-team-button"]')).not.toBeVisible();
          
          // Should be able to remove non-owners
          const managerContributorCard = page.locator('[data-testid="member-card"]').filter({ hasText: 'Contributor' }).first();
          if (await managerContributorCard.count() > 0) {
            await expect(managerContributorCard.locator('[data-testid="remove-member-button"]')).toBeVisible();
          }
          break;
          
        case 'limited':
          // Contributor should see team but no management options
          await expect(page.locator('[data-testid="invite-member-button"]')).not.toBeVisible();
          await expect(page.locator('[data-testid="team-settings-button"]')).not.toBeVisible();
          await expect(page.locator('[data-testid="export-team-button"])).not.toBeVisible();
          
          // Should not see remove buttons
          await expect(page.locator('[data-testid="member-card"]').locator('[data-testid="remove-member-button"]')).not.toBeVisible();
          break;
          
        case 'readonly':
          // Viewer should only see team information
          await expect(page.locator('[data-testid="invite-member-button"])).not.toBeVisible();
          await expect(page.locator('[data-testid="team-settings-button"])).not.toBeVisible();
          await expect(page.locator('[data-testid="export-team-button"])).not.toBeVisible();
          await expect(page.locator('[data-testid="member-card"]').locator('[data-testid="remove-member-button"]')).not.toBeVisible();
          break;
      }
      
      // Logout for next role test
      await page.click('[data-testid="user-menu-button"]');
      await page.click('[data-testid="logout-button"]');
      await page.waitForURL('/login');
    }
  });

  test('should prevent unauthorized API access', async ({ page }) => {
    // Login as contributor (limited access)
    await page.fill('[data-testid="email-input"]', 'contributor@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('/dashboard');
    
    // Try to access management endpoints directly
    const endpoints = [
      { method: 'POST', url: '/api/collaboration/projects/project-1/invite', data: { email: 'test@example.com', role: 'Contributor' } },
      { method: 'DELETE', url: '/api/collaboration/projects/project-1/members/user-123' },
      { method: 'POST', url: '/api/collaboration/projects/project-1/settings', data: { name: 'Test Project' } },
      { method: 'POST', url: '/api/collaboration/projects/project-1/export' },
    ];
    
    for (const endpoint of endpoints) {
      const response = await page.request(endpoint.method, endpoint.url, {
        data: endpoint.data,
      });
      
      // Should return 403 Forbidden
      expect(response.status()).toBe(403);
    }
    
    // Should still be able to access read-only endpoints
    const readonlyEndpoints = [
      { method: 'GET', url: '/api/collaboration/projects/project-1/members' },
      { method: 'GET', url: '/api/collaboration/projects/project-1/invitations' },
      { method: 'GET', url: '/api/collaboration/projects/project-1/activities' },
      { method: 'GET', url: '/api/collaboration/projects/project-1/comments' },
      { method: 'GET', url: '/api/collaboration/projects/project-1/tasks' },
    ];
    
    for (const endpoint of readonlyEndpoints) {
      const response = await page.request(endpoint.method, endpoint.url);
      
      // Should return 200 OK
      expect(response.status()).toBe(200);
    }
  });

  test('should handle permission changes dynamically', async ({ page }) => {
    // Login as contributor
    await page.fill('[data-testid="email-input"]', 'contributor@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('/dashboard');
    
    await page.goto('/team');
    await page.waitForLoadState('networkidle');
    
    // Should not see management options as contributor
    await expect(page.locator('[data-testid="invite-member-button"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="member-card"]').locator('[data-testid="remove-member-button"]')).not.toBeVisible();
    
    // Simulate role change to manager (in real app, this would be done by an admin)
    await page.addInitScript(() => {
      // Mock role change
      window.mockUserRoleChange = 'Manager';
    });
    
    // Refresh page to trigger role re-evaluation
    await page.reload();
    await page.waitForLoadState('networkidle');
    
    // Should now see management options
    await expect(page.locator('[data-testid="invite-member-button"]')).toBeVisible();
    
    const contributorCard = page.locator('[data-testid="member-card"]').filter({ hasText: 'Contributor' }).first();
    if (await contributorCard.count() > 0) {
      await expect(contributorCard.locator('[data-testid="remove-member-button"]')).toBeVisible();
    }
    
    // Simulate role change back to contributor
    await page.addInitScript(() => {
      window.mockUserRoleChange = 'Contributor';
    });
    
    await page.reload();
    await page.waitForLoadState('networkidle');
    
    // Should no longer see management options
    await expect(page.locator('[data-testid="invite-member-button"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="member-card"]').locator('[data-testid="remove-member-button"]')).not.toBeVisible();
  });

  test('should prevent self-removal', async ({ page }) => {
    // Login as manager
    await page.fill('[data-testid="email-input"]', 'manager@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('/dashboard');
    
    await page.goto('/team');
    await page.waitForLoadState('networkidle');
    
    // Find current user's member card
    const currentUserCard = page.locator('[data-testid="member-card"]').filter({ hasText: 'manager@example.com' }).first();
    
    // Should not see remove button for self
    await expect(currentUserCard.locator('[data-testid="remove-member-button"]')).not.toBeVisible();
    
    // Try to call remove API directly
    const response = await page.request('DELETE', '/api/collaboration/projects/project-1/members/manager-user-id');
    
    // Should return 403 Forbidden
    expect(response.status()).toBe(403);
  });

  test('should prevent owner removal', async ({ page }) => {
    // Login as manager
    await page.fill('[data-testid="email-input"]', 'manager@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('/dashboard');
    
    await page.goto('/team');
    await page.waitForLoadState('networkidle');
    
    // Find owner member card
    const ownerCard = page.locator('[data-testid="member-card"]').filter({ hasText: 'Owner' }).first();
    
    // Should not see remove button for owner
    await expect(ownerCard.locator('[data-testid="remove-member-button"]')).not.toBeVisible();
    
    // Try to call remove API directly
    const response = await page.request('DELETE', '/api/collaboration/projects/project-1/members/owner-user-id');
    
    // Should return 403 Forbidden
    expect(response.status()).toBe(403);
  });

  test('should enforce project-level permissions', async ({ page }) => {
    // Login as project manager
    await page.fill('[data-testid="email-input"]', 'manager@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('/dashboard');
    
    await page.goto('/team');
    await page.waitForLoadState('networkidle');
    
    // Should be able to manage this project
    await expect(page.locator('[data-testid="invite-member-button"]')).toBeVisible();
    
    // Try to access different project
    await page.goto('/team?project=other-project');
    await page.waitForLoadState('networkidle');
    
    // Should not see management options for other project
    await expect(page.locator('[data-testid="invite-member-button"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="member-card"]').locator('[data-testid="remove-member-button"]')).not.toBeVisible();
    
    // Should see access denied message
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('You do not have permission to manage this project');
  });

  test('should handle permission inheritance correctly', async ({ page }) => {
    // Login as manager
    await page.fill('[data-testid="email-input"]', 'manager@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('/dashboard');
    
    await page.goto('/team');
    await page.waitForLoadState('networkidle');
    
    // Manager should be able to invite contributors and viewers
    await page.click('[data-testid="invite-member-button"]');
    await page.selectOption('[data-testid="invite-role-select"]', 'Contributor');
    await expect(page.locator('[data-testid="role-description"]')).toContainText('can contribute to project content');
    
    await page.selectOption('[data-testid="invite-role-select"]', 'Viewer');
    expect(page.locator('[data-testid="role-description"]')).toContainText('can only view project content');
    
    // Should not be able to invite other managers or owners
    await page.selectOption('[data-testid="invite-role-select"]', 'Manager');
    expect(page.locator('[data-testid="role-description"]')).toContainText('can manage team members and settings');
    expect(page.locator('[data-testid="role-warning"]')).toBeVisible();
    expect(page.locator('[data-testid="role-warning"]')).toContainText('Only owners can invite other managers');
    
    await page.selectOption('[data-testid="invite-role-select"]', 'Owner');
    expect(page.locator('[data-testid="role-description"]')).toContainText('full access to all project features');
    expect(page.locator('[data-testid="role-warning"]')).toBeVisible();
    expect(page.locator('[data-testid="role-warning"]')).toContainText('Only owners can invite other owners');
    
    // Close modal
    await page.click('[data-testid="cancel-button"]');
  });

  test('should validate permissions at component level', async ({ page }) => {
    // Login as contributor
    await page.fill('[data-testid="email-input"]', 'contributor@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('/dashboard');
    
    await page.goto('/team');
    await page.waitForLoadState('networkidle');
    
    // Try to access invite modal via URL manipulation
    await page.evaluate(() => {
      // Force open invite modal
      const modal = document.createElement('div');
      modal.setAttribute('data-testid', 'invite-modal');
      modal.style.display = 'block';
      document.body.appendChild(modal);
    });
    
    // Modal should be visible but disabled
    await expect(page.locator('[data-testid="invite-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="send-invitation-button"]')).toBeDisabled();
    await expect(page.locator('[data-testid="permission-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="permission-error"]')).toContainText('You do not have permission to invite members');
    
    // Try to access remove button via DOM manipulation
    await page.evaluate(() => {
      const memberCards = document.querySelectorAll('[data-testid="member-card"]');
      if (memberCards.length > 0) {
        const firstCard = memberCards[0];
        const removeButton = document.createElement('button');
        removeButton.setAttribute('data-testid', 'remove-member-button');
        removeButton.style.display = 'block';
        firstCard.appendChild(removeButton);
      }
    });
    
    // Remove button should be visible but disabled
    if (await page.locator('[data-testid="remove-member-button"]').count() > 0) {
      await expect(page.locator('[data-testid="remove-member-button"]').first()).toBeDisabled();
      await expect(page.locator('[data-testid="permission-error"]')).toBeVisible();
    }
  });

  test('should handle permission errors gracefully', async ({ page }) => {
    // Login as contributor
    await page.fill('[data-testid="email-input"]', 'contributor@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('/dashboard');
    
    await page.goto('/team');
    await page.waitForLoadState('networkidle');
    
    // Mock permission error on API call
    await page.route('/api/collaboration/projects/project-1/members/*', route => {
      return route.fulfill({
        status: 403,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'Insufficient permissions' }),
      });
    });
    
    // Try to remove member (should fail at UI level)
    const memberCard = page.locator('[data-testid="member-card"]').first();
    if (await memberCard.count() > 0) {
      // Remove button should not be visible for contributor
      await expect(memberCard.locator('[data-testid="remove-member-button"]')).not.toBeVisible();
    }
    
    // Try to access invite endpoint directly
    const response = await page.request('POST', '/api/collaboration/projects/project-1/invite', {
      data: { email: 'test@example.com', role: 'Contributor' },
    });
    
    // Should handle error gracefully
    expect(response.status()).toBe(403);
    
    // Should show error message if UI attempted operation
    await expect(page.locator('[data-testid="error-message"]')).not.toBeVisible(); // No UI attempt was made
  });

  test('should support role-based UI customization', async ({ page }) => {
    // Test UI customization based on role
    const roles = [
      { email: 'owner@example.com', password: 'password123', expectedTheme: 'owner' },
      { email: 'manager@example.com', password: 'password123', expectedTheme: 'manager' },
      { email: 'contributor@example.com', password: 'password123', expectedTheme: 'contributor' },
      { email: 'viewer@example.com', 'password: 'password123', expectedTheme: 'viewer' },
    ];

    for (const role of roles) {
      // Login with specific role
      await page.fill('[data-testid="email-input"]', role.email);
      await page.fill('[data-testid="password-input"]', role.password);
      await page.click('[data-testid="login-button"]');
      await page.waitForURL('/dashboard');
      
      await page.goto('/team');
      await page.waitForLoadState('networkidle');
      
      // Check role-specific UI elements
      switch (role.expectedTheme) {
        case 'owner':
          await expect(page.locator('[data-testid="role-indicator"]')).toHaveText('Project Owner');
          await expect(page.locator('[data-testid="role-indicator"]')).toHaveClass('bg-purple-100');
          break;
          
        case 'manager':
          await expect(page.locator('[data-testid="role-indicator"]')).toHaveText('Project Manager');
          await expect(page.locator('[data-testid="role-indicator"]')).toHaveClass('bg-blue-100');
          break;
          
        case 'contributor':
          await expect(page.locator('[data-testid="role-indicator"]')).toHaveText('Contributor');
          await expect(page.locator('[data-testid="role-indicator"]')).toHaveClass('bg-green-100');
          break;
          
        case 'viewer':
          await expect(page.locator('[data-testid="role-indicator"]')).toHaveText('Viewer');
          await expect(page.locator('[data-testid="role-indicator"]')).toHaveClass('bg-gray-100');
          break;
      }
      
      // Logout for next role test
      await page.click('[data-testid="user-menu-button"]');
      await page.click('[data-testid="logout-button"]');
      await page.waitForURL('/login');
    }
  });
});

test.describe('Team Permission Edge Cases', () => {
  test('should handle permission inheritance from multiple projects', async ({ page }) => {
    // Login as user with mixed permissions across projects
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', 'mixed@example.com');
    await page.fill('[data-testid="password-input']', 'password123');
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('/dashboard');
    
    // Navigate to first project where user is manager
    await page.goto('/team?project=project-1');
    await page.waitForLoadState('networkidle');
    
    // Should see management options in project-1
    await expect(page.locator('[data-testid="invite-member-button"]')).toBeVisible();
    
    // Navigate to second project where user is contributor
    await page.goto('/team?project=project-2');
    await page.waitForLoadState('networkidle');
    
    // Should not see management options in project-2
    await expect(page.locator('[data-testid="invite-member-button"])).not.toBeVisible();
    
    // Navigate to third project where user is viewer
    await page.goto('/team?project=project-3');
    await page.permissions().set(['read']);
    await page.waitForLoadState('networkidle');
    
    // Should only see read-only options in project-3
    await expect(page.locator('[data-testid="team-members-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="invite-member-button"]')).not.toBeVisible();
  });

  test('should handle permission escalation gracefully', async ({ page }) => {
    // Login as contributor
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', 'contributor@example.com');
    await page.fill('[data-testid="password-input"]', 'permissions123');
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('/dashboard');
    
    await page.goto('/team');
    await page.waitForLoadState('networkidle');
    
    // Should not see management options
    await expect(page.locator('[data-testid="invite-member-button"])).not.toBeVisible();
    
    // Simulate permission escalation (in real app, this would be done by admin)
    await page.addInitScript(() => {
      window.mockPermissionEscalation = true;
      window.mockUserRole = 'Manager';
    });
    
    // Refresh page
    await page.reload();
    await page.waitForLoadState('networkidle');
    
    // Should now see management options
    await expect(page.locator('[data-testid="invite-member-button"]')).toBeVisible();
    
    // Should show permission change notification
    await expect(page.locator('[data-testid="permission-upgrade-notification"]')).toBeVisible();
    await expect(page.locator('[data-testid="permission-upgrade-notification"]')).toContainText('Your permissions have been updated');
  });

  test('should handle permission deescalation gracefully', async ({ page }) => {
    // Login as manager
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', 'manager@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('/dashboard');
    
    await page.goto('/team');
    await page.waitForLoadState('networkidle');
    
    // Should see management options
    await expect(page.locator('[data-testid="invite-member-button"]')).toBeVisible();
    
    // Simulate permission deescalation
    await page.addInitScript(() => {
      window.mockPermissionDeescalation = true;
      window.mockUserRole = 'Contributor';
    });
    
    // Refresh page
    await page.reload();
    await page.waitForLoadState('networkLevel');
    
    // Should no longer see management options
    await expect(page.locator('[data-testid="invite-member-button"])).not.toBeVisible();
    
    // Should show permission change notification
    await expect(page.locator('[data-testid="permission-downgrade-notification"]')).toBeVisible();
    await expect(page.locator('[data-testid="permission-downgrade-notification"]')).toContainText('Your permissions have been updated');
  });

  test('should validate permissions at multiple levels', async ({ page }) => {
    // Login as manager
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', 'manager@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('/dashboard');
    
    await page.goto('/team');
    await page.waitForLoadState('networkidle');
    
    // Should pass UI-level permission checks
    await expect(page.locator('[data-testid="invite-member-button"]')).toBeVisible();
    
    // Try to access API with insufficient permissions (should fail at API level)
    const response = await page.request('DELETE', '/api/collaboration/projects/project-1/members/owner-user-id');
    
    // Should fail at API level even though UI allows it
    expect(response.status()).toBe(403);
    
    // Should show API error message
    await expect(page.locator('[data-testid="api-error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="api-error-message"]')).toContainText('Permission denied');
  });
});
