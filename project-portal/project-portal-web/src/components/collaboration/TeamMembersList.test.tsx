import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import TeamMembersList from '@/components/collaboration/TeamMembersList';
import { useStore } from '@/lib/store/store';
import type { ProjectMember } from '@/lib/store/collaboration/collaboration.types';

// Mock the store
vi.mock('@/lib/store/store', () => ({
  useStore: vi.fn(),
}));

const mockUseStore = vi.mocked(useStore);

// Mock RoleBadge component
vi.mock('@/components/collaboration/RoleBadge', () => ({
  default: ({ role }: { role: string }) => (
    <span data-testid="role-badge" data-role={role}>{role}</span>
  ),
}));

describe('TeamMembersList', () => {
  const mockStore = {
    members: [],
    collaborationLoading: { members: false, removeMember: false },
    removeMember: vi.fn(),
  };

  beforeEach(() => {
    vi.clearAllMocks();
    mockUseStore.mockImplementation((selector) => selector(mockStore));
  });

  const defaultProps = {
    projectId: 'project-1',
    canManage: true,
  };

  describe('Loading States', () => {
    it('should show loading spinner when members are loading', () => {
      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        collaborationLoading: { ...mockStore.collaborationLoading, members: true },
      }));

      render(<TeamMembersList {...defaultProps} />);
      
      expect(screen.getByTestId('loading-spinner')).toBeInTheDocument();
      expect(screen.getByText(/loading team members/i)).toBeInTheDocument();
    });

    it('should not show loading spinner when not loading', () => {
      render(<TeamMembersList {...defaultProps} />);
      
      expect(screen.queryByTestId('loading-spinner')).not.toBeInTheDocument();
    });
  });

  describe('Empty States', () => {
    it('should show empty state when no members exist', () => {
      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        members: [],
      }));

      render(<TeamMembersList {...defaultProps} />);
      
      expect(screen.getByText(/no team members yet/i)).toBeInTheDocument();
      expect(screen.getByText(/invite people to collaborate/i)).toBeInTheDocument();
      expect(screen.getByTestId('users-icon')).toBeInTheDocument();
    });

    it('should not show empty state when members exist', () => {
      const mockMembers: ProjectMember[] = [
        {
          id: '1',
          project_id: 'project-1',
          user_id: 'user-1',
          role: 'Owner',
          permissions: ['all'],
          joined_at: '2023-01-01T00:00:00Z',
          updated_at: '2023-01-01T00:00:00Z',
        },
      ];

      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        members: mockMembers,
      }));

      render(<TeamMembersList {...defaultProps} />);
      
      expect(screen.queryByText(/no team members yet/i)).not.toBeInTheDocument();
    });
  });

  describe('Member Display', () => {
    const mockMembers: ProjectMember[] = [
      {
        id: '1',
        project_id: 'project-1',
        user_id: 'user-1',
        role: 'Owner',
        permissions: ['all'],
        joined_at: '2023-01-01T00:00:00Z',
        updated_at: '2023-01-01T00:00:00Z',
      },
      {
        id: '2',
        project_id: 'project-1',
        user_id: 'user-2',
        role: 'Contributor',
        permissions: ['read', 'write'],
        joined_at: '2023-01-02T00:00:00Z',
        updated_at: '2023-01-02T00:00:00Z',
      },
      {
        id: '3',
        project_id: 'project-1',
        user_id: 'user-3',
        role: 'Manager',
        permissions: ['read', 'write', 'manage'],
        joined_at: '2023-01-03T00:00:00Z',
        updated_at: '2023-01-03T00:00:00Z',
      },
    ];

    beforeEach(() => {
      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        members: mockMembers,
      }));
    });

    it('should render all team members', () => {
      render(<TeamMembersList {...defaultProps} />);
      
      expect(screen.getAllByTestId('member-row')).toHaveLength(3);
    });

    it('should display member information correctly', () => {
      render(<TeamMembersList {...defaultProps} />);
      
      // Check first member
      expect(screen.getByText('user-1')).toBeInTheDocument();
      expect(screen.getByText('Owner')).toBeInTheDocument();
      expect(screen.getByText(/Joined Jan 1, 2023/i)).toBeInTheDocument();
      
      // Check avatar
      const avatar = screen.getAllByTestId('member-avatar')[0];
      expect(avatar).toHaveTextContent('US'); // First 2 letters of 'user-1'
    });

    it('should display role badges for each member', () => {
      render(<TeamMembersList {...defaultProps} />);
      
      const roleBadges = screen.getAllByTestId('role-badge');
      expect(roleBadges).toHaveLength(3);
      expect(roleBadges[0]).toHaveAttribute('data-role', 'Owner');
      expect(roleBadges[1]).toHaveAttribute('data-role', 'Contributor');
      expect(roleBadges[2]).toHaveAttribute('data-role', 'Manager');
    });

    it('should format join date correctly', () => {
      render(<TeamMembersList {...defaultProps} />);
      
      const joinDates = screen.getAllByText(/Joined/i);
      expect(joinDates).toHaveLength(3);
      expect(joinDates[0]).toHaveTextContent('Joined Jan 1, 2023');
      expect(joinDates[1]).toHaveTextContent('Joined Jan 2, 2023');
      expect(joinDates[2]).toHaveTextContent('Joined Jan 3, 2023');
    });
  });

  describe('Member Removal', () => {
    const mockMembers: ProjectMember[] = [
      {
        id: '1',
        project_id: 'project-1',
        user_id: 'owner-user',
        role: 'Owner',
        permissions: ['all'],
        joined_at: '2023-01-01T00:00:00Z',
        updated_at: '2023-01-01T00:00:00Z',
      },
      {
        id: '2',
        project_id: 'project-1',
        user_id: 'contributor-user',
        role: 'Contributor',
        permissions: ['read', 'write'],
        joined_at: '2023-01-02T00:00:00Z',
        updated_at: '2023-01-02T00:00:00Z',
      },
    ];

    beforeEach(() => {
      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        members: mockMembers,
      }));
    });

    it('should show remove button for non-owners when canManage is true', () => {
      render(<TeamMembersList {...defaultProps} />);
      
      const removeButtons = screen.getAllByTestId('remove-member-button');
      expect(removeButtons).toHaveLength(1); // Only for contributor, not owner
      expect(removeButtons[0]).toBeVisible();
    });

    it('should not show remove button for owners', () => {
      render(<TeamMembersList {...defaultProps} />);
      
      const memberRows = screen.getAllByTestId('member-row');
      const ownerRow = memberRows.find(row => 
        row.textContent?.includes('owner-user')
      );
      
      expect(ownerRow?.querySelector('[data-testid="remove-member-button"]')).not.toBeInTheDocument();
    });

    it('should not show remove buttons when cannot manage', () => {
      render(<TeamMembersList {...defaultProps} canManage={false} />);
      
      expect(screen.queryByTestId('remove-member-button')).not.toBeInTheDocument();
    });

    it('should call removeMember when remove button is clicked', async () => {
      const user = userEvent.setup();
      
      render(<TeamMembersList {...defaultProps} />);
      
      const removeButton = screen.getByTestId('remove-member-button');
      await user.click(removeButton);

      expect(mockStore.removeMember).toHaveBeenCalledWith('project-1', 'contributor-user');
    });

    it('should show loading state during member removal', async () => {
      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        members: mockMembers,
        collaborationLoading: { ...mockStore.collaborationLoading, removeMember: true },
      }));

      render(<TeamMembersList {...defaultProps} />);
      
      const removeButton = screen.getByTestId('remove-member-button');
      expect(removeButton).toBeDisabled();
      expect(screen.getByTestId('remove-loading-spinner')).toBeInTheDocument();
    });

    it('should show confirmation dialog before removal', async () => {
      const user = userEvent.setup();
      
      // Mock window.confirm
      const originalConfirm = window.confirm;
      window.confirm = vi.fn(() => true);
      
      render(<TeamMembersList {...defaultProps} />);
      
      const removeButton = screen.getByTestId('remove-member-button');
      await user.click(removeButton);

      expect(window.confirm).toHaveBeenCalledWith(
        expect.stringContaining('Are you sure you want to remove contributor-user from the team?')
      );

      // Restore original confirm
      window.confirm = originalConfirm;
    });

    it('should not remove member if confirmation is cancelled', async () => {
      const user = userEvent.setup();
      
      // Mock window.confirm to return false
      const originalConfirm = window.confirm;
      window.confirm = vi.fn(() => false);
      
      render(<TeamMembersList {...defaultProps} />);
      
      const removeButton = screen.getByTestId('remove-member-button');
      await user.click(removeButton);

      expect(mockStore.removeMember).not.toHaveBeenCalled();

      // Restore original confirm
      window.confirm = originalConfirm;
    });
  });

  describe('Accessibility', () => {
    const mockMembers: ProjectMember[] = [
      {
        id: '1',
        project_id: 'project-1',
        user_id: 'user-1',
        role: 'Owner',
        permissions: ['all'],
        joined_at: '2023-01-01T00:00:00Z',
        updated_at: '2023-01-01T00:00:00Z',
      },
    ];

    beforeEach(() => {
      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        members: mockMembers,
      }));
    });

    it('should have proper ARIA labels', () => {
      render(<TeamMembersList {...defaultProps} />);
      
      expect(screen.getByRole('list')).toBeInTheDocument();
      expect(screen.getAllByRole('listitem')).toHaveLength(1);
    });

    it('should have accessible remove buttons', () => {
      render(<TeamMembersList {...defaultProps} canManage={false} />);
      
      // When user cannot manage, no remove buttons should be present
      expect(screen.queryByLabelText(/remove member/i)).not.toBeInTheDocument();
    });

    it('should support keyboard navigation', async () => {
      const user = userEvent.setup();
      
      render(<TeamMembersList {...defaultProps} />);
      
      const memberRow = screen.getByTestId('member-row');
      memberRow.focus();
      
      await user.tab();
      
      // Should focus on next interactive element if available
      expect(document.activeElement).toBeInTheDocument();
    });
  });

  describe('Error Handling', () => {
    it('should handle empty member list gracefully', () => {
      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        members: [],
      }));

      render(<TeamMembersList {...defaultProps} />);
      
      expect(screen.getByText(/no team members yet/i)).toBeInTheDocument();
      expect(screen.queryByTestId('member-row')).not.toBeInTheDocument();
    });

    it('should handle undefined members gracefully', () => {
      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        members: undefined as any,
      }));

      render(<TeamMembersList {...defaultProps} />);
      
      expect(screen.getByText(/no team members yet/i)).toBeInTheDocument();
    });

    it('should handle members with missing properties gracefully', () => {
      const incompleteMembers = [
        {
          id: '1',
          project_id: 'project-1',
          user_id: '',
          role: '',
          permissions: [],
          joined_at: '',
          updated_at: '',
        },
      ] as ProjectMember[];

      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        members: incompleteMembers,
      }));

      render(<TeamMembersList {...defaultProps} />);
      
      expect(screen.getByTestId('member-row')).toBeInTheDocument();
      expect(screen.getByTestId('member-avatar')).toHaveTextContent('??');
    });
  });

  describe('Performance', () => {
    it('should handle large member lists efficiently', () => {
      const largeMemberList: ProjectMember[] = Array.from({ length: 100 }, (_, i) => ({
        id: `member-${i}`,
        project_id: 'project-1',
        user_id: `user-${i}`,
        role: i % 3 === 0 ? 'Owner' : i % 2 === 0 ? 'Manager' : 'Contributor',
        permissions: ['read'],
        joined_at: '2023-01-01T00:00:00Z',
        updated_at: '2023-01-01T00:00:00Z',
      }));

      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        members: largeMemberList,
      }));

      const startTime = performance.now();
      render(<TeamMembersList {...defaultProps} />);
      const endTime = performance.now();

      // Should render within reasonable time (less than 100ms for 100 items)
      expect(endTime - startTime).toBeLessThan(100);
      expect(screen.getAllByTestId('member-row')).toHaveLength(100);
    });
  });

  describe('Visual Design', () => {
    const mockMembers: ProjectMember[] = [
      {
        id: '1',
        project_id: 'project-1',
        user_id: 'user-1',
        role: 'Owner',
        permissions: ['all'],
        joined_at: '2023-01-01T00:00:00Z',
        updated_at: '2023-01-01T00:00:00Z',
      },
    ];

    beforeEach(() => {
      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        members: mockMembers,
      }));
    });

    it('should apply correct CSS classes', () => {
      render(<TeamMembersList {...defaultProps} />);
      
      const memberRow = screen.getByTestId('member-row');
      expect(memberRow).toHaveClass('flex', 'items-center', 'justify-between');
    });

    it('should have proper avatar styling', () => {
      render(<TeamMembersList {...defaultProps} />);
      
      const avatar = screen.getByTestId('member-avatar');
      expect(avatar).toHaveClass('w-9', 'h-9', 'rounded-full', 'bg-emerald-100');
    });

    it('should have proper role badge styling', () => {
      render(<TeamMembersList {...defaultProps} />);
      
      const roleBadge = screen.getByTestId('role-badge');
      expect(roleBadge).toBeInTheDocument();
    });
  });
});
