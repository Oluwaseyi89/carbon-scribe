import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import InvitationActions from '@/components/collaboration/InvitationActions';
import { useStore } from '@/lib/store/store';
import type { ProjectInvitation } from '@/lib/store/collaboration/collaboration.types';

// Mock the store
vi.mock('@/lib/store/store', () => ({
  useStore: vi.fn(),
}));

const mockUseStore = vi.mocked(useStore);

describe('InvitationActions', () => {
  const mockStore = {
    removeMember: vi.fn(),
    collaborationLoading: { removeMember: false },
    collaborationErrors: { removeMember: null },
  };

  beforeEach(() => {
    vi.clearAllMocks();
    mockUseStore.mockImplementation((selector) => selector(mockStore));
  });

  const mockInvitation: ProjectInvitation = {
    id: 'inv-1',
    project_id: 'project-1',
    email: 'test@example.com',
    role: 'Contributor',
    status: 'pending',
    expires_at: '2023-01-15T00:00:00Z',
    created_at: '2023-01-01T00:00:00Z',
    updated_at: '2023-01-01T00:00:00Z',
  };

  const defaultProps = {
    invitation: mockInvitation,
    canManage: true,
    onAction: vi.fn(),
  };

  describe('Component Rendering', () => {
    it('should render invitation information', () => {
      render(<InvitationActions {...defaultProps} />);
      
      expect(screen.getByText('test@example.com')).toBeInTheDocument();
      expect(screen.getByText('Contributor')).toBeInTheDocument();
      expect(screen.getByText('pending')).toBeInTheDocument();
    });

    it('should show invitation expiry date', () => {
      render(<InvitationActions {...defaultProps} />);
      
      expect(screen.getByText(/expires jan 15, 2023/i)).toBeInTheDocument();
    });

    it('should show invitation creation date', () => {
      render(<InvitationActions {...defaultProps} />);
      
      expect(screen.getByText(/invited jan 1, 2023/i)).toBeInTheDocument();
    });

    it('should not show actions when cannot manage', () => {
      render(<InvitationActions {...defaultProps} canManage={false} />);
      
      expect(screen.queryByRole('button', { name: /resend/i })).not.toBeInTheDocument();
      expect(screen.queryByRole('button', { name: /cancel/i })).not.toBeInTheDocument();
    });

    it('should show actions when can manage', () => {
      render(<InvitationActions {...defaultProps} />);
      
      expect(screen.getByRole('button', { name: /resend/i })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /cancel/i })).toBeInTheDocument();
    });
  });

  describe('Status Display', () => {
    it('should show pending status with correct styling', () => {
      render(<InvitationActions {...defaultProps} />);
      
      const statusBadge = screen.getByTestId('invitation-status');
      expect(statusBadge).toHaveTextContent('pending');
      expect(statusBadge).toHaveClass('bg-yellow-100', 'text-yellow-800');
    });

    it('should show accepted status with correct styling', () => {
      const acceptedInvitation = { ...mockInvitation, status: 'accepted' as const };
      
      render(<InvitationActions {...defaultProps} invitation={acceptedInvitation} />);
      
      const statusBadge = screen.getByTestId('invitation-status');
      expect(statusBadge).toHaveTextContent('accepted');
      expect(statusBadge).toHaveClass('bg-green-100', 'text-green-800');
    });

    it('should show expired status with correct styling', () => {
      const expiredInvitation = { ...mockInvitation, status: 'expired' as const };
      
      render(<InvitationActions {...defaultProps} invitation={expiredInvitation} />);
      
      const statusBadge = screen.getByTestId('invitation-status');
      expect(statusBadge).toHaveTextContent('expired');
      expect(statusBadge).toHaveClass('bg-red-100', 'text-red-800');
    });

    it('should not show actions for accepted invitations', () => {
      const acceptedInvitation = { ...mockInvitation, status: 'accepted' as const };
      
      render(<InvitationActions {...defaultProps} invitation={acceptedInvitation} />);
      
      expect(screen.queryByRole('button', { name: /resend/i })).not.toBeInTheDocument();
      expect(screen.queryByRole('button', { name: /cancel/i })).not.toBeInTheDocument();
    });

    it('should not show actions for expired invitations', () => {
      const expiredInvitation = { ...mockInvitation, status: 'expired' as const };
      
      render(<InvitationActions {...defaultProps} invitation={expiredInvitation} />);
      
      expect(screen.queryByRole('button', { name: /resend/i })).not.toBeInTheDocument();
      expect(screen.queryByRole('button', { name: /cancel/i })).not.toBeInTheDocument();
    });
  });

  describe('Resend Invitation', () => {
    it('should call onAction with resend when resend button is clicked', async () => {
      const user = userEvent.setup();
      
      render(<InvitationActions {...defaultProps} />);
      
      const resendButton = screen.getByRole('button', { name: /resend/i });
      await user.click(resendButton);

      expect(defaultProps.onAction).toHaveBeenCalledWith('resend', mockInvitation);
    });

    it('should show confirmation dialog before resending', async () => {
      const user = userEvent.setup();
      
      // Mock window.confirm
      const originalConfirm = window.confirm;
      window.confirm = vi.fn(() => true);
      
      render(<InvitationActions {...defaultProps} />);
      
      const resendButton = screen.getByRole('button', { name: /resend/i });
      await user.click(resendButton);

      expect(window.confirm).toHaveBeenCalledWith(
        expect.stringContaining('Resend invitation to test@example.com?')
      );

      // Restore original confirm
      window.confirm = originalConfirm;
    });

    it('should not resend if confirmation is cancelled', async () => {
      const user = userEvent.setup();
      
      // Mock window.confirm to return false
      const originalConfirm = window.confirm;
      window.confirm = vi.fn(() => false);
      
      render(<InvitationActions {...defaultProps} />);
      
      const resendButton = screen.getByRole('button', { name: /resend/i });
      await user.click(resendButton);

      expect(defaultProps.onAction).not.toHaveBeenCalled();

      // Restore original confirm
      window.confirm = originalConfirm;
    });

    it('should show loading state during resend', async () => {
      const user = userEvent.setup();
      
      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        collaborationLoading: { ...mockStore.collaborationLoading, removeMember: true },
      }));

      render(<InvitationActions {...defaultProps} />);
      
      const resendButton = screen.getByRole('button', { name: /resend/i });
      expect(resendButton).toBeDisabled();
      expect(screen.getByTestId('resend-loading-spinner')).toBeInTheDocument();
    });
  });

  describe('Cancel Invitation', () => {
    it('should call onAction with cancel when cancel button is clicked', async () => {
      const user = userEvent.setup();
      
      render(<InvitationActions {...defaultProps} />);
      
      const cancelButton = screen.getByRole('button', { name: /cancel/i });
      await user.click(cancelButton);

      expect(defaultProps.onAction).toHaveBeenCalledWith('cancel', mockInvitation);
    });

    it('should show confirmation dialog before cancelling', async () => {
      const user = userEvent.setup();
      
      // Mock window.confirm
      const originalConfirm = window.confirm;
      window.confirm = vi.fn(() => true);
      
      render(<InvitationActions {...defaultProps} />);
      
      const cancelButton = screen.getByRole('button', { name: /cancel/i });
      await user.click(cancelButton);

      expect(window.confirm).toHaveBeenCalledWith(
        expect.stringContaining('Cancel invitation for test@example.com?')
      );

      // Restore original confirm
      window.confirm = originalConfirm;
    });

    it('should not cancel if confirmation is cancelled', async () => {
      const user = userEvent.setup();
      
      // Mock window.confirm to return false
      const originalConfirm = window.confirm;
      window.confirm = vi.fn(() => false);
      
      render(<InvitationActions {...defaultProps} />);
      
      const cancelButton = screen.getByRole('button', { name: /cancel/i });
      await user.click(cancelButton);

      expect(defaultProps.onAction).not.toHaveBeenCalled();

      // Restore original confirm
      window.confirm = originalConfirm;
    });

    it('should show loading state during cancel', async () => {
      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        collaborationLoading: { ...mockStore.collaborationLoading, removeMember: true },
      }));

      render(<InvitationActions {...defaultProps} />);
      
      const cancelButton = screen.getByRole('button', { name: /cancel/i });
      expect(cancelButton).toBeDisabled();
      expect(screen.getByTestId('cancel-loading-spinner')).toBeInTheDocument();
    });
  });

  describe('Role Display', () => {
    it('should display role badge with correct styling', () => {
      render(<InvitationActions {...defaultProps} />);
      
      const roleBadge = screen.getByTestId('role-badge');
      expect(roleBadge).toHaveTextContent('Contributor');
      expect(roleBadge).toHaveClass('bg-blue-100', 'text-blue-800');
    });

    it('should display owner role with special styling', () => {
      const ownerInvitation = { ...mockInvitation, role: 'Owner' };
      
      render(<InvitationActions {...defaultProps} invitation={ownerInvitation} />);
      
      const roleBadge = screen.getByTestId('role-badge');
      expect(roleBadge).toHaveTextContent('Owner');
      expect(roleBadge).toHaveClass('bg-purple-100', 'text-purple-800');
    });

    it('should display manager role with correct styling', () => {
      const managerInvitation = { ...mockInvitation, role: 'Manager' };
      
      render(<InvitationActions {...defaultProps} invitation={managerInvitation} />);
      
      const roleBadge = screen.getByTestId('role-badge');
      expect(roleBadge).toHaveTextContent('Manager');
      expect(roleBadge).toHaveClass('bg-indigo-100', 'text-indigo-800');
    });

    it('should display viewer role with correct styling', () => {
      const viewerInvitation = { ...mockInvitation, role: 'Viewer' };
      
      render(<InvitationActions {...defaultProps} invitation={viewerInvitation} />);
      
      const roleBadge = screen.getByTestId('role-badge');
      expect(roleBadge).toHaveTextContent('Viewer');
      expect(roleBadge).toHaveClass('bg-gray-100', 'text-gray-800');
    });
  });

  describe('Time Display', () => {
    it('should show relative time for recent invitations', () => {
      const recentInvitation = {
        ...mockInvitation,
        created_at: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(), // 2 hours ago
        expires_at: new Date(Date.now() + 46 * 60 * 60 * 1000).toISOString(), // 46 hours from now
      };

      render(<InvitationActions {...defaultProps} invitation={recentInvitation} />);
      
      expect(screen.getByText(/invited 2 hours ago/i)).toBeInTheDocument();
      expect(screen.getByText(/expires in 46 hours/i)).toBeInTheDocument();
    });

    it('should show absolute time for older invitations', () => {
      const oldInvitation = {
        ...mockInvitation,
        created_at: '2022-12-01T00:00:00Z',
        expires_at: '2023-01-15T00:00:00Z',
      };

      render(<InvitationActions {...defaultProps} invitation={oldInvitation} />);
      
      expect(screen.getByText(/invited dec 1, 2022/i)).toBeInTheDocument();
      expect(screen.getByText(/expires jan 15, 2023/i)).toBeInTheDocument();
    });

    it('should show expired time for expired invitations', () => {
      const expiredInvitation = {
        ...mockInvitation,
        status: 'expired' as const,
        expires_at: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(), // 2 days ago
      };

      render(<InvitationActions {...defaultProps} invitation={expiredInvitation} />);
      
      expect(screen.getByText(/expired 2 days ago/i)).toBeInTheDocument();
    });
  });

  describe('Accessibility', () => {
    it('should have proper ARIA labels', () => {
      render(<InvitationActions {...defaultProps} />);
      
      expect(screen.getByRole('button', { name: /resend invitation/i })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /cancel invitation/i })).toBeInTheDocument();
    });

    it('should support keyboard navigation', async () => {
      const user = userEvent.setup();
      
      render(<InvitationActions {...defaultProps} />);
      
      const resendButton = screen.getByRole('button', { name: /resend/i });
      resendButton.focus();
      
      await user.keyboard('{ArrowRight}');
      
      expect(screen.getByRole('button', { name: /cancel/i })).toHaveFocus();
    });

    it('should announce status changes to screen readers', () => {
      render(<InvitationActions {...defaultProps} />);
      
      expect(screen.getByRole('status')).toBeInTheDocument();
      expect(screen.getByRole('status')).toHaveTextContent('pending');
    });
  });

  describe('Error Handling', () => {
    it('should handle missing invitation data gracefully', () => {
      const incompleteInvitation = {
        id: 'inv-1',
        project_id: '',
        email: '',
        role: '',
        status: 'pending' as const,
        expires_at: '',
        created_at: '',
        updated_at: '',
      };

      render(<InvitationActions {...defaultProps} invitation={incompleteInvitation} />);
      
      expect(screen.getByTestId('invitation-status')).toBeInTheDocument();
      expect(screen.getByTestId('role-badge')).toBeInTheDocument();
    });

    it('should handle undefined invitation gracefully', () => {
      render(<InvitationActions {...defaultProps} invitation={undefined as any} />);
      
      expect(screen.getByText(/loading invitation/i)).toBeInTheDocument();
    });

    it('should display error message when action fails', async () => {
      const user = userEvent.setup();
      
      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        collaborationErrors: { removeMember: 'Failed to cancel invitation' },
      }));

      render(<InvitationActions {...defaultProps} />);
      
      const cancelButton = screen.getByRole('button', { name: /cancel/i });
      await user.click(cancelButton);

      expect(screen.getByText(/failed to cancel invitation/i)).toBeInTheDocument();
    });
  });

  describe('Component Interactions', () => {
    it('should disable all actions during loading', () => {
      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        collaborationLoading: { ...mockStore.collaborationLoading, removeMember: true },
      }));

      render(<InvitationActions {...defaultProps} />);
      
      expect(screen.getByRole('button', { name: /resend/i })).toBeDisabled();
      expect(screen.getByRole('button', { name: /cancel/i })).toBeDisabled();
    });

    it('should enable actions when not loading', () => {
      render(<InvitationActions {...defaultProps} />);
      
      expect(screen.getByRole('button', { name: /resend/i })).not.toBeDisabled();
      expect(screen.getByRole('button', { name: /cancel/i })).not.toBeDisabled();
    });

    it('should handle rapid button clicks', async () => {
      const user = userEvent.setup();
      
      render(<InvitationActions {...defaultProps} />);
      
      const resendButton = screen.getByRole('button', { name: /resend/i });
      
      // Click multiple times rapidly
      await user.click(resendButton);
      await user.click(resendButton);
      await user.click(resendButton);

      // Should only call onAction once (due to confirmation dialog)
      expect(defaultProps.onAction).toHaveBeenCalledTimes(1);
    });
  });

  describe('Visual Design', () => {
    it('should have correct CSS classes for container', () => {
      render(<InvitationActions {...defaultProps} />);
      
      const container = screen.getByTestId('invitation-actions');
      expect(container).toHaveClass('flex', 'items-center', 'justify-between', 'p-4', 'border-b');
    });

    it('should have correct CSS classes for action buttons', () => {
      render(<InvitationActions {...defaultProps} />);
      
      const resendButton = screen.getByRole('button', { name: /resend/i });
      expect(resendButton).toHaveClass('px-3', 'py-1', 'text-sm', 'bg-blue-600', 'text-white');
      
      const cancelButton = screen.getByRole('button', { name: /cancel/i });
      expect(cancelButton).toHaveClass('px-3', 'py-1', 'text-sm', 'bg-red-600', 'text-white');
    });

    it('should have correct CSS classes for status badge', () => {
      render(<InvitationActions {...defaultProps} />);
      
      const statusBadge = screen.getByTestId('invitation-status');
      expect(statusBadge).toHaveClass('inline-flex', 'px-2', 'py-1', 'text-xs', 'font-medium');
    });
  });

  describe('Performance', () => {
    it('should handle multiple invitations efficiently', () => {
      const invitations = Array.from({ length: 50 }, (_, i) => ({
        ...mockInvitation,
        id: `inv-${i}`,
        email: `user${i}@example.com`,
      }));

      const startTime = performance.now();
      
      invitations.forEach((invitation) => {
        render(<InvitationActions {...defaultProps} invitation={invitation} />);
      });
      
      const endTime = performance.now();

      // Should render within reasonable time
      expect(endTime - startTime).toBeLessThan(100);
    });

    it('should not re-render unnecessarily', () => {
      const { rerender } = render(<InvitationActions {...defaultProps} />);
      
      // Re-render with same props
      rerender(<InvitationActions {...defaultProps} />);
      
      // Component should handle re-render gracefully
      expect(screen.getByText('test@example.com')).toBeInTheDocument();
    });
  });
});
