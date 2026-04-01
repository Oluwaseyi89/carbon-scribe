import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import InviteUserModal from '@/components/collaboration/InviteUserModal';
import { useStore } from '@/lib/store/store';
import type { ProjectInvitation } from '@/lib/store/collaboration/collaboration.types';

// Mock the store
vi.mock('@/lib/store/store', () => ({
  useStore: vi.fn(),
}));

const mockUseStore = vi.mocked(useStore);

describe('InviteUserModal', () => {
  const mockStore = {
    inviteUser: vi.fn(),
    collaborationLoading: { invite: false },
    collaborationErrors: { invite: null },
    clearCollaborationErrors: vi.fn(),
  };

  beforeEach(() => {
    vi.clearAllMocks();
    mockUseStore.mockImplementation((selector) => selector(mockStore));
  });

  const defaultProps = {
    isOpen: true,
    onClose: vi.fn(),
    projectId: 'project-1',
  };

  describe('Modal Rendering', () => {
    it('should render modal when isOpen is true', () => {
      render(<InviteUserModal {...defaultProps} />);
      
      expect(screen.getByText(/invite team member/i)).toBeInTheDocument();
      expect(screen.getByRole('dialog')).toBeInTheDocument();
    });

    it('should not render modal when isOpen is false', () => {
      render(<InviteUserModal {...defaultProps} isOpen={false} />);
      
      expect(screen.queryByText(/invite team member/i)).not.toBeInTheDocument();
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });

    it('should render form fields', () => {
      render(<InviteUserModal {...defaultProps} />);
      
      expect(screen.getByLabelText(/email/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/role/i)).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /send invitation/i })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /cancel/i })).toBeInTheDocument();
    });

    it('should have proper ARIA attributes', () => {
      render(<InviteUserModal {...defaultProps} />);
      
      const dialog = screen.getByRole('dialog');
      expect(dialog).toHaveAttribute('aria-modal', 'true');
      expect(dialog).toHaveAttribute('aria-labelledby');
      expect(dialog).toHaveAttribute('aria-describedby');
    });
  });

  describe('Form Validation', () => {
    it('should show validation error for empty email', async () => {
      const user = userEvent.setup();
      
      render(<InviteUserModal {...defaultProps} />);
      
      const submitButton = screen.getByRole('button', { name: /send invitation/i });
      await user.click(submitButton);

      expect(screen.getByText(/email is required/i)).toBeInTheDocument();
      expect(mockStore.inviteUser).not.toHaveBeenCalled();
    });

    it('should show validation error for invalid email', async () => {
      const user = userEvent.setup();
      
      render(<InviteUserModal {...defaultProps} />);
      
      const emailInput = screen.getByLabelText(/email/i);
      const submitButton = screen.getByRole('button', { name: /send invitation/i });

      await user.type(emailInput, 'invalid-email');
      await user.click(submitButton);

      expect(screen.getByText(/please enter a valid email/i)).toBeInTheDocument();
      expect(mockStore.inviteUser).not.toHaveBeenCalled();
    });

    it('should show validation error for empty role', async () => {
      const user = userEvent.setup();
      
      render(<InviteUserModal {...defaultProps} />);
      
      const emailInput = screen.getByLabelText(/email/i);
      const submitButton = screen.getByRole('button', { name: /send invitation/i });

      await user.type(emailInput, 'valid@example.com');
      await user.click(submitButton);

      expect(screen.getByText(/role is required/i)).toBeInTheDocument();
      expect(mockStore.inviteUser).not.toHaveBeenCalled();
    });

    it('should not show validation errors for valid input', async () => {
      const user = userEvent.setup();
      
      render(<InviteUserModal {...defaultProps} />);
      
      const emailInput = screen.getByLabelText(/email/i);
      const roleSelect = screen.getByLabelText(/role/i);

      await user.type(emailInput, 'valid@example.com');
      await user.selectOptions(roleSelect, 'Contributor');

      expect(screen.queryByText(/email is required/i)).not.toBeInTheDocument();
      expect(screen.queryByText(/role is required/i)).not.toBeInTheDocument();
    });
  });

  describe('Form Submission', () => {
    it('should call inviteUser with correct data', async () => {
      const user = userEvent.setup();
      const mockInvitation: ProjectInvitation = {
        id: 'inv-1',
        project_id: 'project-1',
        email: 'new@example.com',
        role: 'Contributor',
        status: 'pending',
        expires_at: '2023-01-15T00:00:00Z',
        created_at: '2023-01-01T00:00:00Z',
        updated_at: '2023-01-01T00:00:00Z',
      };

      mockStore.inviteUser.mockResolvedValue(mockInvitation);

      render(<InviteUserModal {...defaultProps} />);
      
      const emailInput = screen.getByLabelText(/email/i);
      const roleSelect = screen.getByLabelText(/role/i);
      const submitButton = screen.getByRole('button', { name: /send invitation/i });

      await user.type(emailInput, 'new@example.com');
      await user.selectOptions(roleSelect, 'Contributor');
      await user.click(submitButton);

      expect(mockStore.inviteUser).toHaveBeenCalledWith('project-1', {
        email: 'new@example.com',
        role: 'Contributor',
      });
    });

    it('should close modal on successful submission', async () => {
      const user = userEvent.setup();
      const mockInvitation: ProjectInvitation = {
        id: 'inv-1',
        project_id: 'project-1',
        email: 'new@example.com',
        role: 'Contributor',
        status: 'pending',
        expires_at: '2023-01-15T00:00:00Z',
        created_at: '2023-01-01T00:00:00Z',
        updated_at: '2023-01-01T00:00:00Z',
      };

      mockStore.inviteUser.mockResolvedValue(mockInvitation);

      render(<InviteUserModal {...defaultProps} />);
      
      const emailInput = screen.getByLabelText(/email/i);
      const roleSelect = screen.getByLabelText(/role/i);
      const submitButton = screen.getByRole('button', { name: /send invitation/i });

      await user.type(emailInput, 'new@example.com');
      await user.selectOptions(roleSelect, 'Contributor');
      await user.click(submitButton);

      await waitFor(() => {
        expect(defaultProps.onClose).toHaveBeenCalled();
      });
    });

    it('should not close modal on failed submission', async () => {
      const user = userEvent.setup();
      
      mockStore.inviteUser.mockResolvedValue(null);

      render(<InviteUserModal {...defaultProps} />);
      
      const emailInput = screen.getByLabelText(/email/i);
      const roleSelect = screen.getByLabelText(/role/i);
      const submitButton = screen.getByRole('button', { name: /send invitation/i });

      await user.type(emailInput, 'new@example.com');
      await user.selectOptions(roleSelect, 'Contributor');
      await user.click(submitButton);

      await waitFor(() => {
        expect(defaultProps.onClose).not.toHaveBeenCalled();
      });
    });
  });

  describe('Loading States', () => {
    it('should show loading state during submission', async () => {
      const user = userEvent.setup();
      
      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        collaborationLoading: { invite: true },
      }));

      render(<InviteUserModal {...defaultProps} />);
      
      const submitButton = screen.getByRole('button', { name: /send invitation/i });
      expect(submitButton).toBeDisabled();
      expect(screen.getByTestId('loading-spinner')).toBeInTheDocument();
    });

    it('should disable form fields during loading', () => {
      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        collaborationLoading: { invite: true },
      }));

      render(<InviteUserModal {...defaultProps} />);
      
      expect(screen.getByLabelText(/email/i)).toBeDisabled();
      expect(screen.getByLabelText(/role/i)).toBeDisabled();
    });
  });

  describe('Error Handling', () => {
    it('should display error message when invitation fails', async () => {
      const user = userEvent.setup();
      
      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        collaborationErrors: { invite: 'Failed to send invitation' },
      }));

      render(<InviteUserModal {...defaultProps} />);
      
      expect(screen.getByText(/failed to send invitation/i)).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument();
    });

    it('should clear error when user retries', async () => {
      const user = userEvent.setup();
      
      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        collaborationErrors: { invite: 'Failed to send invitation' },
      }));

      render(<InviteUserModal {...defaultProps} />);
      
      const retryButton = screen.getByRole('button', { name: /retry/i });
      await user.click(retryButton);

      expect(mockStore.clearCollaborationErrors).toHaveBeenCalled();
    });

    it('should show network error message', async () => {
      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        collaborationErrors: { invite: 'Network error. Please try again.' },
      }));

      render(<InviteUserModal {...defaultProps} />);
      
      expect(screen.getByText(/network error/i)).toBeInTheDocument();
    });

    it('should show permission error message', async () => {
      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        collaborationErrors: { invite: 'You do not have permission to invite members.' },
      }));

      render(<InviteUserModal {...defaultProps} />);
      
      expect(screen.getByText(/you do not have permission/i)).toBeInTheDocument();
    });
  });

  describe('Modal Interactions', () => {
    it('should call onClose when cancel button is clicked', async () => {
      const user = userEvent.setup();
      
      render(<InviteUserModal {...defaultProps} />);
      
      const cancelButton = screen.getByRole('button', { name: /cancel/i });
      await user.click(cancelButton);

      expect(defaultProps.onClose).toHaveBeenCalled();
    });

    it('should call onClose when close button is clicked', async () => {
      const user = userEvent.setup();
      
      render(<InviteUserModal {...defaultProps} />);
      
      const closeButton = screen.getByRole('button', { name: /close/i });
      await user.click(closeButton);

      expect(defaultProps.onClose).toHaveBeenCalled();
    });

    it('should call onClose when escape key is pressed', async () => {
      render(<InviteUserModal {...defaultProps} />);
      
      fireEvent.keyDown(screen.getByRole('dialog'), { key: 'Escape' });

      expect(defaultProps.onClose).toHaveBeenCalled();
    });

    it('should call onClose when overlay is clicked', async () => {
      const user = userEvent.setup();
      
      render(<InviteUserModal {...defaultProps} />);
      
      const overlay = screen.getByTestId('modal-overlay');
      await user.click(overlay);

      expect(defaultProps.onClose).toHaveBeenCalled();
    });
  });

  describe('Role Selection', () => {
    it('should display all available roles', () => {
      render(<InviteUserModal {...defaultProps} />);
      
      const roleSelect = screen.getByLabelText(/role/i);
      
      expect(screen.getByRole('option', { name: /owner/i })).toBeInTheDocument();
      expect(screen.getByRole('option', { name: /manager/i })).toBeInTheDocument();
      expect(screen.getByRole('option', { name: /contributor/i })).toBeInTheDocument();
      expect(screen.getByRole('option', { name: /viewer/i })).toBeInTheDocument();
    });

    it('should have role descriptions', () => {
      render(<InviteUserModal {...defaultProps} />);
      
      expect(screen.getByText(/full access to all project features/i)).toBeInTheDocument();
      expect(screen.getByText(/can manage team members and settings/i)).toBeInTheDocument();
      expect(screen.getByText(/can contribute to project content/i)).toBeInTheDocument();
      expect(screen.getByText(/can only view project content/i)).toBeInTheDocument();
    });

    it('should update role description when role changes', async () => {
      const user = userEvent.setup();
      
      render(<InviteUserModal {...defaultProps} />);
      
      const roleSelect = screen.getByLabelText(/role/i);
      
      await user.selectOptions(roleSelect, 'Owner');
      expect(screen.getByText(/full access to all project features/i)).toBeInTheDocument();
      
      await user.selectOptions(roleSelect, 'Viewer');
      expect(screen.getByText(/can only view project content/i)).toBeInTheDocument();
    });
  });

  describe('Email Input', () => {
    it('should format email input correctly', async () => {
      const user = userEvent.setup();
      
      render(<InviteUserModal {...defaultProps} />);
      
      const emailInput = screen.getByLabelText(/email/i);
      
      await user.type(emailInput, 'TEST@EXAMPLE.COM');
      expect(emailInput).toHaveValue('TEST@EXAMPLE.COM'); // Should preserve case for display
    });

    it('should show email validation feedback', async () => {
      const user = userEvent.setup();
      
      render(<InviteUserModal {...defaultProps} />);
      
      const emailInput = screen.getByLabelText(/email/i);
      
      await user.type(emailInput, 'invalid');
      expect(screen.getByText(/please enter a valid email/i)).toBeInTheDocument();
      
      await user.clear(emailInput);
      await user.type(emailInput, 'valid@example.com');
      expect(screen.queryByText(/please enter a valid email/i)).not.toBeInTheDocument();
    });

    it('should handle email with special characters', async () => {
      const user = userEvent.setup();
      
      render(<InviteUserModal {...defaultProps} />);
      
      const emailInput = screen.getByLabelText(/email/i);
      
      await user.type(emailInput, 'test.email+tag@example.co.uk');
      expect(screen.queryByText(/please enter a valid email/i)).not.toBeInTheDocument();
    });
  });

  describe('Accessibility', () => {
    it('should trap focus within modal', async () => {
      const user = userEvent.setup();
      
      render(<InviteUserModal {...defaultProps} />);
      
      const emailInput = screen.getByLabelText(/email/i);
      const cancelButton = screen.getByRole('button', { name: /cancel/i });
      
      emailInput.focus();
      
      await user.tab();
      expect(screen.getByLabelText(/role/i)).toHaveFocus();
      
      await user.tab();
      expect(screen.getByRole('button', { name: /send invitation/i })).toHaveFocus();
      
      await user.tab();
      expect(cancelButton).toHaveFocus();
      
      await user.tab();
      expect(emailInput).toHaveFocus(); // Focus should loop back
    });

    it('should have proper heading structure', () => {
      render(<InviteUserModal {...defaultProps} />);
      
      expect(screen.getByRole('heading', { level: 2 })).toHaveTextContent(/invite team member/i);
    });

    it('should announce form errors to screen readers', async () => {
      const user = userEvent.setup();
      
      render(<InviteUserModal {...defaultProps} />);
      
      const submitButton = screen.getByRole('button', { name: /send invitation/i });
      await user.click(submitButton);

      expect(screen.getByRole('alert')).toBeInTheDocument();
      expect(screen.getByRole('alert')).toHaveTextContent(/email is required/i);
    });
  });

  describe('Component Lifecycle', () => {
    it('should clear errors when modal opens', () => {
      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        collaborationErrors: { invite: 'Previous error' },
      }));

      render(<InviteUserModal {...defaultProps} />);
      
      // Should clear errors when modal opens
      expect(mockStore.clearCollaborationErrors).toHaveBeenCalled();
    });

    it('should reset form when modal closes and reopens', async () => {
      const user = userEvent.setup();
      
      const { rerender } = render(<InviteUserModal {...defaultProps} />);
      
      // Fill form
      const emailInput = screen.getByLabelText(/email/i);
      await user.type(emailInput, 'test@example.com');
      
      // Close modal
      rerender(<InviteUserModal {...defaultProps} isOpen={false} />);
      
      // Reopen modal
      rerender(<InviteUserModal {...defaultProps} isOpen={true} />);
      
      // Form should be reset
      expect(screen.getByLabelText(/email/i)).toHaveValue('');
    });
  });
});
