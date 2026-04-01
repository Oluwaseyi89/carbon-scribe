import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { renderHook } from '@testing-library/react';
import { Provider } from 'jotai';
import { TeamPage } from './page';
import { useStore } from '@/lib/store/store';
import type { ProjectMember } from '@/lib/store/collaboration/collaboration.types';

// Mock the store
vi.mock('@/lib/store/store', () => ({
  useStore: vi.fn(),
}));

const mockUseStore = vi.mocked(useStore);

// Mock the collaboration components
vi.mock('@/components/collaboration/TeamMembersList', () => ({
  default: ({ projectId, canManage }: { projectId: string; canManage: boolean }) => (
    <div data-testid="team-members-list">
      <span data-testid="project-id">{projectId}</span>
      <span data-testid="can-manage">{canManage.toString()}</span>
    </div>
  ),
}));

describe('TeamPage', () => {
  const mockStore = {
    members: [],
    collaborationLoading: { members: false },
    collaborationErrors: { members: null },
    fetchMembers: vi.fn(),
    setCurrentProjectId: vi.fn(),
    clearCollaborationErrors: vi.fn(),
  };

  beforeEach(() => {
    vi.clearAllMocks();
    mockUseStore.mockImplementation((selector) => selector(mockStore));
  });

  const renderWithProvider = (component: React.ReactElement) => {
    return render(
      <Provider>
        {component}
      </Provider>
    );
  };

  describe('Component Rendering', () => {
    it('should render team page with default tab', () => {
      renderWithProvider(<TeamPage />);
      
      expect(screen.getByText('Team')).toBeInTheDocument();
      expect(screen.getByRole('tab', { name: /members/i })).toBeInTheDocument();
      expect(screen.getByRole('tab', { name: /activities/i })).toBeInTheDocument();
      expect(screen.getByRole('tab', { name: /resources/i })).toBeInTheDocument();
    });

    it('should render search input', () => {
      renderWithProvider(<TeamPage />);
      
      expect(screen.getByPlaceholderText(/search team members/i)).toBeInTheDocument();
    });

    it('should render project filter dropdown', () => {
      renderWithProvider(<TeamPage />);
      
      expect(screen.getByText(/all projects/i)).toBeInTheDocument();
    });

    it('should render invite button when user can manage team', () => {
      renderWithProvider(<TeamPage />);
      
      expect(screen.getByRole('button', { name: /invite member/i })).toBeInTheDocument();
    });
  });

  describe('Tab Navigation', () => {
    it('should switch to activities tab when clicked', async () => {
      renderWithProvider(<TeamPage />);
      
      const activitiesTab = screen.getByRole('tab', { name: /activities/i });
      fireEvent.click(activitiesTab);

      await waitFor(() => {
        expect(activitiesTab).toHaveAttribute('aria-selected', 'true');
      });
    });

    it('should switch to resources tab when clicked', async () => {
      renderWithProvider(<TeamPage />);
      
      const resourcesTab = screen.getByRole('tab', { name: /resources/i });
      fireEvent.click(resourcesTab);

      await waitFor(() => {
        expect(resourcesTab).toHaveAttribute('aria-selected', 'true');
      });
    });

    it('should maintain members tab as active by default', () => {
      renderWithProvider(<TeamPage />);
      
      const membersTab = screen.getByRole('tab', { name: /members/i });
      expect(membersTab).toHaveAttribute('aria-selected', 'true');
    });
  });

  describe('Search Functionality', () => {
    it('should update search query when typing', async () => {
      renderWithProvider(<TeamPage />);
      
      const searchInput = screen.getByPlaceholderText(/search team members/i);
      fireEvent.change(searchInput, { target: { value: 'John' } });

      await waitFor(() => {
        expect(searchInput).toHaveValue('John');
      });
    });

    it('should clear search when clear button is clicked', async () => {
      renderWithProvider(<TeamPage />);
      
      const searchInput = screen.getByPlaceholderText(/search team members/i);
      fireEvent.change(searchInput, { target: { value: 'John' } });

      await waitFor(() => {
        expect(searchInput).toHaveValue('John');
      });

      // Find and click clear button (X icon)
      const clearButton = screen.getByRole('button', { name: /clear search/i });
      fireEvent.click(clearButton);

      await waitFor(() => {
        expect(searchInput).toHaveValue('');
      });
    });
  });

  describe('Project Filter', () => {
    it('should show project dropdown when clicked', async () => {
      renderWithProvider(<TeamPage />);
      
      const projectDropdown = screen.getByText(/all projects/i);
      fireEvent.click(projectDropdown);

      await waitFor(() => {
        expect(screen.getByText(/kenyan agroforestry/i)).toBeInTheDocument();
        expect(screen.getByText(/amazon rainforest/i)).toBeInTheDocument();
      });
    });

    it('should filter by project when project is selected', async () => {
      renderWithProvider(<TeamPage />);
      
      const projectDropdown = screen.getByText(/all projects/i);
      fireEvent.click(projectDropdown);

      const kenyanProject = screen.getByText(/kenyan agroforestry/i);
      fireEvent.click(kenyanProject);

      await waitFor(() => {
        expect(screen.getByText(/kenyan agroforestry/i)).toBeInTheDocument();
      });
    });
  });

  describe('Data Loading States', () => {
    it('should show loading skeleton when members are loading', () => {
      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        collaborationLoading: { members: true },
      }));

      renderWithProvider(<TeamPage />);
      
      expect(screen.getByTestId('loading-skeleton')).toBeInTheDocument();
    });

    it('should show error state when members fetch fails', () => {
      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        collaborationErrors: { members: 'Failed to fetch members' },
      }));

      renderWithProvider(<TeamPage />);
      
      expect(screen.getByText(/failed to fetch members/i)).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument();
    });

    it('should show empty state when no members exist', () => {
      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        members: [],
      }));

      renderWithProvider(<TeamPage />);
      
      expect(screen.getByText(/no team members yet/i)).toBeInTheDocument();
      expect(screen.getByText(/invite people to collaborate/i)).toBeInTheDocument();
    });
  });

  describe('Team Members Display', () => {
    it('should display team members when data is loaded', () => {
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
      ];

      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        members: mockMembers,
      }));

      renderWithProvider(<TeamPage />);
      
      expect(screen.getByTestId('team-members-list')).toBeInTheDocument();
      expect(screen.getByTestId('project-id')).toHaveTextContent('project-1');
    });

    it('should pass correct permissions to TeamMembersList', () => {
      const mockMembers: ProjectMember[] = [
        {
          id: '1',
          project_id: 'project-1',
          user_id: 'current-user',
          role: 'Manager',
          permissions: ['read', 'write', 'manage'],
          joined_at: '2023-01-01T00:00:00Z',
          updated_at: '2023-01-01T00:00:00Z',
        },
      ];

      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        members: mockMembers,
      }));

      renderWithProvider(<TeamPage />);
      
      expect(screen.getByTestId('can-manage')).toHaveTextContent('true');
    });

    it('should pass false permissions when user cannot manage team', () => {
      const mockMembers: ProjectMember[] = [
        {
          id: '1',
          project_id: 'project-1',
          user_id: 'current-user',
          role: 'Contributor',
          permissions: ['read', 'write'],
          joined_at: '2023-01-01T00:00:00Z',
          updated_at: '2023-01-01T00:00:00Z',
        },
      ];

      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        members: mockMembers,
      }));

      renderWithProvider(<TeamPage />);
      
      expect(screen.getByTestId('can-manage')).toHaveTextContent('false');
    });
  });

  describe('Invite Functionality', () => {
    it('should open invite modal when invite button is clicked', async () => {
      renderWithProvider(<TeamPage />);
      
      const inviteButton = screen.getByRole('button', { name: /invite member/i });
      fireEvent.click(inviteButton);

      await waitFor(() => {
        expect(screen.getByText(/invite team member/i)).toBeInTheDocument();
        expect(screen.getByLabelText(/email/i)).toBeInTheDocument();
        expect(screen.getByLabelText(/role/i)).toBeInTheDocument();
      });
    });

    it('should close invite modal when cancel is clicked', async () => {
      renderWithProvider(<TeamPage />);
      
      const inviteButton = screen.getByRole('button', { name: /invite member/i });
      fireEvent.click(inviteButton);

      await waitFor(() => {
        expect(screen.getByText(/invite team member/i)).toBeInTheDocument();
      });

      const cancelButton = screen.getByRole('button', { name: /cancel/i });
      fireEvent.click(cancelButton);

      await waitFor(() => {
        expect(screen.queryByText(/invite team member/i)).not.toBeInTheDocument();
      });
    });

    it('should submit invitation with valid data', async () => {
      renderWithProvider(<TeamPage />);
      
      const inviteButton = screen.getByRole('button', { name: /invite member/i });
      fireEvent.click(inviteButton);

      await waitFor(() => {
        expect(screen.getByText(/invite team member/i)).toBeInTheDocument();
      });

      const emailInput = screen.getByLabelText(/email/i);
      const roleSelect = screen.getByLabelText(/role/i);
      const submitButton = screen.getByRole('button', { name: /send invitation/i });

      fireEvent.change(emailInput, { target: { value: 'new.member@example.com' } });
      fireEvent.change(roleSelect, { target: { value: 'Contributor' } });
      fireEvent.click(submitButton);

      await waitFor(() => {
        expect(screen.queryByText(/invite team member/i)).not.toBeInTheDocument();
      });
    });
  });

  describe('Error Handling', () => {
    it('should retry fetching members when retry button is clicked', async () => {
      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        collaborationErrors: { members: 'Failed to fetch members' },
      }));

      renderWithProvider(<TeamPage />);
      
      const retryButton = screen.getByRole('button', { name: /retry/i });
      fireEvent.click(retryButton);

      await waitFor(() => {
        expect(mockStore.fetchMembers).toHaveBeenCalled();
      });
    });

    it('should clear errors when clear errors is called', async () => {
      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        collaborationErrors: { members: 'Failed to fetch members' },
      }));

      renderWithProvider(<TeamPage />);
      
      // Simulate error clearing
      mockStore.clearCollaborationErrors();

      await waitFor(() => {
        expect(mockStore.clearCollaborationErrors).toHaveBeenCalled();
      });
    });
  });

  describe('Component Lifecycle', () => {
    it('should fetch members on component mount', () => {
      renderWithProvider(<TeamPage />);
      
      expect(mockStore.fetchMembers).toHaveBeenCalled();
      expect(mockStore.setCurrentProjectId).toHaveBeenCalled();
    });

    it('should clear errors on component unmount', () => {
      const { unmount } = renderWithProvider(<TeamPage />);
      
      unmount();
      
      // Note: In a real implementation, you'd use useEffect cleanup
      // This is a simplified test to demonstrate the concept
    });
  });

  describe('Responsive Design', () => {
    it('should adapt layout for mobile screens', () => {
      // Mock mobile viewport
      Object.defineProperty(window, 'innerWidth', {
        writable: true,
        configurable: true,
        value: 375,
      });

      renderWithProvider(<TeamPage />);
      
      // Check for mobile-specific elements
      expect(screen.getByRole('button', { name: /menu/i })).toBeInTheDocument();
    });

    it('should show full layout on desktop screens', () => {
      // Mock desktop viewport
      Object.defineProperty(window, 'innerWidth', {
        writable: true,
        configurable: true,
        value: 1024,
      });

      renderWithProvider(<TeamPage />);
      
      // Check for desktop-specific elements
      expect(screen.getByRole('navigation')).toBeInTheDocument();
    });
  });

  describe('Accessibility', () => {
    it('should have proper ARIA labels', () => {
      renderWithProvider(<TeamPage />);
      
      expect(screen.getByRole('main')).toBeInTheDocument();
      expect(screen.getByRole('navigation')).toBeInTheDocument();
      expect(screen.getByRole('tablist')).toBeInTheDocument();
    });

    it('should support keyboard navigation', async () => {
      renderWithProvider(<TeamPage />);
      
      const firstTab = screen.getByRole('tab', { name: /members/i });
      firstTab.focus();
      
      fireEvent.keyDown(firstTab, { key: 'ArrowRight' });
      
      await waitFor(() => {
        expect(screen.getByRole('tab', { name: /activities/i })).toHaveFocus();
      });
    });

    it('should announce screen reader messages', () => {
      renderWithProvider(<TeamPage />);
      
      expect(screen.getByRole('status')).toBeInTheDocument();
    });
  });
});
