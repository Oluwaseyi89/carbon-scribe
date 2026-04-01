import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook } from '@testing-library/react';
import { useInvitations } from './useInvitations';
import { useStore } from '@/lib/store/store';
import type { ProjectInvitation } from '@/lib/store/collaboration/collaboration.types';

// Mock the store
vi.mock('@/lib/store/store', () => ({
  useStore: vi.fn(),
}));

const mockUseStore = vi.mocked(useStore);

describe('useInvitations', () => {
  const mockStore = {
    invitations: [],
    collaborationLoading: { invitations: false },
    collaborationErrors: { invitations: null },
    fetchInvitations: vi.fn(),
    inviteUser: vi.fn(),
  };

  beforeEach(() => {
    vi.clearAllMocks();
    mockUseStore.mockImplementation((selector) => selector(mockStore));
  });

  describe('Hook Behavior', () => {
    it('should return invitations data from store', () => {
      const mockInvitations: ProjectInvitation[] = [
        {
          id: 'inv-1',
          project_id: 'project-1',
          email: 'test@example.com',
          role: 'Contributor',
          status: 'pending',
          expires_at: '2023-01-15T00:00:00Z',
          created_at: '2023-01-01T00:00:00Z',
          updated_at: '2023-01-01T00:00:00Z',
        },
      ];

      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        invitations: mockInvitations,
      }));

      const { result } = renderHook(() => useInvitations('project-1'));

      expect(result.current.invitations).toEqual(mockInvitations);
      expect(result.current.loading).toBe(false);
      expect(result.current.error).toBeNull();
    });

    it('should return loading state from store', () => {
      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        collaborationLoading: { ...mockStore.collaborationLoading, invitations: true },
      }));

      const { result } = renderHook(() => useInvitations('project-1'));

      expect(result.current.loading).toBe(true);
    });

    it('should return error state from store', () => {
      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        collaborationErrors: { ...mockStore.collaborationErrors, invitations: 'Failed to fetch' },
      }));

      const { result } = renderHook(() => useInvitations('project-1'));

      expect(result.current.error).toBe('Failed to fetch');
    });

    it('should call fetchInvitations when projectId changes', () => {
      const { rerender } = renderHook(({ projectId }) => useInvitations(projectId), {
        initialProps: { projectId: 'project-1' },
      });

      expect(mockStore.fetchInvitations).toHaveBeenCalledWith('project-1');

      rerender({ projectId: 'project-2' });

      expect(mockStore.fetchInvitations).toHaveBeenCalledWith('project-2');
      expect(mockStore.fetchInvitations).toHaveBeenCalledTimes(2);
    });

    it('should not call fetchInvitations on initial render if projectId is empty', () => {
      renderHook(() => useInvitations(''));

      expect(mockStore.fetchInvitations).not.toHaveBeenCalled();
    });

    it('should not call fetchInvitations if projectId has not changed', () => {
      const { rerender } = renderHook(({ projectId }) => useInvitations(projectId), {
        initialProps: { projectId: 'project-1' },
      });

      rerender({ projectId: 'project-1' });

      expect(mockStore.fetchInvitations).toHaveBeenCalledTimes(1);
    });
  });

  describe('Data Processing', () => {
    it('should filter out expired invitations', () => {
      const mockInvitations: ProjectInvitation[] = [
        {
          id: 'inv-1',
          project_id: 'project-1',
          email: 'pending@example.com',
          role: 'Contributor',
          status: 'pending',
          expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(), // Tomorrow
          created_at: '2023-01-01T00:00:00Z',
          updated_at: '2023-01-01T00:00:00Z',
        },
        {
          id: 'inv-2',
          project_id: 'project-1',
          email: 'expired@example.com',
          role: 'Contributor',
          status: 'expired',
          expires_at: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(), // Yesterday
          created_at: '2023-01-01T00:00:00Z',
          updated_at: '2023-01-01T00:00:00Z',
        },
      ];

      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        invitations: mockInvitations,
      }));

      const { result } = renderHook(() => useInvitations('project-1'));

      expect(result.current.pendingInvitations).toHaveLength(1);
      expect(result.current.pendingInvitations[0].email).toBe('pending@example.com');
      expect(result.current.expiredInvitations).toHaveLength(1);
      expect(result.current.expiredInvitations[0].email).toBe('expired@example.com');
    });

    it('should sort invitations by creation date (newest first)', () => {
      const mockInvitations: ProjectInvitation[] = [
        {
          id: 'inv-1',
          project_id: 'project-1',
          email: 'old@example.com',
          role: 'Contributor',
          status: 'pending',
          expires_at: '2023-01-15T00:00:00Z',
          created_at: '2023-01-01T00:00:00Z',
          updated_at: '2023-01-01T00:00:00Z',
        },
        {
          id: 'inv-2',
          project_id: 'project-1',
          email: 'new@example.com',
          role: 'Contributor',
          status: 'pending',
          expires_at: '2023-01-15T00:00:00Z',
          created_at: '2023-01-03T00:00:00Z',
          updated_at: '2023-01-03T00:00:00Z',
        },
        {
          id: 'inv-3',
          project_id: 'project-1',
          email: 'middle@example.com',
          role: 'Contributor',
          status: 'pending',
          expires_at: '2023-01-15T00:00:00Z',
          created_at: '2023-01-02T00:00:00Z',
          updated_at: '2023-01-02T00:00:00Z',
        },
      ];

      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        invitations: mockInvitations,
      }));

      const { result } = renderHook(() => useInvitations('project-1'));

      expect(result.current.invitations[0].email).toBe('new@example.com');
      expect(result.current.invitations[1].email).toBe('middle@example.com');
      expect(result.current.invitations[2].email).toBe('old@example.com');
    });

    it('should calculate invitation statistics', () => {
      const mockInvitations: ProjectInvitation[] = [
        {
          id: 'inv-1',
          project_id: 'project-1',
          email: 'pending1@example.com',
          role: 'Contributor',
          status: 'pending',
          expires_at: '2023-01-15T00:00:00Z',
          created_at: '2023-01-01T00:00:00Z',
          updated_at: '2023-01-01T00:00:00Z',
        },
        {
          id: 'inv-2',
          project_id: 'project-1',
          email: 'pending2@example.com',
          role: 'Contributor',
          status: 'pending',
          expires_at: '2023-01-15T00:00:00Z',
          created_at: '2023-01-02T00:00:00Z',
          updated_at: '2023-01-02T00:00:00Z',
        },
        {
          id: 'inv-3',
          project_id: 'project-1',
          email: 'accepted@example.com',
          role: 'Contributor',
          status: 'accepted',
          expires_at: '2023-01-15T00:00:00Z',
          created_at: '2023-01-01T00:00:00Z',
          updated_at: '2023-01-01T00:00:00Z',
        },
        {
          id: 'inv-4',
          project_id: 'project-1',
          email: 'expired@example.com',
          role: 'Contributor',
          status: 'expired',
          expires_at: '2023-01-15T00:00:00Z',
          created_at: '2023-01-01T00:00:00Z',
          updated_at: '2023-01-01T00:00:00Z',
        },
      ];

      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        invitations: mockInvitations,
      }));

      const { result } = renderHook(() => useInvitations('project-1'));

      expect(result.current.stats).toEqual({
        total: 4,
        pending: 2,
        accepted: 1,
        expired: 1,
      });
    });

    it('should group invitations by role', () => {
      const mockInvitations: ProjectInvitation[] = [
        {
          id: 'inv-1',
          project_id: 'project-1',
          email: 'owner@example.com',
          role: 'Owner',
          status: 'pending',
          expires_at: '2023-01-15T00:00:00Z',
          created_at: '2023-01-01T00:00:00Z',
          updated_at: '2023-01-01T00:00:00Z',
        },
        {
          id: 'inv-2',
          project_id: 'project-1',
          email: 'contributor1@example.com',
          role: 'Contributor',
          status: 'pending',
          expires_at: '2023-01-15T00:00:00Z',
          created_at: '2023-01-02T00:00:00Z',
          updated_at: '2023-01-02T00:00:00Z',
        },
        {
          id: 'inv-3',
          project_id: 'project-1',
          email: 'contributor2@example.com',
          role: 'Contributor',
          status: 'pending',
          expires_at: '2023-01-15T00:00:00Z',
          created_at: '2023-01-03T00:00:00Z',
          updated_at: '2023-01-03T00:00:00Z',
        },
      ];

      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        invitations: mockInvitations,
      }));

      const { result } = renderHook(() => useInvitations('project-1'));

      expect(result.current.invitationsByRole).toEqual({
        Owner: [mockInvitations[0]],
        Contributor: [mockInvitations[1], mockInvitations[2]],
        Manager: [],
        Viewer: [],
      });
    });

    it('should identify invitations expiring soon', () => {
      const mockInvitations: ProjectInvitation[] = [
        {
          id: 'inv-1',
          project_id: 'project-1',
          email: 'expiring-soon@example.com',
          role: 'Contributor',
          status: 'pending',
          expires_at: new Date(Date.now() + 12 * 60 * 60 * 1000).toISOString(), // 12 hours from now
          created_at: '2023-01-01T00:00:00Z',
          updated_at: '2023-01-01T00:00:00Z',
        },
        {
          id: 'inv-2',
          project_id: 'project-1',
          email: 'not-expiring-soon@example.com',
          role: 'Contributor',
          status: 'pending',
          expires_at: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000).toISOString(), // 3 days from now
          created_at: '2023-01-01T00:00:00Z',
          updated_at: '2023-01-01T00:00:00Z',
        },
      ];

      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        invitations: mockInvitations,
      }));

      const { result } = renderHook(() => useInvitations('project-1'));

      expect(result.current.expiringSoon).toHaveLength(1);
      expect(result.current.expiringSoon[0].email).toBe('expiring-soon@example.com');
    });
  });

  describe('Actions', () => {
    it('should provide resendInvitation function', () => {
      const { result } = renderHook(() => useInvitations('project-1'));

      expect(typeof result.current.resendInvitation).toBe('function');
    });

    it('should provide cancelInvitation function', () => {
      const { result } = renderHook(() => useInvitations('project-1'));

      expect(typeof result.current.cancelInvitation).toBe('function');
    });

    it('should provide createInvitation function', () => {
      const { result } = renderHook(() => useInvitations('project-1'));

      expect(typeof result.current.createInvitation).toBe('function');
    });

    it('should handle invitation creation', async () => {
      const mockInvitation: ProjectInvitation = {
        id: 'inv-new',
        project_id: 'project-1',
        email: 'new@example.com',
        role: 'Contributor',
        status: 'pending',
        expires_at: '2023-01-15T00:00:00Z',
        created_at: '2023-01-01T00:00:00Z',
        updated_at: '2023-01-01T00:00:00Z',
      };

      mockStore.inviteUser.mockResolvedValue(mockInvitation);

      const { result } = renderHook(() => useInvitations('project-1'));

      const createdInvitation = await result.current.createInvitation({
        email: 'new@example.com',
        role: 'Contributor',
      });

      expect(mockStore.inviteUser).toHaveBeenCalledWith('project-1', {
        email: 'new@example.com',
        role: 'Contributor',
      });
      expect(createdInvitation).toEqual(mockInvitation);
    });

    it('should handle invitation creation failure', async () => {
      mockStore.inviteUser.mockResolvedValue(null);

      const { result } = renderHook(() => useInvitations('project-1'));

      const createdInvitation = await result.current.createInvitation({
        email: 'new@example.com',
        role: 'Contributor',
      });

      expect(createdInvitation).toBeNull();
    });
  });

  describe('Error Handling', () => {
    it('should handle undefined invitations gracefully', () => {
      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        invitations: undefined as any,
      }));

      const { result } = renderHook(() => useInvitations('project-1'));

      expect(result.current.invitations).toEqual([]);
      expect(result.current.loading).toBe(false);
      expect(result.current.error).toBeNull();
    });

    it('should handle null invitations gracefully', () => {
      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        invitations: null as any,
      }));

      const { result } = renderHook(() => useInvitations('project-1'));

      expect(result.current.invitations).toEqual([]);
    });

    it('should handle malformed invitation data gracefully', () => {
      const malformedInvitations = [
        {
          id: '1',
          project_id: 'project-1',
          email: '',
          role: '',
          status: 'pending',
          expires_at: '',
          created_at: '',
          updated_at: '',
        },
        null,
        undefined,
      ] as any;

      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        invitations: malformedInvitations,
      }));

      const { result } = renderHook(() => useInvitations('project-1'));

      expect(result.current.invitations).toEqual([]);
    });

    it('should handle network errors gracefully', () => {
      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        collaborationErrors: { ...mockStore.collaborationErrors, invitations: 'Network error' },
        collaborationLoading: { ...mockStore.collaborationLoading, invitations: false },
      }));

      const { result } = renderHook(() => useInvitations('project-1'));

      expect(result.current.error).toBe('Network error');
      expect(result.current.loading).toBe(false);
    });
  });

  describe('Performance', () => {
    it('should not cause unnecessary re-renders', () => {
      const { result, rerender } = renderHook(() => useInvitations('project-1'));

      const initialInvitations = result.current.invitations;
      const initialLoading = result.current.loading;
      const initialError = result.current.error;

      rerender();

      expect(result.current.invitations).toBe(initialInvitations);
      expect(result.current.loading).toBe(initialLoading);
      expect(result.current.error).toBe(initialError);
    });

    it('should handle large invitation lists efficiently', () => {
      const largeInvitationList: ProjectInvitation[] = Array.from({ length: 500 }, (_, i) => ({
        id: `inv-${i}`,
        project_id: 'project-1',
        email: `user${i}@example.com`,
        role: i % 4 === 0 ? 'Owner' : i % 3 === 0 ? 'Manager' : i % 2 === 0 ? 'Contributor' : 'Viewer',
        status: i % 3 === 0 ? 'pending' : i % 2 === 0 ? 'accepted' : 'expired',
        expires_at: '2023-01-15T00:00:00Z',
        created_at: '2023-01-01T00:00:00Z',
        updated_at: '2023-01-01T00:00:00Z',
      }));

      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        invitations: largeInvitationList,
      }));

      const startTime = performance.now();
      const { result } = renderHook(() => useInvitations('project-1'));
      const endTime = performance.now();

      expect(result.current.invitations).toHaveLength(500);
      expect(result.current.stats.total).toBe(500);
      expect(endTime - startTime).toBeLessThan(50); // Should process quickly
    });
  });

  describe('Side Effects', () => {
    it('should clear errors when fetching new data', () => {
      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        collaborationErrors: { ...mockStore.collaborationErrors, invitations: 'Previous error' },
      }));

      const { rerender } = renderHook(({ projectId }) => useInvitations(projectId), {
        initialProps: { projectId: 'project-1' },
      });

      // Clear errors should be called when projectId changes
      rerender({ projectId: 'project-2' });

      expect(mockStore.fetchInvitations).toHaveBeenCalledTimes(2);
    });

    it('should reset state when projectId becomes empty', () => {
      const { rerender } = renderHook(({ projectId }) => useInvitations(projectId), {
        initialProps: { projectId: 'project-1' },
      });

      rerender({ projectId: '' });

      expect(mockStore.fetchInvitations).not.toHaveBeenCalledWith('');
    });
  });

  describe('Integration with Store', () => {
    it('should update when store invitations change', () => {
      const { result, rerender } = renderHook(() => useInvitations('project-1'));

      const initialInvitations = result.current.invitations;

      // Simulate store update
      const newInvitations: ProjectInvitation[] = [
        {
          id: 'inv-2',
          project_id: 'project-1',
          email: 'updated@example.com',
          role: 'Contributor',
          status: 'pending',
          expires_at: '2023-01-15T00:00:00Z',
          created_at: '2023-01-02T00:00:00Z',
          updated_at: '2023-01-02T00:00:00Z',
        },
      ];

      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        invitations: newInvitations,
      }));

      rerender();

      expect(result.current.invitations).toEqual(newInvitations);
      expect(result.current.invitations).not.toBe(initialInvitations);
    });

    it('should update when store loading state changes', () => {
      const { result, rerender } = renderHook(() => useInvitations('project-1'));

      expect(result.current.loading).toBe(false);

      // Simulate loading state change
      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        collaborationLoading: { ...mockStore.collaborationLoading, invitations: true },
      }));

      rerender();

      expect(result.current.loading).toBe(true);
    });

    it('should update when store error state changes', () => {
      const { result, rerender } = renderHook(() => useInvitations('project-1'));

      expect(result.current.error).toBeNull();

      // Simulate error state change
      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        collaborationErrors: { ...mockStore.collaborationErrors, invitations: 'New error' },
      }));

      rerender();

      expect(result.current.error).toBe('New error');
    });
  });

  describe('Utility Functions', () => {
    it('should provide utility to check if invitation is expired', () => {
      const mockInvitations: ProjectInvitation[] = [
        {
          id: 'inv-1',
          project_id: 'project-1',
          email: 'expired@example.com',
          role: 'Contributor',
          status: 'expired',
          expires_at: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
          created_at: '2023-01-01T00:00:00Z',
          updated_at: '2023-01-01T00:00:00Z',
        },
        {
          id: 'inv-2',
          project_id: 'project-1',
          email: 'pending@example.com',
          role: 'Contributor',
          status: 'pending',
          expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
          created_at: '2023-01-01T00:00:00Z',
          updated_at: '2023-01-01T00:00:00Z',
        },
      ];

      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        invitations: mockInvitations,
      }));

      const { result } = renderHook(() => useInvitations('project-1'));

      expect(result.current.isInvitationExpired(mockInvitations[0])).toBe(true);
      expect(result.current.isInvitationExpired(mockInvitations[1])).toBe(false);
    });

    it('should provide utility to get invitation status text', () => {
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

      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        invitations: [mockInvitation],
      }));

      const { result } = renderHook(() => useInvitations('project-1'));

      expect(result.current.getInvitationStatusText(mockInvitation)).toBe('Pending');
    });
  });
});
