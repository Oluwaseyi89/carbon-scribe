import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook } from '@testing-library/react';
import { useTeamMembers } from './useTeamMembers';
import { useStore } from '@/lib/store/store';
import type { ProjectMember } from '@/lib/store/collaboration/collaboration.types';

// Mock the store
vi.mock('@/lib/store/store', () => ({
  useStore: vi.fn(),
}));

const mockUseStore = vi.mocked(useStore);

describe('useTeamMembers', () => {
  const mockStore = {
    members: [],
    collaborationLoading: { members: false },
    collaborationErrors: { members: null },
    fetchMembers: vi.fn(),
    setCurrentProjectId: vi.fn(),
  };

  beforeEach(() => {
    vi.clearAllMocks();
    mockUseStore.mockImplementation((selector) => selector(mockStore));
  });

  describe('Hook Behavior', () => {
    it('should return team members data from store', () => {
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

      const { result } = renderHook(() => useTeamMembers('project-1'));

      expect(result.current.members).toEqual(mockMembers);
      expect(result.current.loading).toBe(false);
      expect(result.current.error).toBeNull();
    });

    it('should return loading state from store', () => {
      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        collaborationLoading: { ...mockStore.collaborationLoading, members: true },
      }));

      const { result } = renderHook(() => useTeamMembers('project-1'));

      expect(result.current.loading).toBe(true);
    });

    it('should return error state from store', () => {
      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        collaborationErrors: { ...mockStore.collaborationErrors, members: 'Failed to fetch' },
      }));

      const { result } = renderHook(() => useTeamMembers('project-1'));

      expect(result.current.error).toBe('Failed to fetch');
    });

    it('should call fetchMembers when projectId changes', () => {
      const { rerender } = renderHook(({ projectId }) => useTeamMembers(projectId), {
        initialProps: { projectId: 'project-1' },
      });

      expect(mockStore.fetchMembers).toHaveBeenCalledWith('project-1');

      rerender({ projectId: 'project-2' });

      expect(mockStore.fetchMembers).toHaveBeenCalledWith('project-2');
      expect(mockStore.fetchMembers).toHaveBeenCalledTimes(2);
    });

    it('should call setCurrentProjectId when projectId changes', () => {
      const { rerender } = renderHook(({ projectId }) => useTeamMembers(projectId), {
        initialProps: { projectId: 'project-1' },
      });

      expect(mockStore.setCurrentProjectId).toHaveBeenCalledWith('project-1');

      rerender({ projectId: 'project-2' });

      expect(mockStore.setCurrentProjectId).toHaveBeenCalledWith('project-2');
      expect(mockStore.setCurrentProjectId).toHaveBeenCalledTimes(2);
    });

    it('should not call fetchMembers on initial render if projectId is empty', () => {
      renderHook(() => useTeamMembers(''));

      expect(mockStore.fetchMembers).not.toHaveBeenCalled();
      expect(mockStore.setCurrentProjectId).toHaveBeenCalledWith('');
    });

    it('should not call fetchMembers if projectId has not changed', () => {
      const { rerender } = renderHook(({ projectId }) => useTeamMembers(projectId), {
        initialProps: { projectId: 'project-1' },
      });

      rerender({ projectId: 'project-1' });

      expect(mockStore.fetchMembers).toHaveBeenCalledTimes(1);
    });
  });

  describe('Data Processing', () => {
    it('should filter out members with empty user_id', () => {
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
          user_id: '',
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

      const { result } = renderHook(() => useTeamMembers('project-1'));

      expect(result.current.members).toHaveLength(1);
      expect(result.current.members[0].user_id).toBe('user-1');
    });

    it('should sort members by role priority', () => {
      const mockMembers: ProjectMember[] = [
        {
          id: '1',
          project_id: 'project-1',
          user_id: 'contributor-1',
          role: 'Contributor',
          permissions: ['read', 'write'],
          joined_at: '2023-01-03T00:00:00Z',
          updated_at: '2023-01-03T00:00:00Z',
        },
        {
          id: '2',
          project_id: 'project-1',
          user_id: 'owner-1',
          role: 'Owner',
          permissions: ['all'],
          joined_at: '2023-01-01T00:00:00Z',
          updated_at: '2023-01-01T00:00:00Z',
        },
        {
          id: '3',
          project_id: 'project-1',
          user_id: 'manager-1',
          role: 'Manager',
          permissions: ['read', 'write', 'manage'],
          joined_at: '2023-01-02T00:00:00Z',
          updated_at: '2023-01-02T00:00:00Z',
        },
      ];

      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        members: mockMembers,
      }));

      const { result } = renderHook(() => useTeamMembers('project-1'));

      expect(result.current.members[0].role).toBe('Owner');
      expect(result.current.members[1].role).toBe('Manager');
      expect(result.current.members[2].role).toBe('Contributor');
    });

    it('should calculate user management permissions', () => {
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

      const { result } = renderHook(() => useTeamMembers('project-1'));

      expect(result.current.canManageTeam).toBe(true);
    });

    it('should return false for user management when user is contributor', () => {
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

      const { result } = renderHook(() => useTeamMembers('project-1'));

      expect(result.current.canManageTeam).toBe(false);
    });

    it('should return false for user management when user is not found', () => {
      const mockMembers: ProjectMember[] = [
        {
          id: '1',
          project_id: 'project-1',
          user_id: 'other-user',
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

      const { result } = renderHook(() => useTeamMembers('project-1'));

      expect(result.current.canManageTeam).toBe(false);
    });
  });

  describe('Error Handling', () => {
    it('should handle undefined members gracefully', () => {
      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        members: undefined as any,
      }));

      const { result } = renderHook(() => useTeamMembers('project-1'));

      expect(result.current.members).toEqual([]);
      expect(result.current.loading).toBe(false);
      expect(result.current.error).toBeNull();
    });

    it('should handle null members gracefully', () => {
      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        members: null as any,
      }));

      const { result } = renderHook(() => useTeamMembers('project-1'));

      expect(result.current.members).toEqual([]);
    });

    it('should handle malformed member data gracefully', () => {
      const malformedMembers = [
        {
          id: '1',
          project_id: 'project-1',
          user_id: '',
          role: '',
          permissions: [],
          joined_at: '',
          updated_at: '',
        },
        null,
        undefined,
      ] as any;

      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        members: malformedMembers,
      }));

      const { result } = renderHook(() => useTeamMembers('project-1'));

      expect(result.current.members).toEqual([]);
    });
  });

  describe('Performance', () => {
    it('should not cause unnecessary re-renders', () => {
      const { result, rerender } = renderHook(() => useTeamMembers('project-1'));

      const initialMembers = result.current.members;
      const initialLoading = result.current.loading;
      const initialError = result.current.error;

      rerender();

      expect(result.current.members).toBe(initialMembers);
      expect(result.current.loading).toBe(initialLoading);
      expect(result.current.error).toBe(initialError);
    });

    it('should handle large member lists efficiently', () => {
      const largeMemberList: ProjectMember[] = Array.from({ length: 1000 }, (_, i) => ({
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
      const { result } = renderHook(() => useTeamMembers('project-1'));
      const endTime = performance.now();

      expect(result.current.members).toHaveLength(1000);
      expect(endTime - startTime).toBeLessThan(50); // Should process quickly
    });
  });

  describe('Side Effects', () => {
    it('should clear errors when fetching new data', () => {
      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        collaborationErrors: { ...mockStore.collaborationErrors, members: 'Previous error' },
      }));

      const { rerender } = renderHook(({ projectId }) => useTeamMembers(projectId), {
        initialProps: { projectId: 'project-1' },
      });

      // Clear errors should be called when projectId changes
      rerender({ projectId: 'project-2' });

      expect(mockStore.fetchMembers).toHaveBeenCalledTimes(2);
    });

    it('should handle fetch errors gracefully', () => {
      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        collaborationErrors: { ...mockStore.collaborationErrors, members: 'Network error' },
        collaborationLoading: { ...mockStore.collaborationLoading, members: false },
      }));

      const { result } = renderHook(() => useTeamMembers('project-1'));

      expect(result.current.error).toBe('Network error');
      expect(result.current.loading).toBe(false);
    });

    it('should reset state when projectId becomes empty', () => {
      const { rerender } = renderHook(({ projectId }) => useTeamMembers(projectId), {
        initialProps: { projectId: 'project-1' },
      });

      rerender({ projectId: '' });

      expect(mockStore.setCurrentProjectId).toHaveBeenCalledWith('');
    });
  });

  describe('Integration with Store', () => {
    it('should update when store members change', () => {
      const { result, rerender } = renderHook(() => useTeamMembers('project-1'));

      const initialMembers = result.current.members;

      // Simulate store update
      const newMembers: ProjectMember[] = [
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
        members: newMembers,
      }));

      rerender();

      expect(result.current.members).toEqual(newMembers);
      expect(result.current.members).not.toBe(initialMembers);
    });

    it('should update when store loading state changes', () => {
      const { result, rerender } = renderHook(() => useTeamMembers('project-1'));

      expect(result.current.loading).toBe(false);

      // Simulate loading state change
      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        collaborationLoading: { ...mockStore.collaborationLoading, members: true },
      }));

      rerender();

      expect(result.current.loading).toBe(true);
    });

    it('should update when store error state changes', () => {
      const { result, rerender } = renderHook(() => useTeamMembers('project-1'));

      expect(result.current.error).toBeNull();

      // Simulate error state change
      mockUseStore.mockImplementation((selector) => selector({
        ...mockStore,
        collaborationErrors: { ...mockStore.collaborationErrors, members: 'New error' },
      }));

      rerender();

      expect(result.current.error).toBe('New error');
    });
  });
});
