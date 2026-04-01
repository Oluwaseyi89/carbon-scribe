import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { CollaborationSlice } from './collaboration.types';
import { createCollaborationSlice } from './collaborationSlice';
import * as api from './collaboration.api';

// Mock the API module
vi.mock('./collaboration.api', () => ({
  fetchMembersApi: vi.fn(),
  fetchInvitationsApi: vi.fn(),
  fetchActivitiesApi: vi.fn(),
  fetchCommentsApi: vi.fn(),
  fetchTasksApi: vi.fn(),
  fetchResourcesApi: vi.fn(),
  inviteUserApi: vi.fn(),
  removeMemberApi: vi.fn(),
  createCommentApi: vi.fn(),
  createTaskApi: vi.fn(),
  updateTaskApi: vi.fn(),
  createResourceApi: vi.fn(),
}));

const mockApi = vi.mocked(api);

describe('CollaborationSlice', () => {
  let slice: CollaborationSlice;
  let mockSet: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.clearAllMocks();
    mockSet = vi.fn();
    slice = createCollaborationSlice(mockSet, () => slice);
  });

  describe('Initial State', () => {
    it('should have correct initial state', () => {
      expect(slice.currentProjectId).toBeNull();
      expect(slice.members).toEqual([]);
      expect(slice.invitations).toEqual([]);
      expect(slice.activities).toEqual([]);
      expect(slice.activitiesPagination).toEqual({ limit: 20, offset: 0, total: 0 });
      expect(slice.activityTypeFilter).toBe('All');
      expect(slice.comments).toEqual([]);
      expect(slice.tasks).toEqual([]);
      expect(slice.resources).toEqual([]);
      expect(slice.collaborationLoading).toEqual({
        members: false,
        invitations: false,
        activities: false,
        comments: false,
        tasks: false,
        resources: false,
        invite: false,
        removeMember: false,
        createComment: false,
        createTask: false,
        updateTask: false,
        createResource: false,
      });
      expect(slice.collaborationErrors).toEqual({
        members: null,
        invitations: null,
        activities: null,
        comments: null,
        tasks: null,
        resources: null,
        invite: null,
        removeMember: null,
        createComment: null,
        createTask: null,
        updateTask: null,
        createResource: null,
      });
    });
  });

  describe('fetchMembers', () => {
    it('should fetch members successfully', async () => {
      const mockMembers = [
        { id: '1', project_id: 'p1', user_id: 'user1', role: 'Owner', permissions: ['all'], joined_at: '2023-01-01T00:00:00Z', updated_at: '2023-01-01T00:00:00Z' },
        { id: '2', project_id: 'p1', user_id: 'user2', role: 'Contributor', permissions: ['read', 'write'], joined_at: '2023-01-02T00:00:00Z', updated_at: '2023-01-02T00:00:00Z' },
      ];
      mockApi.fetchMembersApi.mockResolvedValue(mockMembers);

      await slice.fetchMembers('p1');

      expect(mockApi.fetchMembersApi).toHaveBeenCalledWith('p1');
      expect(mockSet).toHaveBeenCalledWith(
        expect.objectContaining({
          collaborationLoading: expect.objectContaining({ members: true }),
          collaborationErrors: expect.objectContaining({ members: null }),
        })
      );
      expect(mockSet).toHaveBeenCalledWith(
        expect.objectContaining({
          members: mockMembers,
          collaborationLoading: expect.objectContaining({ members: false }),
        })
      );
    });

    it('should handle fetch members error', async () => {
      const error = new Error('Failed to fetch members');
      mockApi.fetchMembersApi.mockRejectedValue(error);

      await slice.fetchMembers('p1');

      expect(mockApi.fetchMembersApi).toHaveBeenCalledWith('p1');
      expect(mockSet).toHaveBeenCalledWith(
        expect.objectContaining({
          collaborationLoading: expect.objectContaining({ members: true }),
          collaborationErrors: expect.objectContaining({ members: null }),
        })
      );
      expect(mockSet).toHaveBeenCalledWith(
        expect.objectContaining({
          collaborationLoading: expect.objectContaining({ members: false }),
          collaborationErrors: expect.objectContaining({ members: error.message }),
        })
      );
    });
  });

  describe('fetchInvitations', () => {
    it('should fetch invitations successfully', async () => {
      const mockInvitations = [
        { id: '1', project_id: 'p1', email: 'test@example.com', role: 'Contributor', status: 'pending', expires_at: '2023-01-01T00:00:00Z', created_at: '2023-01-01T00:00:00Z', updated_at: '2023-01-01T00:00:00Z' },
      ];
      mockApi.fetchInvitationsApi.mockResolvedValue(mockInvitations);

      await slice.fetchInvitations('p1');

      expect(mockApi.fetchInvitationsApi).toHaveBeenCalledWith('p1');
      expect(mockSet).toHaveBeenCalledWith(
        expect.objectContaining({
          collaborationLoading: expect.objectContaining({ invitations: true }),
          collaborationErrors: expect.objectContaining({ invitations: null }),
        })
      );
      expect(mockSet).toHaveBeenCalledWith(
        expect.objectContaining({
          invitations: mockInvitations,
          collaborationLoading: expect.objectContaining({ invitations: false }),
        })
      );
    });

    it('should handle fetch invitations error', async () => {
      const error = new Error('Failed to fetch invitations');
      mockApi.fetchInvitationsApi.mockRejectedValue(error);

      await slice.fetchInvitations('p1');

      expect(mockSet).toHaveBeenCalledWith(
        expect.objectContaining({
          collaborationLoading: expect.objectContaining({ invitations: false }),
          collaborationErrors: expect.objectContaining({ invitations: error.message }),
        })
      );
    });
  });

  describe('fetchActivities', () => {
    it('should fetch activities with default pagination', async () => {
      const mockActivities = [
        { id: '1', project_id: 'p1', user_id: 'user1', type: 'user', action: 'user_invited', metadata: {}, created_at: '2023-01-01T00:00:00Z' },
      ];
      mockApi.fetchActivitiesApi.mockResolvedValue(mockActivities);

      await slice.fetchActivities('p1');

      expect(mockApi.fetchActivitiesApi).toHaveBeenCalledWith('p1', 20, 0);
      expect(mockSet).toHaveBeenCalledWith(
        expect.objectContaining({
          collaborationLoading: expect.objectContaining({ activities: true }),
          collaborationErrors: expect.objectContaining({ activities: null }),
        })
      );
      expect(mockSet).toHaveBeenCalledWith(
        expect.objectContaining({
          activities: mockActivities,
          collaborationLoading: expect.objectContaining({ activities: false }),
        })
      );
    });

    it('should fetch activities with custom pagination', async () => {
      const mockActivities = [];
      mockApi.fetchActivitiesApi.mockResolvedValue(mockActivities);

      await slice.fetchActivities('p1', 10, 5);

      expect(mockApi.fetchActivitiesApi).toHaveBeenCalledWith('p1', 10, 5);
    });

    it('should handle fetch activities error', async () => {
      const error = new Error('Failed to fetch activities');
      mockApi.fetchActivitiesApi.mockRejectedValue(error);

      await slice.fetchActivities('p1');

      expect(mockSet).toHaveBeenCalledWith(
        expect.objectContaining({
          collaborationLoading: expect.objectContaining({ activities: false }),
          collaborationErrors: expect.objectContaining({ activities: error.message }),
        })
      );
    });
  });

  describe('inviteUser', () => {
    it('should invite user successfully', async () => {
      const mockInvitation = { id: '1', project_id: 'p1', email: 'test@example.com', role: 'Contributor', status: 'pending', expires_at: '2023-01-01T00:00:00Z', created_at: '2023-01-01T00:00:00Z', updated_at: '2023-01-01T00:00:00Z' };
      mockApi.inviteUserApi.mockResolvedValue(mockInvitation);

      const result = await slice.inviteUser('p1', { email: 'test@example.com', role: 'Contributor' });

      expect(mockApi.inviteUserApi).toHaveBeenCalledWith('p1', { email: 'test@example.com', role: 'Contributor' });
      expect(mockSet).toHaveBeenCalledWith(
        expect.objectContaining({
          collaborationLoading: expect.objectContaining({ invite: true }),
          collaborationErrors: expect.objectContaining({ invite: null }),
        })
      );
      expect(mockSet).toHaveBeenCalledWith(
        expect.objectContaining({
          collaborationLoading: expect.objectContaining({ invite: false }),
        })
      );
      expect(result).toEqual(mockInvitation);
    });

    it('should handle invite user error', async () => {
      const error = new Error('Failed to invite user');
      mockApi.inviteUserApi.mockRejectedValue(error);

      const result = await slice.inviteUser('p1', { email: 'test@example.com', role: 'Contributor' });

      expect(mockSet).toHaveBeenCalledWith(
        expect.objectContaining({
          collaborationLoading: expect.objectContaining({ invite: false }),
          collaborationErrors: expect.objectContaining({ invite: error.message }),
        })
      );
      expect(result).toBeNull();
    });
  });

  describe('removeMember', () => {
    it('should remove member successfully', async () => {
      mockApi.removeMemberApi.mockResolvedValue(true);

      const result = await slice.removeMember('p1', 'user123');

      expect(mockApi.removeMemberApi).toHaveBeenCalledWith('p1', 'user123');
      expect(mockSet).toHaveBeenCalledWith(
        expect.objectContaining({
          collaborationLoading: expect.objectContaining({ removeMember: true }),
          collaborationErrors: expect.objectContaining({ removeMember: null }),
        })
      );
      expect(mockSet).toHaveBeenCalledWith(
        expect.objectContaining({
          collaborationLoading: expect.objectContaining({ removeMember: false }),
        })
      );
      expect(result).toBe(true);
    });

    it('should handle remove member error', async () => {
      const error = new Error('Failed to remove member');
      mockApi.removeMemberApi.mockRejectedValue(error);

      const result = await slice.removeMember('p1', 'user123');

      expect(mockSet).toHaveBeenCalledWith(
        expect.objectContaining({
          collaborationLoading: expect.objectContaining({ removeMember: false }),
          collaborationErrors: expect.objectContaining({ removeMember: error.message }),
        })
      );
      expect(result).toBe(false);
    });
  });

  describe('createComment', () => {
    it('should create comment successfully', async () => {
      const mockComment = { id: '1', project_id: 'p1', user_id: 'user1', content: 'Test comment', created_at: '2023-01-01T00:00:00Z', updated_at: '2023-01-01T00:00:00Z' };
      mockApi.createCommentApi.mockResolvedValue(mockComment);

      const result = await slice.createComment({ project_id: 'p1', user_id: 'user1', content: 'Test comment' });

      expect(mockApi.createCommentApi).toHaveBeenCalledWith({ project_id: 'p1', user_id: 'user1', content: 'Test comment' });
      expect(mockSet).toHaveBeenCalledWith(
        expect.objectContaining({
          collaborationLoading: expect.objectContaining({ createComment: true }),
          collaborationErrors: expect.objectContaining({ createComment: null }),
        })
      );
      expect(mockSet).toHaveBeenCalledWith(
        expect.objectContaining({
          collaborationLoading: expect.objectContaining({ createComment: false }),
        })
      );
      expect(result).toEqual(mockComment);
    });

    it('should handle create comment error', async () => {
      const error = new Error('Failed to create comment');
      mockApi.createCommentApi.mockRejectedValue(error);

      const result = await slice.createComment({ project_id: 'p1', user_id: 'user1', content: 'Test comment' });

      expect(mockSet).toHaveBeenCalledWith(
        expect.objectContaining({
          collaborationLoading: expect.objectContaining({ createComment: false }),
          collaborationErrors: expect.objectContaining({ createComment: error.message }),
        })
      );
      expect(result).toBeNull();
    });
  });

  describe('createTask', () => {
    it('should create task successfully', async () => {
      const mockTask = { id: '1', project_id: 'p1', created_by: 'user1', title: 'Test task', status: 'todo', created_at: '2023-01-01T00:00:00Z', updated_at: '2023-01-01T00:00:00Z' };
      mockApi.createTaskApi.mockResolvedValue(mockTask);

      const result = await slice.createTask({ project_id: 'p1', title: 'Test task', created_by: 'user1' });

      expect(mockApi.createTaskApi).toHaveBeenCalledWith({ project_id: 'p1', title: 'Test task', created_by: 'user1' });
      expect(mockSet).toHaveBeenCalledWith(
        expect.objectContaining({
          collaborationLoading: expect.objectContaining({ createTask: true }),
          collaborationErrors: expect.objectContaining({ createTask: null }),
        })
      );
      expect(mockSet).toHaveBeenCalledWith(
        expect.objectContaining({
          collaborationLoading: expect.objectContaining({ createTask: false }),
        })
      );
      expect(result).toEqual(mockTask);
    });

    it('should handle create task error', async () => {
      const error = new Error('Failed to create task');
      mockApi.createTaskApi.mockRejectedValue(error);

      const result = await slice.createTask({ project_id: 'p1', title: 'Test task', created_by: 'user1' });

      expect(mockSet).toHaveBeenCalledWith(
        expect.objectContaining({
          collaborationLoading: expect.objectContaining({ createTask: false }),
          collaborationErrors: expect.objectContaining({ createTask: error.message }),
        })
      );
      expect(result).toBeNull();
    });
  });

  describe('updateTask', () => {
    it('should update task successfully', async () => {
      const mockTask = { id: '1', project_id: 'p1', title: 'Updated task', status: 'done', updated_at: '2023-01-01T00:00:00Z' };
      mockApi.updateTaskApi.mockResolvedValue(mockTask);

      const result = await slice.updateTask('1', { status: 'done' });

      expect(mockApi.updateTaskApi).toHaveBeenCalledWith('1', { status: 'done' });
      expect(mockSet).toHaveBeenCalledWith(
        expect.objectContaining({
          collaborationLoading: expect.objectContaining({ updateTask: true }),
          collaborationErrors: expect.objectContaining({ updateTask: null }),
        })
      );
      expect(mockSet).toHaveBeenCalledWith(
        expect.objectContaining({
          collaborationLoading: expect.objectContaining({ updateTask: false }),
        })
      );
      expect(result).toEqual(mockTask);
    });

    it('should handle update task error', async () => {
      const error = new Error('Failed to update task');
      mockApi.updateTaskApi.mockRejectedValue(error);

      const result = await slice.updateTask('1', { status: 'done' });

      expect(mockSet).toHaveBeenCalledWith(
        expect.objectContaining({
          collaborationLoading: expect.objectContaining({ updateTask: false }),
          collaborationErrors: expect.objectContaining({ updateTask: error.message }),
        })
      );
      expect(result).toBeNull();
    });
  });

  describe('createResource', () => {
    it('should create resource successfully', async () => {
      const mockResource = { id: '1', project_id: 'p1', type: 'document', name: 'Test resource', uploaded_by: 'user1', created_at: '2023-01-01T00:00:00Z', updated_at: '2023-01-01T00:00:00Z' };
      mockApi.createResourceApi.mockResolvedValue(mockResource);

      const result = await slice.createResource({ project_id: 'p1', type: 'document', name: 'Test resource', uploaded_by: 'user1' });

      expect(mockApi.createResourceApi).toHaveBeenCalledWith({ project_id: 'p1', type: 'document', name: 'Test resource', uploaded_by: 'user1' });
      expect(mockSet).toHaveBeenCalledWith(
        expect.objectContaining({
          collaborationLoading: expect.objectContaining({ createResource: true }),
          collaborationErrors: expect.objectContaining({ createResource: null }),
        })
      );
      expect(mockSet).toHaveBeenCalledWith(
        expect.objectContaining({
          collaborationLoading: expect.objectContaining({ createResource: false }),
        })
      );
      expect(result).toEqual(mockResource);
    });

    it('should handle create resource error', async () => {
      const error = new Error('Failed to create resource');
      mockApi.createResourceApi.mockRejectedValue(error);

      const result = await slice.createResource({ project_id: 'p1', type: 'document', name: 'Test resource', uploaded_by: 'user1' });

      expect(mockSet).toHaveBeenCalledWith(
        expect.objectContaining({
          collaborationLoading: expect.objectContaining({ createResource: false }),
          collaborationErrors: expect.objectContaining({ createResource: error.message }),
        })
      );
      expect(result).toBeNull();
    });
  });

  describe('UI State Management', () => {
    it('should set current project ID', () => {
      slice.setCurrentProjectId('p1');
      expect(mockSet).toHaveBeenCalledWith(
        expect.objectContaining({
          currentProjectId: 'p1',
        })
      );
    });

    it('should set activity type filter', () => {
      slice.setActivityTypeFilter('user');
      expect(mockSet).toHaveBeenCalledWith(
        expect.objectContaining({
          activityTypeFilter: 'user',
        })
      );
    });

    it('should clear collaboration errors', () => {
      // Set some errors first
      slice.collaborationErrors.members = 'Error';
      slice.collaborationErrors.invitations = 'Error';

      slice.clearCollaborationErrors();

      expect(mockSet).toHaveBeenCalledWith(
        expect.objectContaining({
          collaborationErrors: {
            members: null,
            invitations: null,
            activities: null,
            comments: null,
            tasks: null,
            resources: null,
            invite: null,
            removeMember: null,
            createComment: null,
            createTask: null,
            updateTask: null,
            createResource: null,
          },
        })
      );
    });

    it('should reset collaboration state', () => {
      // Set some state first
      slice.currentProjectId = 'p1';
      slice.members = [{ id: '1', user_id: 'user1', role: 'Owner' } as any];
      slice.collaborationErrors.members = 'Error';

      slice.resetCollaborationState();

      expect(mockSet).toHaveBeenCalledWith(
        expect.objectContaining({
          currentProjectId: null,
          members: [],
          invitations: [],
          activities: [],
          activitiesPagination: { limit: 20, offset: 0, total: 0 },
          activityTypeFilter: 'All',
          comments: [],
          tasks: [],
          resources: [],
          collaborationLoading: {
            members: false,
            invitations: false,
            activities: false,
            comments: false,
            tasks: false,
            resources: false,
            invite: false,
            removeMember: false,
            createComment: false,
            createTask: false,
            updateTask: false,
            createResource: false,
          },
          collaborationErrors: {
            members: null,
            invitations: null,
            activities: null,
            comments: null,
            tasks: null,
            resources: null,
            invite: null,
            removeMember: null,
            createComment: null,
            createTask: null,
            updateTask: null,
            createResource: null,
          },
        })
      );
    });
  });

  describe('Loading State Management', () => {
    it('should manage loading states correctly during operations', async () => {
      const mockMembers = [{ id: '1', user_id: 'user1', role: 'Owner' } as any];
      mockApi.fetchMembersApi.mockImplementation(() => new Promise(resolve => {
        // Check that loading is set to true
        expect(mockSet).toHaveBeenCalledWith(
          expect.objectContaining({
            collaborationLoading: expect.objectContaining({ members: true }),
          })
        );
        resolve(mockMembers);
      }));

      await slice.fetchMembers('p1');

      // Check that loading is set back to false
      expect(mockSet).toHaveBeenCalledWith(
        expect.objectContaining({
          collaborationLoading: expect.objectContaining({ members: false }),
        })
      );
    });
  });

  describe('Error State Management', () => {
    it('should clear specific error when operation succeeds', async () => {
      // Set initial error
      slice.collaborationErrors.members = 'Previous error';

      const mockMembers = [{ id: '1', user_id: 'user1', role: 'Owner' } as any];
      mockApi.fetchMembersApi.mockResolvedValue(mockMembers);

      await slice.fetchMembers('p1');

      // Error should be cleared when operation starts
      expect(mockSet).toHaveBeenCalledWith(
        expect.objectContaining({
          collaborationErrors: expect.objectContaining({ members: null }),
        })
      );
    });

    it('should set error when operation fails', async () => {
      const error = new Error('Network error');
      mockApi.fetchMembersApi.mockRejectedValue(error);

      await slice.fetchMembers('p1');

      expect(mockSet).toHaveBeenCalledWith(
        expect.objectContaining({
          collaborationErrors: expect.objectContaining({ members: 'Network error' }),
        })
      );
    });
  });
});
