import { StateCreator } from 'zustand';
import type { GeospatialSlice, ProjectGeometry, Geofence, MapTile, Geometry } from './geospatial.types';
import {
  fetchProjectGeometryApi,
  fetchAllProjectGeometriesApi,
  updateProjectGeometryApi,
  fetchGeofencesApi,
  createGeofenceApi,
  updateGeofenceApi,
  deleteGeofenceApi,
  fetchMapTilesApi,
} from './geospatial.api';
import { getErrorMessage } from '@/lib/utils/errorMessage';
import { showSuccessToast, showErrorToast } from '@/lib/utils/toast';

const initialState: Pick<
  GeospatialSlice,
  'projectGeometries' | 'geofences' | 'mapTiles' | 'selectedGeometry' | 'selectedGeofence' | 'loading' | 'errors'
> = {
  projectGeometries: [],
  geofences: [],
  mapTiles: [],
  selectedGeometry: null,
  selectedGeofence: null,
  loading: {
    isFetchingGeometry: false,
    isFetchingGeofences: false,
    isFetchingTiles: false,
    isUpdating: false,
  },
  errors: {
    fetchGeometry: null,
    fetchGeofences: null,
    fetchTiles: null,
    update: null,
  },
};

export const createGeospatialSlice: StateCreator<GeospatialSlice> = (set, get) => ({
  ...initialState,

  fetchProjectGeometry: async (projectId: string) => {
    set((state) => ({
      loading: { ...state.loading, isFetchingGeometry: true },
      errors: { ...state.errors, fetchGeometry: null },
    }));

    try {
      const geometry = await fetchProjectGeometryApi(projectId);
      set((state) => ({
        projectGeometries: state.projectGeometries
          .filter((g) => g.projectId !== projectId)
          .concat([geometry]),
        loading: { ...get().loading, isFetchingGeometry: false },
      }));
    } catch (error: unknown) {
      set((state) => ({
        loading: { ...state.loading, isFetchingGeometry: false },
        errors: { ...state.errors, fetchGeometry: getErrorMessage(error) },
      }));
    }
  },

  fetchAllProjectGeometries: async () => {
    set((state) => ({
      loading: { ...state.loading, isFetchingGeometry: true },
      errors: { ...state.errors, fetchGeometry: null },
    }));

    try {
      const geometries = await fetchAllProjectGeometriesApi();
      set({
        projectGeometries: geometries,
        loading: { ...get().loading, isFetchingGeometry: false },
      });
    } catch (error: unknown) {
      set((state) => ({
        loading: { ...state.loading, isFetchingGeometry: false },
        errors: { ...state.errors, fetchGeometry: getErrorMessage(error) },
      }));
    }
  },

  updateProjectGeometry: async (projectId: string, geometry: Geometry) => {
    set((state) => ({
      loading: { ...state.loading, isUpdating: true },
      errors: { ...state.errors, update: null },
    }));

    try {
      const updatedGeometry = await updateProjectGeometryApi(projectId, geometry);
      set((state) => ({
        projectGeometries: state.projectGeometries
          .map((g) => (g.projectId === projectId ? updatedGeometry : g)),
        selectedGeometry: state.selectedGeometry?.projectId === projectId ? updatedGeometry : state.selectedGeometry,
        loading: { ...get().loading, isUpdating: false },
      }));
      showSuccessToast('Geometry updated successfully');
      return updatedGeometry;
    } catch (error: unknown) {
      set((state) => ({
        loading: { ...state.loading, isUpdating: false },
        errors: { ...state.errors, update: getErrorMessage(error) },
      }));
      showErrorToast('Failed to update geometry');
      return null;
    }
  },

  fetchGeofences: async (projectId: string) => {
    set((state) => ({
      loading: { ...state.loading, isFetchingGeofences: true },
      errors: { ...state.errors, fetchGeofences: null },
    }));

    try {
      const geofences = await fetchGeofencesApi(projectId);
      set((state) => ({
        geofences: state.geofences
          .filter((g) => g.projectId !== projectId)
          .concat(geofences),
        loading: { ...get().loading, isFetchingGeofences: false },
      }));
    } catch (error: unknown) {
      set((state) => ({
        loading: { ...state.loading, isFetchingGeofences: false },
        errors: { ...state.errors, fetchGeofences: getErrorMessage(error) },
      }));
    }
  },

  createGeofence: async (projectId: string, data: Omit<Geofence, 'id' | 'createdAt' | 'updatedAt'>) => {
    set((state) => ({
      loading: { ...state.loading, isUpdating: true },
      errors: { ...state.errors, update: null },
    }));

    try {
      const newGeofence = await createGeofenceApi(projectId, data);
      set((state) => ({
        geofences: [...state.geofences, newGeofence],
        loading: { ...get().loading, isUpdating: false },
      }));
      showSuccessToast('Geofence created successfully');
      return newGeofence;
    } catch (error: unknown) {
      set((state) => ({
        loading: { ...state.loading, isUpdating: false },
        errors: { ...state.errors, update: getErrorMessage(error) },
      }));
      showErrorToast('Failed to create geofence');
      return null;
    }
  },

  updateGeofence: async (id: string, data: Partial<Omit<Geofence, 'id' | 'createdAt' | 'updatedAt'>>) => {
    set((state) => ({
      loading: { ...state.loading, isUpdating: true },
      errors: { ...state.errors, update: null },
    }));

    try {
      const updatedGeofence = await updateGeofenceApi(id, data);
      set((state) => ({
        geofences: state.geofences.map((g) => (g.id === id ? updatedGeofence : g)),
        selectedGeofence: state.selectedGeofence?.id === id ? updatedGeofence : state.selectedGeofence,
        loading: { ...get().loading, isUpdating: false },
      }));
      showSuccessToast('Geofence updated successfully');
      return updatedGeofence;
    } catch (error: unknown) {
      set((state) => ({
        loading: { ...state.loading, isUpdating: false },
        errors: { ...state.errors, update: getErrorMessage(error) },
      }));
      showErrorToast('Failed to update geofence');
      return null;
    }
  },

  deleteGeofence: async (id: string) => {
    set((state) => ({
      loading: { ...state.loading, isUpdating: true },
      errors: { ...state.errors, update: null },
    }));

    try {
      await deleteGeofenceApi(id);
      set((state) => ({
        geofences: state.geofences.filter((g) => g.id !== id),
        selectedGeofence: state.selectedGeofence?.id === id ? null : state.selectedGeofence,
        loading: { ...get().loading, isUpdating: false },
      }));
      showSuccessToast('Geofence deleted successfully');
      return true;
    } catch (error: unknown) {
      set((state) => ({
        loading: { ...state.loading, isUpdating: false },
        errors: { ...state.errors, update: getErrorMessage(error) },
      }));
      showErrorToast('Failed to delete geofence');
      return false;
    }
  },

  fetchMapTiles: async (projectId: string, type?: string) => {
    set((state) => ({
      loading: { ...state.loading, isFetchingTiles: true },
      errors: { ...state.errors, fetchTiles: null },
    }));

    try {
      const tiles = await fetchMapTilesApi(projectId, type);
      set((state) => ({
        mapTiles: state.mapTiles
          .filter((t) => t.projectId !== projectId || (type && t.type !== type))
          .concat(tiles),
        loading: { ...get().loading, isFetchingTiles: false },
      }));
    } catch (error: unknown) {
      set((state) => ({
        loading: { ...state.loading, isFetchingTiles: false },
        errors: { ...state.errors, fetchTiles: getErrorMessage(error) },
      }));
    }
  },

  setSelectedGeometry: (geometry) => set({ selectedGeometry: geometry }),
  setSelectedGeofence: (geofence) => set({ selectedGeofence: geofence }),

  clearGeospatialErrors: () =>
    set({
      errors: {
        fetchGeometry: null,
        fetchGeofences: null,
        fetchTiles: null,
        update: null,
      },
    }),

  resetGeospatialState: () => set({ ...initialState }),
});
