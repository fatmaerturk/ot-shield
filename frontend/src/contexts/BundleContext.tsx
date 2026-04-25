import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react';
import {
  ResearchBundle,
  listBundles,
  createBundle as apiCreateBundle,
  updateBundle as apiUpdateBundle,
  deleteBundle as apiDeleteBundle,
  BundleCreateRequest,
  BundleUpdateRequest,
} from '../services/bundleService';
import { ACTIVE_BUNDLE_STORAGE_KEY } from '../services/api';

/**
 * Context for the currently-selected Research bundle.
 *
 * <p>State kept in localStorage so the selection persists across tabs
 * and reloads. The axios request interceptor reads the same key to
 * inject the {@code X-Bundle-Id} header on every Research endpoint.
 */

interface BundleContextValue {
  bundles: ResearchBundle[];
  activeBundleId: string | null;
  activeBundle: ResearchBundle | null;
  loading: boolean;
  error: string | null;
  refresh: () => Promise<void>;
  selectBundle: (id: string | null) => void;
  createBundle: (req: BundleCreateRequest) => Promise<ResearchBundle>;
  updateBundle: (id: string, req: BundleUpdateRequest) => Promise<ResearchBundle>;
  deleteBundle: (id: string) => Promise<void>;
}

const BundleContext = createContext<BundleContextValue | null>(null);

export const BundleProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [bundles, setBundles] = useState<ResearchBundle[]>([]);
  const [activeBundleId, setActiveBundleId] = useState<string | null>(
    () => localStorage.getItem(ACTIVE_BUNDLE_STORAGE_KEY)
  );
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const rows = await listBundles();
      setBundles(rows);
      setError(null);
      // If the stored active id no longer exists (deleted from another
      // tab, for example), fall back to the first bundle so the UI
      // always has something to render.
      if (rows.length > 0) {
        const stillThere = rows.some(b => b.id === activeBundleId);
        if (!stillThere) {
          const first = rows[0].id;
          setActiveBundleId(first);
          localStorage.setItem(ACTIVE_BUNDLE_STORAGE_KEY, first);
        }
      } else {
        setActiveBundleId(null);
        localStorage.removeItem(ACTIVE_BUNDLE_STORAGE_KEY);
      }
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load bundles');
    } finally {
      setLoading(false);
    }
  }, [activeBundleId]);

  // Initial load
  useEffect(() => { void refresh(); /* eslint-disable-next-line */ }, []);

  const selectBundle = useCallback((id: string | null) => {
    setActiveBundleId(id);
    if (id) localStorage.setItem(ACTIVE_BUNDLE_STORAGE_KEY, id);
    else localStorage.removeItem(ACTIVE_BUNDLE_STORAGE_KEY);
  }, []);

  const createBundle = useCallback(async (req: BundleCreateRequest) => {
    const b = await apiCreateBundle(req);
    await refresh();
    selectBundle(b.id); // new bundles become active immediately
    return b;
  }, [refresh, selectBundle]);

  const updateBundle = useCallback(async (id: string, req: BundleUpdateRequest) => {
    const b = await apiUpdateBundle(id, req);
    await refresh();
    return b;
  }, [refresh]);

  const deleteBundle = useCallback(async (id: string) => {
    await apiDeleteBundle(id);
    // If we just deleted the active one, the next refresh will auto-pick
    // the first remaining bundle.
    await refresh();
  }, [refresh]);

  const activeBundle = useMemo(
    () => bundles.find(b => b.id === activeBundleId) ?? null,
    [bundles, activeBundleId]
  );

  const value: BundleContextValue = {
    bundles,
    activeBundleId,
    activeBundle,
    loading,
    error,
    refresh,
    selectBundle,
    createBundle,
    updateBundle,
    deleteBundle,
  };

  return (
    <BundleContext.Provider value={value}>
      {children}
    </BundleContext.Provider>
  );
};

/**
 * Hook for consuming the bundle context. Throws a helpful error if
 * called outside the provider so the bug surfaces immediately instead
 * of silently rendering a broken state.
 */
export function useBundles(): BundleContextValue {
  const ctx = useContext(BundleContext);
  if (!ctx) {
    throw new Error('useBundles must be used inside <BundleProvider>');
  }
  return ctx;
}
