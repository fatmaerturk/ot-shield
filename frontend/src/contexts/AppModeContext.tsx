import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';

/**
 * App-wide "mode" switch introduced in Option C #4 — the HMGCC brief
 * asks for a tear-down assistant rather than a SOC platform, so the
 * default experience has to be the Research Studio, not the alerts /
 * decoy dashboards. Users who want the full OTShield product can flip
 * a toggle in the top bar and get everything back.
 *
 * <p>Mode persists in {@code localStorage} so refreshes don't kick
 * the researcher back into SOC mode. First-time visitors land on
 * {@code RESEARCH} because that's the capability we want HMGCC
 * reviewers to see in the first 30 seconds.
 */

export type AppMode = 'RESEARCH' | 'SOC';

const STORAGE_KEY = 'otshield.appMode';
const DEFAULT_MODE: AppMode = 'RESEARCH';

interface AppModeContextValue {
  mode: AppMode;
  setMode: (next: AppMode) => void;
  toggle: () => void;
}

const AppModeContext = createContext<AppModeContextValue | undefined>(undefined);

function readInitialMode(): AppMode {
  if (typeof window === 'undefined') return DEFAULT_MODE;
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (raw === 'RESEARCH' || raw === 'SOC') return raw;
  } catch {
    // localStorage disabled / private mode - fall through to default.
  }
  return DEFAULT_MODE;
}

export const AppModeProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [mode, setModeState] = useState<AppMode>(() => readInitialMode());

  const setMode = useCallback((next: AppMode) => {
    setModeState(next);
    try {
      window.localStorage.setItem(STORAGE_KEY, next);
    } catch {
      // Non-fatal; the runtime state still reflects the choice.
    }
  }, []);

  const toggle = useCallback(() => {
    setMode(mode === 'RESEARCH' ? 'SOC' : 'RESEARCH');
  }, [mode, setMode]);

  // React to external writes (e.g. the user opens a second tab and
  // flips the mode there). This keeps the sidebar filter consistent
  // across tabs without a refresh.
  useEffect(() => {
    const handler = (e: StorageEvent) => {
      if (e.key !== STORAGE_KEY) return;
      if (e.newValue === 'RESEARCH' || e.newValue === 'SOC') {
        setModeState(e.newValue);
      }
    };
    window.addEventListener('storage', handler);
    return () => window.removeEventListener('storage', handler);
  }, []);

  const value = useMemo<AppModeContextValue>(
    () => ({ mode, setMode, toggle }),
    [mode, setMode, toggle]
  );

  return <AppModeContext.Provider value={value}>{children}</AppModeContext.Provider>;
};

/**
 * Access the current mode + setters. Returns a default fallback when
 * called outside the provider rather than throwing - that way a stale
 * webpack hot-reload chunk or a one-off test harness won't crash the
 * whole app; you just get the default (RESEARCH) and no-op setters.
 * The provider-wrapped call path is unchanged.
 */
export function useAppMode(): AppModeContextValue {
  const ctx = useContext(AppModeContext);
  if (ctx) return ctx;
  return {
    mode: DEFAULT_MODE,
    setMode: () => { /* no-op fallback */ },
    toggle: () => { /* no-op fallback */ },
  };
}
