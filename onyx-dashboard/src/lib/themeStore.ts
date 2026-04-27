'use client';
import { create } from 'zustand';
import { persist } from 'zustand/middleware';

type Theme = 'dark' | 'light';

interface ThemeState {
  theme: Theme;
  toggleTheme: () => void;
  setTheme: (t: Theme) => void;
}

export const useThemeStore = create<ThemeState>()(
  persist(
    (set, get) => ({
      theme: 'dark',
      toggleTheme: () => {
        const next = get().theme === 'dark' ? 'light' : 'dark';
        set({ theme: next });
        if (typeof document !== 'undefined') {
          document.documentElement.setAttribute('data-theme', next);
        }
      },
      setTheme: (t) => {
        set({ theme: t });
        if (typeof document !== 'undefined') {
          document.documentElement.setAttribute('data-theme', t);
        }
      },
    }),
    { name: 'onyx-theme' }
  )
);

/** Call once on client mount to sync DOM with persisted state */
export function applyPersistedTheme() {
  if (typeof window === 'undefined') return;
  try {
    const raw = localStorage.getItem('onyx-theme');
    if (raw) {
      const parsed = JSON.parse(raw);
      const theme: Theme = parsed?.state?.theme ?? 'dark';
      document.documentElement.setAttribute('data-theme', theme);
    }
  } catch (_) {}
}
