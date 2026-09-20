'use client';

import { create } from 'zustand';
import { api, type Me } from '@/lib/api';

interface AuthState {
  /** Current signed-in user, or null when signed out / not yet known. */
  user: Me | null;
  /** True while the first identity check is in flight. */
  loading: boolean;
  /** Last non-auth error message (e.g. network failure). */
  error: string | null;
  refresh: () => Promise<void>;
  clear: () => void;
}

export const useAuthStore = create<AuthState>((set, get) => ({
  user: null,
  loading: false,
  error: null,

  refresh: async () => {
    if (get().loading) return;
    set({ loading: true, error: null });
    try {
      const me = await api.auth.me();
      set({ user: me, loading: false });
    } catch (err: unknown) {
      // 401 => simply signed out; any other failure is surfaced.
      const message = err instanceof Error ? err.message : 'Request failed';
      const signedOut = message.includes('401') || message.includes('Authentication failed');
      set({ user: null, loading: false, error: signedOut ? null : message });
    }
  },

  clear: () => set({ user: null, error: null }),
}));
