import { create } from 'zustand';

export interface VaultItem {
  id: string;
  type: string;
  title: string;
  username?: string;
  password?: string;
  urls: string[];
  notes?: string;
  favorite: boolean;
  folder?: string;
  created_at: string;
  updated_at: string;
}

export type SyncState = 'idle' | 'syncing' | 'saved' | 'error';

interface VaultState {
  isLocked: boolean;
  items: VaultItem[];
  folders: string[];
  searchQuery: string;
  selectedItem: VaultItem | null;
  lockTimeout: number;
  lastActivity: number;

  /** AES-GCM vault key derived from the master password (kept only in memory). */
  key: CryptoKey | null;
  /** Version of the newest snapshot this client knows about (0 = never synced). */
  serverVersion: number;
  syncState: SyncState;
  syncError: string | null;
  /** Bumped by retrySync() so the sync watcher re-runs after a failure. */
  syncRetry: number;

  unlock: (items: VaultItem[], folders: string[], key: CryptoKey, serverVersion: number) => void;
  /** Swap the in-memory data key without touching contents — used when a
   * legacy vault is upgraded to a random VEK during a master-password change. */
  rekey: (key: CryptoKey) => void;
  lock: () => void;
  addItem: (item: VaultItem) => void;
  updateItem: (id: string, updates: Partial<VaultItem>) => void;
  removeItem: (id: string) => void;
  setSearchQuery: (query: string) => void;
  setSelectedItem: (item: VaultItem | null) => void;
  setLockTimeout: (minutes: number) => void;
  updateActivity: () => void;
  getFilteredItems: () => VaultItem[];
  setSyncState: (state: SyncState, error?: string | null) => void;
  retrySync: () => void;
  /** Replace local contents from a fresh server snapshot (conflict resolution). */
  applyServerContents: (items: VaultItem[], folders: string[], serverVersion: number) => void;
}

export const useVaultStore = create<VaultState>((set, get) => ({
  isLocked: true,
  items: [],
  folders: [],
  searchQuery: '',
  selectedItem: null,
  lockTimeout: 15,
  lastActivity: Date.now(),
  key: null,
  serverVersion: 0,
  syncState: 'idle',
  syncError: null,
  syncRetry: 0,

  unlock: (items, folders, key, serverVersion) =>
    set({ isLocked: false, items, folders, key, serverVersion, syncState: 'idle', syncError: null }),

  rekey: (key) => set({ key }),

  lock: () =>
    set({
      isLocked: true,
      items: [],
      folders: [],
      selectedItem: null,
      key: null,
      serverVersion: 0,
      syncState: 'idle',
      syncError: null,
    }),

  addItem: (item) => set((state) => ({ items: [...state.items, item] })),

  updateItem: (id, updates) =>
    set((state) => ({
      items: state.items.map((item) =>
        item.id === id ? { ...item, ...updates, updated_at: new Date().toISOString() } : item
      ),
    })),

  removeItem: (id) =>
    set((state) => ({
      items: state.items.filter((item) => item.id !== id),
    })),

  setSearchQuery: (query) => set({ searchQuery: query }),
  setSelectedItem: (item) => set({ selectedItem: item }),
  setLockTimeout: (minutes) => set({ lockTimeout: minutes }),
  updateActivity: () => set({ lastActivity: Date.now() }),

  getFilteredItems: () => {
    const { items, searchQuery } = get();
    if (!searchQuery) return items;
    const q = searchQuery.toLowerCase();
    return items.filter(
      (item) =>
        item.title.toLowerCase().includes(q) ||
        item.username?.toLowerCase().includes(q) ||
        item.urls.some((url) => url.toLowerCase().includes(q)) ||
        item.folder?.toLowerCase().includes(q)
    );
  },

  setSyncState: (syncState, syncError = null) => set({ syncState, syncError }),

  retrySync: () =>
    set((state) => ({ syncRetry: state.syncRetry + 1, syncState: 'idle', syncError: null })),

  applyServerContents: (items, folders, serverVersion) =>
    set({ items, folders, serverVersion, syncState: 'saved', syncError: null }),
}));
