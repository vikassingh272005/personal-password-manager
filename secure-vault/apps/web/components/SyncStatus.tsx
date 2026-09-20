'use client';

import { useEffect, useRef, useState } from 'react';
import { useVaultStore } from '@/hooks/useVault';
import { AlertTriangle, Check, Loader2, RefreshCw } from 'lucide-react';

/** Shows whether the vault's local changes have been persisted to the server. */
export function SyncStatus() {
  const syncState = useVaultStore((s) => s.syncState);
  const syncError = useVaultStore((s) => s.syncError);
  const retrySync = useVaultStore((s) => s.retrySync);
  const [showSaved, setShowSaved] = useState(false);
  const savedTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (syncState === 'saved') {
      setShowSaved(true);
      if (savedTimer.current) clearTimeout(savedTimer.current);
      savedTimer.current = setTimeout(() => setShowSaved(false), 2500);
    }
  }, [syncState]);

  useEffect(() => () => {
    if (savedTimer.current) clearTimeout(savedTimer.current);
  }, []);

  if (syncState === 'syncing') {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
        <Loader2 className="h-3.5 w-3.5 animate-spin" />
        Saving…
      </span>
    );
  }

  if (syncState === 'error') {
    return (
      <span
        className="inline-flex items-center gap-1.5 text-xs font-medium text-red-400"
        title={syncError ?? undefined}
      >
        <AlertTriangle className="h-3.5 w-3.5" />
        Sync failed
        <button
          onClick={retrySync}
          className="btn-ghost ml-1 !px-2 !py-1 text-xs"
          title="Retry sync"
        >
          <RefreshCw className="h-3 w-3" />
          Retry
        </button>
      </span>
    );
  }

  if (showSaved) {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs font-medium text-emerald-400">
        <Check className="h-3.5 w-3.5" />
        Saved to server
      </span>
    );
  }

  return null;
}
