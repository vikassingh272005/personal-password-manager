'use client';

import { useEffect, useRef } from 'react';
import { api } from '@/lib/api';
import { useVaultStore } from '@/hooks/useVault';
import { decryptEnvelope, encryptEnvelope } from '@/lib/vaultEnvelope';

/**
 * Single owner of vault persistence: watches the in-memory vault and uploads a
 * new encrypted snapshot after every change. Mounted once in the root layout.
 *
 * On a version conflict (another device synced first) it quietly reloads the
 * newer server copy, so the client never drifts. The master password / vault
 * key never leave this device — only ciphertext is uploaded.
 */
export function VaultSyncManager() {
  const key = useVaultStore((s) => s.key);
  const items = useVaultStore((s) => s.items);
  const folders = useVaultStore((s) => s.folders);
  const serverVersion = useVaultStore((s) => s.serverVersion);
  const retry = useVaultStore((s) => s.syncRetry);
  const isLocked = useVaultStore((s) => s.isLocked);

  const inFlight = useRef(false);
  const lastSent = useRef<string | null>(null);

  // Seed the "last sent" marker when the vault is (re)unlocked: the contents
  // just loaded from the server are by definition already persisted.
  const hadKey = useRef(false);
  useEffect(() => {
    const state = useVaultStore.getState();
    if (state.key && !hadKey.current) {
      hadKey.current = true;
      lastSent.current = JSON.stringify({ items: state.items, folders: state.folders });
    }
    if (!state.key) hadKey.current = false;
  }, [key]);

  useEffect(() => {
    if (isLocked || !key) return;

    const state = useVaultStore.getState();
    const payload = JSON.stringify({ items: state.items, folders: state.folders });

    // Nothing to push: empty vault that has never synced, or no local change.
    if (state.serverVersion === 0 && state.items.length === 0 && state.folders.length === 0) {
      lastSent.current = payload;
      return;
    }
    if (payload === lastSent.current) return;

    const timer = setTimeout(async () => {
      if (inFlight.current) return;
      inFlight.current = true;

      const snapshot = useVaultStore.getState();
      if (snapshot.isLocked || !snapshot.key) {
        inFlight.current = false;
        return;
      }

      try {
        snapshot.setSyncState('syncing');
        const body = await encryptEnvelope(snapshot.key, snapshot.items, snapshot.folders);
        const res = await api.vault.update({
          version: snapshot.serverVersion + 1,
          ...body,
        });
        useVaultStore.getState().setSyncState('saved');
        useVaultStore.setState({ serverVersion: res.version });
        lastSent.current = JSON.stringify({ items: snapshot.items, folders: snapshot.folders });
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Sync failed';
        if (message.toLowerCase().includes('conflict')) {
          // Another device advanced the vault: adopt the newer server copy.
          try {
            const fresh = await api.vault.get();
            const st = useVaultStore.getState();
            if (!st.key) {
              inFlight.current = false;
              return;
            }
            if (fresh.ciphertext && fresh.nonce) {
              const envelope = await decryptEnvelope(st.key, fresh.ciphertext, fresh.nonce);
              lastSent.current = JSON.stringify({
                items: envelope.items,
                folders: envelope.folders,
              });
              st.applyServerContents(envelope.items, envelope.folders, fresh.version);
            } else {
              // Server vault is empty; treat local as newest, rebased to v1.
              lastSent.current = JSON.stringify({ items: st.items, folders: st.folders });
              st.applyServerContents(st.items, st.folders, 0);
            }
          } catch (reloadErr) {
            useVaultStore
              .getState()
              .setSyncState(
                'error',
                `Could not reload the newer vault copy — lock and unlock to resync (${reloadErr instanceof Error ? reloadErr.message : 'error'})`
              );
          }
        } else {
          useVaultStore.getState().setSyncState('error', message);
        }
      } finally {
        inFlight.current = false;
      }
    }, 600);

    return () => clearTimeout(timer);
  }, [key, items, folders, serverVersion, retry, isLocked]);

  return null;
}
