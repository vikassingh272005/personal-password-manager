'use client';

import { useEffect, useState } from 'react';
import { api, type VaultMeta } from '@/lib/api';
import { WRAP_AAD, deriveVaultKey, generateVek, normalizeRecoverySecret, wrapRawKey } from '@/lib/crypto';
import { decryptEnvelope, encryptEnvelope } from '@/lib/vaultEnvelope';
import { resolveVaultKeyWithMasterPassword, resolveVaultKeyWithSecretKey } from '@/lib/vaultKeys';
import { useVaultStore, type VaultItem } from '@/hooks/useVault';
import { useRouter } from 'next/navigation';
import { Lock, KeyRound } from 'lucide-react';
import Link from 'next/link';

type Mode = 'password' | 'secret' | 'setmaster';

export default function UnlockPage() {
  const router = useRouter();
  const { isLocked, unlock } = useVaultStore();
  const [mode, setMode] = useState<Mode>('password');
  const [masterPassword, setMasterPassword] = useState('');
  const [secretInput, setSecretInput] = useState('');
  const [newMaster, setNewMaster] = useState('');
  const [confirmNewMaster, setConfirmNewMaster] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // Held between the recovery-unlock step and the mandatory "set a new master
  // password" step; zeroized once the rewrap succeeds.
  const [pendingRewrap, setPendingRewrap] = useState<{ meta: VaultMeta; rawVek: Uint8Array<ArrayBuffer> } | null>(null);

  // Already unlocked this session? Nothing to do here.
  useEffect(() => {
    if (!isLocked) router.replace('/vault');
  }, [isLocked, router]);

  const sessionExpired = (message: string) =>
    message.includes('401') || message.toLowerCase().includes('authentication failed');

  /** Fetch metadata; surfaces expired-session as a friendly error. */
  const getMeta = async (): Promise<VaultMeta | null> => {
    try {
      return await api.vault.get();
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unlock failed';
      setError(sessionExpired(message) ? 'Your session expired — sign in again.' : message);
      return null;
    }
  };

  /** Decrypt the latest snapshot (if any) into store contents. */
  const loadContents = async (
    meta: VaultMeta,
    dataKey: CryptoKey
  ): Promise<{ items: VaultItem[]; folders: string[]; serverVersion: number }> => {
    if (meta.ciphertext && meta.nonce) {
      const envelope = await decryptEnvelope(dataKey, meta.ciphertext, meta.nonce);
      return { items: envelope.items, folders: envelope.folders, serverVersion: meta.version };
    }
    // No snapshot yet: fresh vault (or a legacy vault that never synced).
    return { items: [], folders: [], serverVersion: meta.kek_wrap ? meta.version : 0 };
  };

  const enterVault = (dataKey: CryptoKey, items: VaultItem[], folders: string[], serverVersion: number) => {
    unlock(items, folders, dataKey, serverVersion);
    router.push('/dashboard');
  };

  const handleUnlock = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (masterPassword.length < 12) {
      setError('Enter your master password to unlock');
      return;
    }

    setBusy(true);
    try {
      const meta = await getMeta();
      if (!meta) return;

      let dataKey: CryptoKey;
      let healed = false;
      try {
        // v2 vaults unwrap the VEK (wrong password fails here); legacy vaults
        // derive the data key directly.
        const resolved = await resolveVaultKeyWithMasterPassword(meta, masterPassword);
        dataKey = resolved.dataKey;

        if (resolved.mode === 'legacy' && !meta.kek_wrap && !meta.ciphertext) {
          // A legacy vault that never synced has nothing to verify the password
          // against. Activate it properly: mint a VEK, wrap it under the derived
          // KEK, and upload the empty v1 snapshot so later unlocks can verify.
          const { raw: rawVek, key: vek } = await generateVek();
          const kek = dataKey; // legacy data key == KEK derivation
          const kekWrap = await wrapRawKey(kek, rawVek, WRAP_AAD.kek);
          rawVek.fill(0);
          const body = await encryptEnvelope(vek, [], []);
          await api.vault.update({ version: 1, ...body, kek_wrap: kekWrap });
          dataKey = vek;
          healed = true; // snapshot v1 now exists; the cached meta is stale
        }
      } catch (cryptoErr) {
        setError('Incorrect master password — the vault could not be decrypted.');
        return;
      }

      let contents;
      try {
        // After a heal the vault is exactly the empty v1 snapshot we just
        // uploaded — deriving from the stale meta would report version 0 and
        // the first save would collide with it.
        contents = healed
          ? { items: [], folders: [], serverVersion: 1 }
          : await loadContents(meta, dataKey);
      } catch {
        setError('Incorrect master password — the vault could not be decrypted.');
        return;
      }

      enterVault(dataKey, contents.items, contents.folders, contents.serverVersion);
    } finally {
      setBusy(false);
    }
  };

  const handleSecretUnlock = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    let normalized: string;
    try {
      normalized = normalizeRecoverySecret(secretInput);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'That Secret Key is not valid.');
      return;
    }

    setBusy(true);
    try {
      const meta = await getMeta();
      if (!meta) return;

      let rawVek: Uint8Array<ArrayBuffer>;
      let dataKey: CryptoKey;
      try {
        const resolved = await resolveVaultKeyWithSecretKey(meta, normalized);
        rawVek = resolved.rawVek;
        dataKey = resolved.dataKey;
      } catch {
        setError('That Secret Key does not match this account.');
        return;
      }

      let contents;
      try {
        contents = await loadContents(meta, dataKey);
      } catch {
        // The recovery wrap is keyed correctly (it just decrypted) — a failure
        // here means the vault blob itself is damaged, not a wrong key.
        setError('Your vault data could not be decrypted with this Secret Key.');
        return;
      }

      unlock(contents.items, contents.folders, dataKey, contents.serverVersion);

      // The old master-password wrap is now useless (that password is lost) —
      // require a replacement before entering the vault.
      setPendingRewrap({ meta, rawVek });
      setMode('setmaster');
    } finally {
      setBusy(false);
    }
  };

  const handleSetNewMaster = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (newMaster !== confirmNewMaster) {
      setError('New master passwords do not match');
      return;
    }
    if (newMaster.length < 12) {
      setError('New master password must be at least 12 characters');
      return;
    }
    if (!pendingRewrap) return;

    setBusy(true);
    try {
      const { meta, rawVek } = pendingRewrap;
      const newKek = await deriveVaultKey(newMaster, meta.kdf_salt, meta.kdf_iterations);
      const kekWrap = await wrapRawKey(newKek, rawVek, WRAP_AAD.kek);
      rawVek.fill(0); // done with the raw VEK
      await api.vault.updateKeys({ kek_wrap: kekWrap });
      setPendingRewrap(null);
      router.push('/dashboard');
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to set new master password';
      setError(sessionExpired(message) ? 'Your session expired — sign in again.' : message);
    } finally {
      setBusy(false);
    }
  };

  const showModeSwitch = mode === 'password' || mode === 'secret';

  return (
    <div className="mx-auto mt-10 flex min-h-[calc(100vh-5rem)] max-w-md flex-col justify-center py-6">
      <div className="card p-8">
        <div className="icon-disc mx-auto !h-12 !w-12">
          {mode === 'secret' ? <KeyRound className="h-5 w-5 text-white" /> : <Lock className="h-5 w-5 text-white" />}
        </div>

        {mode === 'password' && (
          <>
            <h1 className="mt-5 text-center text-2xl font-bold tracking-tight">Vault locked</h1>
            <p className="mt-1.5 text-center text-sm leading-relaxed text-muted-foreground">
              Enter your master password to unlock your vault. It is processed
              locally in this browser and never sent to the server.
            </p>

            {error && <div className="alert-error mt-5">{error}</div>}

            <form onSubmit={handleUnlock} className="mt-6 space-y-4">
              <div>
                <label className="label" htmlFor="master-password">Master Password</label>
                <input
                  id="master-password"
                  type="password"
                  autoFocus
                  value={masterPassword}
                  onChange={(e) => setMasterPassword(e.target.value)}
                  className="input"
                  placeholder="••••••••••••"
                />
              </div>
              <button type="submit" disabled={busy} className="btn-primary w-full">
                {busy ? 'Decrypting…' : 'Unlock'}
              </button>
            </form>
          </>
        )}

        {mode === 'secret' && (
          <>
            <h1 className="mt-5 text-center text-2xl font-bold tracking-tight">Unlock with Secret Key</h1>
            <p className="mt-1.5 text-center text-sm leading-relaxed text-muted-foreground">
              Forgot your master password? Enter the Secret Key from your
              emergency kit. It decrypts locally — only you can use it.
            </p>

            {error && <div className="alert-error mt-5">{error}</div>}

            <form onSubmit={handleSecretUnlock} className="mt-6 space-y-4">
              <div>
                <label className="label" htmlFor="secret-key">Secret Key</label>
                <input
                  id="secret-key"
                  type="text"
                  autoFocus
                  autoComplete="off"
                  spellCheck={false}
                  value={secretInput}
                  onChange={(e) => setSecretInput(e.target.value)}
                  className="input font-mono tracking-widest"
                  placeholder="ABCD-EFGH-JKLM-NOPQ"
                />
              </div>
              <button type="submit" disabled={busy} className="btn-primary w-full">
                {busy ? 'Decrypting…' : 'Unlock with Secret Key'}
              </button>
            </form>
          </>
        )}

        {mode === 'setmaster' && (
          <>
            <h1 className="mt-5 text-center text-2xl font-bold tracking-tight">
              Set a new master password
            </h1>
            <p className="mt-1.5 text-center text-sm leading-relaxed text-muted-foreground">
              Your vault is unlocked with your Secret Key. Since your old master
              password no longer works, choose a new one. Your stored data is
              untouched — only the lock changes.
            </p>

            {error && <div className="alert-error mt-5">{error}</div>}

            <form onSubmit={handleSetNewMaster} className="mt-6 space-y-4">
              <div>
                <label className="label" htmlFor="new-master">New Master Password</label>
                <input
                  id="new-master"
                  type="password"
                  autoFocus
                  autoComplete="new-password"
                  value={newMaster}
                  onChange={(e) => setNewMaster(e.target.value)}
                  className="input"
                  placeholder="At least 12 characters"
                />
              </div>
              <div>
                <label className="label" htmlFor="confirm-new-master">Confirm New Master Password</label>
                <input
                  id="confirm-new-master"
                  type="password"
                  autoComplete="new-password"
                  value={confirmNewMaster}
                  onChange={(e) => setConfirmNewMaster(e.target.value)}
                  className="input"
                  placeholder="Repeat it"
                />
              </div>
              <button type="submit" disabled={busy} className="btn-primary w-full">
                {busy ? 'Saving…' : 'Set password & enter vault'}
              </button>
            </form>
          </>
        )}

        {showModeSwitch && (
          <p className="mt-6 text-center text-sm text-muted-foreground">
            {mode === 'password' ? (
              <>
                Forgot your master password?{' '}
                <Link
                  href="/unlock"
                  onClick={(e) => { e.preventDefault(); setError(null); setMode('secret'); }}
                  className="font-medium text-white hover:underline"
                >
                  Use your Secret Key
                </Link>
              </>
            ) : (
              <>
                Remember your master password?{' '}
                <Link
                  href="/unlock"
                  onClick={(e) => { e.preventDefault(); setError(null); setMode('password'); }}
                  className="font-medium text-white hover:underline"
                >
                  Unlock normally
                </Link>
              </>
            )}
          </p>
        )}
      </div>
    </div>
  );
}
