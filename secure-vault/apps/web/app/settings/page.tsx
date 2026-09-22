'use client';

import { useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useVaultStore } from '@/hooks/useVault';
import { useAuthStore } from '@/hooks/useAuth';
import { api, type VaultMeta } from '@/lib/api';
import { decryptEnvelope, encryptEnvelope } from '@/lib/vaultEnvelope';
import {
  WRAP_AAD,
  deriveRecoveryKey,
  deriveVaultKey,
  generateRecoverySecret,
  generateVek,
  normalizeRecoverySecret,
  unwrapRawKey,
  wrapRawKey,
} from '@/lib/crypto';
import {
  Timer,
  ClipboardX,
  Database,
  AlertTriangle,
  KeyRound,
  ShieldCheck,
  Check,
  Copy,
  Download,
  ShieldAlert,
  Smartphone,
  Fingerprint,
  Trash2,
} from 'lucide-react';
import QRCode from 'qrcode';
import { cn } from '@/lib/crypto';
import {
  createEncryptedExport,
  downloadExportFile,
  openEncryptedExport,
  readExportFile,
} from '@/lib/vaultTransfer';
import { createPasskey, passkeysSupported } from '@/lib/passkeys';
import type { PasskeyInfo } from '@/lib/api';

export default function SettingsPage() {
  const { lockTimeout, setLockTimeout } = useVaultStore();
  const [meta, setMeta] = useState<VaultMeta | null>(null);

  // ---- Data: encrypted export / import / account deletion ----------------
  const vaultItems = useVaultStore((s) => s.items);
  const vaultFolders = useVaultStore((s) => s.folders);
  const vaultKey = useVaultStore((s) => s.key);
  const addItemToStore = useVaultStore((s) => s.addItem);
  const lockVault = useVaultStore((s) => s.lock);
  const router = useRouter();
  const [exportPass, setExportPass] = useState('');
  const [exportBusy, setExportBusy] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);
  const importFileRef = useRef<HTMLInputElement>(null);
  const [importFile, setImportFile] = useState<File | null>(null);
  const [importPass, setImportPass] = useState('');
  const [importBusy, setImportBusy] = useState(false);
  const [importError, setImportError] = useState<string | null>(null);
  const [importResult, setImportResult] = useState<string | null>(null);
  const [deletePassword, setDeletePassword] = useState('');
  const [deleteConfirm, setDeleteConfirm] = useState('');
  const [deleteBusy, setDeleteBusy] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const handleExport = async () => {
    setExportError(null);
    if (!vaultKey) {
      setExportError('Unlock your vault first — export works on decrypted data.');
      return;
    }
    if (exportPass.length < 8) {
      setExportError('Use a passphrase of at least 8 characters for the export file.');
      return;
    }
    setExportBusy(true);
    try {
      const exportFile = await createEncryptedExport(exportPass, vaultItems, vaultFolders);
      downloadExportFile(exportFile);
      setExportPass('');
    } catch (err: unknown) {
      setExportError(err instanceof Error ? err.message : 'Export failed');
    } finally {
      setExportBusy(false);
    }
  };

  const handleImport = async () => {
    setImportError(null);
    setImportResult(null);
    if (!importFile || !vaultKey) {
      setImportError('Choose an export file (and unlock your vault) first.');
      return;
    }
    setImportBusy(true);
    try {
      const parsed = await readExportFile(importFile);
      const { items, folders } = await openEncryptedExport(importPass, parsed);
      const existingIds = new Set(vaultItems.map((i) => i.id));
      let added = 0;
      for (const item of items) {
        if (existingIds.has(item.id)) continue; // no silent overwrite
        addItemToStore(item);
        added += 1;
      }
      // Folders merge through the next sync (envelope carries the union).
      const mergedFolders = Array.from(new Set([...vaultFolders, ...folders]));
      useVaultStore.setState({ folders: mergedFolders });
      setImportResult(`Imported ${added} item${added === 1 ? '' : 's'} — syncing…`);
      setImportFile(null);
      setImportPass('');
      if (importFileRef.current) importFileRef.current.value = '';
    } catch (err: unknown) {
      setImportError(err instanceof Error ? err.message : 'Import failed');
    } finally {
      setImportBusy(false);
    }
  };

  const handleDeleteAccount = async () => {
    setDeleteError(null);
    if (deleteConfirm !== 'DELETE') {
      setDeleteError('Type DELETE to confirm.');
      return;
    }
    setDeleteBusy(true);
    try {
      await api.account.delete(deletePassword);
      lockVault();
      useAuthStore.getState().clear();
      router.push('/');
    } catch (err: unknown) {
      setDeleteError(err instanceof Error ? err.message : 'Deletion failed');
      setDeleteBusy(false);
    }
  };

  // ---- Master password change state ----
  const [currentMaster, setCurrentMaster] = useState('');
  const [newMaster, setNewMaster] = useState('');
  const [confirmNewMaster, setConfirmNewMaster] = useState('');
  const [mpError, setMpError] = useState<string | null>(null);
  const [mpBusy, setMpBusy] = useState(false);
  const [mpSuccess, setMpSuccess] = useState<string | null>(null);

  // ---- Passkey state ----
  const [passkeys, setPasskeys] = useState<PasskeyInfo[]>([]);
  const [passkeyBusy, setPasskeyBusy] = useState(false);
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  const [passkeyError, setPasskeyError] = useState<string | null>(null);
  const [passkeySuccess, setPasskeySuccess] = useState<string | null>(null);

  const refreshPasskeys = async () => {
    try {
      const res = await api.auth.listPasskeys();
      setPasskeys(res.passkeys);
    } catch {
      setPasskeys([]);
    }
  };

  const addPasskey = async () => {
    setPasskeyError(null);
    setPasskeySuccess(null);
    setPasskeyBusy(true);
    try {
      const { ceremony_id, options } = await api.auth.startPasskeyRegistration();
      const attestation = await createPasskey(options);
      await api.auth.finishPasskeyRegistration({
        ceremony_id,
        ...attestation,
        name: options.rp.name || 'This device',
      });
      setPasskeySuccess('Passkey added — you can now sign in without a password.');
      await refreshPasskeys();
    } catch (err: any) {
      if (err?.name !== 'NotAllowedError') {
        setPasskeyError(err.message);
      }
    } finally {
      setPasskeyBusy(false);
    }
  };

  const removePasskey = async (id: string) => {
    setPasskeyError(null);
    setPasskeySuccess(null);
    try {
      await api.auth.revokePasskey(id);
      setPasskeys((prev) => prev.filter((p) => p.id !== id));
      setPasskeySuccess('Passkey removed.');
    } catch (err: any) {
      setPasskeyError(err.message);
    }
  };

  // ---- Recovery kit state ----
  const [kitBusy, setKitBusy] = useState(false);
  const [kitError, setKitError] = useState<string | null>(null);
  const [secretKey, setSecretKey] = useState<string | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [copied, setCopied] = useState(false);

  // ---- Two-factor (TOTP) state ----
  const totpEnabled = useAuthStore((s) => s.user?.totp_enabled ?? false);
  const authUser = useAuthStore((s) => s.user);
  const refreshAuth = useAuthStore((s) => s.refresh);
  const [enrolling, setEnrolling] = useState(false);
  const [qrDataUrl, setQrDataUrl] = useState<string | null>(null);
  const [totpSecret, setTotpSecret] = useState<string | null>(null);
  const [totpCode, setTotpCode] = useState('');
  const [totpPassword, setTotpPassword] = useState('');
  const [totpError, setTotpError] = useState<string | null>(null);
  const [totpBusy, setTotpBusy] = useState(false);

  const timeoutOptions = [1, 5, 15, 30];
  const isUnlocked = useVaultStore((s) => !s.isLocked);

  // Show vault key-hierarchy status once, when the vault is unlocked.
  useEffect(() => {
    if (!isUnlocked) return;
    api.vault
      .get()
      .then(setMeta)
      .catch(() => setMeta(null));
  }, [isUnlocked]);

  // Load the account's passkeys when signed in.
  useEffect(() => {
    if (!authUser) return;
    refreshPasskeys();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [authUser?.user_id]);

  const sessionExpired = (message: string) =>
    message.includes('401') || message.toLowerCase().includes('authentication failed');

  /** Change the master password: v2 vaults only re-wrap the VEK; legacy
   * vaults are upgraded (mint a VEK, re-encrypt the items once) as part of
   * the change. Either way the stored data is untouched. */
  const handleChangeMaster = async (e: React.FormEvent) => {
    e.preventDefault();
    setMpError(null);
    setMpSuccess(null);

    if (newMaster !== confirmNewMaster) {
      setMpError('New master passwords do not match');
      return;
    }
    if (newMaster.length < 12) {
      setMpError('New master password must be at least 12 characters');
      return;
    }
    if (currentMaster.length < 1) {
      setMpError('Enter your current master password to confirm the change');
      return;
    }

    setMpBusy(true);
    try {
      const vaultMeta = meta ?? (await api.vault.get());
      if (!vaultMeta) return;

      if (vaultMeta.kek_wrap) {
        // v2: prove the current password by unwrapping the VEK, then re-wrap.
        let rawVek: Uint8Array<ArrayBuffer>;
        try {
          const oldKek = await deriveVaultKey(currentMaster, vaultMeta.kdf_salt, vaultMeta.kdf_iterations);
          rawVek = await unwrapRawKey(oldKek, vaultMeta.kek_wrap, WRAP_AAD.kek);
        } catch {
          setMpError('Current master password is incorrect.');
          return;
        }
        const newKek = await deriveVaultKey(newMaster, vaultMeta.kdf_salt, vaultMeta.kdf_iterations);
        const kekWrap = await wrapRawKey(newKek, rawVek, WRAP_AAD.kek);
        rawVek.fill(0);
        await api.vault.updateKeys({ kek_wrap: kekWrap });
        setMpSuccess('Master password changed. Your vault data was not re-encrypted — only the lock changed.');
      } else {
        // Legacy vault: verify the current password against the stored
        // snapshot, then upgrade to a random VEK under the new password.
        if (!vaultMeta.ciphertext || !vaultMeta.nonce) {
          setMpError('This vault has not been initialized yet — lock and unlock it once, then try again.');
          return;
        }
        const oldKey = await deriveVaultKey(currentMaster, vaultMeta.kdf_salt, vaultMeta.kdf_iterations);
        try {
          await decryptEnvelope(oldKey, vaultMeta.ciphertext, vaultMeta.nonce);
        } catch {
          setMpError('Current master password is incorrect.');
          return;
        }

        const { raw: rawVek, key: vek } = await generateVek();
        const newKek = await deriveVaultKey(newMaster, vaultMeta.kdf_salt, vaultMeta.kdf_iterations);
        const kekWrap = await wrapRawKey(newKek, rawVek, WRAP_AAD.kek);
        rawVek.fill(0);

        const state = useVaultStore.getState();
        const body = await encryptEnvelope(vek, state.items, state.folders);
        const res = await api.vault.update({
          version: state.serverVersion + 1,
          ...body,
          kek_wrap: kekWrap,
        });
        // The store must encrypt future saves with the VEK from now on.
        state.rekey(vek);
        useVaultStore.setState({ serverVersion: res.version });
        setMpSuccess('Master password changed and your vault was upgraded to random-key encryption. Your data is intact.');
      }
      setCurrentMaster('');
      setNewMaster('');
      setConfirmNewMaster('');
      setMeta(await api.vault.get());
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Change failed';
      setMpError(
        sessionExpired(message)
          ? 'Your session expired — sign in again and retry.'
          : message
      );
    } finally {
      setMpBusy(false);
    }
  };

  /** Generate a Secret Key recovery kit (only possible once the vault holds a
   * random VEK — i.e. v2). The new key wraps the existing VEK; the old wrap
   * (if any) is untouched, so previously printed kits keep working. */
  const handleGenerateKit = async () => {
    setKitError(null);
    setKitBusy(true);
    try {
      const vaultMeta = meta ?? (await api.vault.get());
      if (!vaultMeta) return;
      if (!vaultMeta.kek_wrap) {
        setKitError(
          'This vault still uses direct master-password encryption. Change your master password once to upgrade it, then generate a recovery kit.'
        );
        return;
      }

      const storeKey = useVaultStore.getState().key;
      if (!storeKey) {
        setKitError('Vault is locked — unlock it before generating a recovery kit.');
        return;
      }
      const rawVek = new Uint8Array(await crypto.subtle.exportKey('raw', storeKey));

      const secret = generateRecoverySecret();
      const normalized = normalizeRecoverySecret(secret);
      const rk = await deriveRecoveryKey(normalized, vaultMeta.kdf_iterations);
      const recoveryWrap = await wrapRawKey(rk, rawVek, WRAP_AAD.recovery);
      rawVek.fill(0);

      await api.vault.updateKeys({ recovery_wrap: recoveryWrap });
      setSecretKey(secret);
      setMeta(await api.vault.get());
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Generation failed';
      setKitError(sessionExpired(message) ? 'Your session expired — sign in again and retry.' : message);
    } finally {
      setKitBusy(false);
    }
  };

  const downloadKit = () => {
    if (!secretKey) return;
    const me = useAuthStore.getState().user?.email ?? null;
    const text = [
      'SecureVault — Emergency Kit',
      '===========================',
      '',
      ...(me ? [`Account:  ${me}`] : []),
      `Secret Key:  ${secretKey}`,
      '',
      'Keep this somewhere safe and private. Anyone who has your email and',
      'Secret Key can unlock your vault if your master password is lost.',
      'SecureVault can never show this key again.',
    ].join('\n');
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'securevault-emergency-kit.txt';
    a.click();
    URL.revokeObjectURL(url);
  };

  const copySecret = async () => {
    if (!secretKey) return;
    await navigator.clipboard.writeText(secretKey);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const doneWithKit = () => {
    setSecretKey(null);
    setAcknowledged(false);
  };

  /** Begin 2FA enrollment: mint a pending secret server-side and render its
   * otpauth:// URI as a QR code entirely in the browser. */
  const startTotpSetup = async () => {
    setTotpError(null);
    setTotpBusy(true);
    try {
      const { secret, otpauth_uri } = await api.auth.start2faSetup();
      setTotpSecret(secret);
      setQrDataUrl(
        await QRCode.toDataURL(otpauth_uri, {
          margin: 1,
          width: 180,
          color: { dark: '#0b1220', light: '#ffffff' },
        })
      );
      setTotpCode('');
      setEnrolling(true);
    } catch (err) {
      setTotpError(err instanceof Error ? err.message : 'Setup failed');
    } finally {
      setTotpBusy(false);
    }
  };

  /** Confirm a live code from the authenticator app — activates 2FA. */
  const verifyTotp = async (e: React.FormEvent) => {
    e.preventDefault();
    setTotpError(null);
    setTotpBusy(true);
    try {
      await api.auth.verify2fa(totpCode.trim());
      await refreshAuth();
      setEnrolling(false);
      setTotpCode('');
      setTotpSecret(null);
      setQrDataUrl(null);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Verification failed';
      setTotpError(sessionExpired(message) ? 'Your session expired — sign in again and retry.' : message);
    } finally {
      setTotpBusy(false);
    }
  };

  /** Disable 2FA — requires both a current code and the account password. */
  const disableTotp = async (e: React.FormEvent) => {
    e.preventDefault();
    setTotpError(null);
    setTotpBusy(true);
    try {
      await api.auth.disable2fa(totpCode.trim(), totpPassword);
      await refreshAuth();
      setTotpCode('');
      setTotpPassword('');
    } catch (err) {
      setTotpError(err instanceof Error ? err.message : 'Disable failed');
    } finally {
      setTotpBusy(false);
    }
  };

  const cancelEnrollment = () => {
    setEnrolling(false);
    setTotpCode('');
    setTotpSecret(null);
    setQrDataUrl(null);
    setTotpError(null);
  };

  // ---- Secret Key reveal (shown once per generation) ----
  if (secretKey) {
    return (
      <div className="space-y-8">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Your new Secret Key</h1>
          <p className="mt-1.5 text-muted-foreground">
            Shown once — store it in your emergency kit. Your previous key (if any) still works.
          </p>
        </div>
        <div className="card p-8">
          <div className="select-all mx-auto max-w-md rounded-xl bg-secondary/60 px-4 py-3 text-center font-mono text-lg font-semibold tracking-[0.08em]">
            {secretKey}
          </div>
          <div className="mx-auto mt-4 flex max-w-md gap-2">
            <button onClick={copySecret} className="btn-ghost flex-1 cursor-pointer">
              {copied ? <Check className="mr-1.5 inline h-4 w-4" /> : <Copy className="mr-1.5 inline h-4 w-4" />}
              {copied ? 'Copied' : 'Copy'}
            </button>
            <button onClick={downloadKit} className="btn-ghost flex-1 cursor-pointer">
              <Download className="mr-1.5 inline h-4 w-4" />
              Download kit
            </button>
          </div>
          <div className="mx-auto mt-4 flex max-w-md items-start gap-2.5 rounded-xl border border-orange-500/20 bg-orange-500/10 px-4 py-3 text-xs leading-relaxed text-orange-300">
            <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
            <span>
              Anyone with this key and your email can unlock your vault. Keep it offline.
            </span>
          </div>
          <label className="mx-auto mt-5 flex max-w-md cursor-pointer items-start gap-2.5 text-sm text-muted-foreground">
            <input
              type="checkbox"
              checked={acknowledged}
              onChange={(e) => setAcknowledged(e.target.checked)}
              className="mt-0.5"
            />
            <span>I have saved this Secret Key somewhere safe.</span>
          </label>
          <div className="mx-auto mt-5 max-w-md">
            <button onClick={doneWithKit} disabled={!acknowledged} className="btn-primary w-full">
              Done
            </button>
          </div>
        </div>
      </div>
    );
  }

  const isV2 = meta?.kek_wrap != null;
  const hasKit = meta?.recovery_wrap != null;

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Settings</h1>
        <p className="mt-1.5 text-muted-foreground">Manage your vault preferences.</p>
      </div>

      <section className="card p-6">
        <div className="flex items-start gap-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-primary/10">
            <Timer className="h-4 w-4 text-primary" />
          </div>
          <div>
            <h2 className="text-lg font-semibold tracking-tight">Auto Lock</h2>
            <p className="mt-1 text-sm leading-relaxed text-muted-foreground">
              Automatically lock the vault after inactivity. The decryption key is
              removed from memory on lock.
            </p>
          </div>
        </div>
        <div className="mt-5 flex flex-wrap gap-2">
          {timeoutOptions.map((minutes) => (
            <button
              key={minutes}
              onClick={() => setLockTimeout(minutes)}
              className={cn(
                'cursor-pointer rounded-xl px-4 py-2 text-sm font-medium transition-all',
                lockTimeout === minutes
                  ? 'bg-primary text-primary-foreground shadow-[0_4px_16px_-6px_hsl(var(--primary)/0.55)]'
                  : 'border border-border hover:bg-accent'
              )}
            >
              {minutes} min
            </button>
          ))}
          <button
            onClick={() => setLockTimeout(0)}
            className={cn(
              'cursor-pointer rounded-xl px-4 py-2 text-sm font-medium transition-all',
              lockTimeout === 0
                ? 'bg-primary text-primary-foreground shadow-[0_4px_16px_-6px_hsl(var(--primary)/0.55)]'
                : 'border border-border hover:bg-accent'
            )}
          >
            Never
          </button>
        </div>
        {lockTimeout === 0 && (
          <p className="mt-3 flex items-center gap-2 text-xs text-orange-400">
            <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
            Warning: disabling auto-lock leaves your decrypted vault in memory indefinitely.
          </p>
        )}
      </section>

      <section className="card p-6">
        <div className="flex items-start gap-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-primary/10">
            <Smartphone className="h-4 w-4 text-primary" />
          </div>
          <div className="flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="text-lg font-semibold tracking-tight">Two-Factor Authentication</h2>
              <span
                className={cn(
                  'rounded px-1.5 py-0.5 text-[10px] font-mono font-semibold uppercase tracking-wide',
                  totpEnabled
                    ? 'bg-emerald-500/15 text-emerald-400'
                    : 'bg-secondary text-muted-foreground'
                )}
              >
                {totpEnabled ? 'active' : 'off'}
              </span>
            </div>
            <p className="mt-1 text-sm leading-relaxed text-muted-foreground">
              Require a rotating 6-digit code from an authenticator app (Google
              Authenticator, Authy, 1Password…) after your password at sign-in.
            </p>
          </div>
        </div>

        {totpError && <div className="alert-error mt-5">{totpError}</div>}

        {totpEnabled ? (
          <form onSubmit={disableTotp} className="mt-5 space-y-4">
            <p className="text-sm text-muted-foreground">
              To turn two-factor off, enter a current code and your account password.
            </p>
            <div className="grid gap-4 sm:grid-cols-2">
              <div>
                <label className="label" htmlFor="totp-disable-code">Authenticator code</label>
                <input
                  id="totp-disable-code"
                  type="text"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  maxLength={6}
                  value={totpCode}
                  onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ''))}
                  className="input font-mono tracking-[0.3em]"
                  placeholder="000000"
                />
              </div>
              <div>
                <label className="label" htmlFor="totp-disable-password">Account password</label>
                <input
                  id="totp-disable-password"
                  type="password"
                  autoComplete="current-password"
                  value={totpPassword}
                  onChange={(e) => setTotpPassword(e.target.value)}
                  className="input"
                  placeholder="••••••••••••"
                />
              </div>
            </div>
            <button type="submit" disabled={totpBusy || totpCode.length !== 6 || !totpPassword} className="btn-danger">
              {totpBusy ? 'Disabling…' : 'Disable Two-Factor'}
            </button>
          </form>
        ) : enrolling && qrDataUrl ? (
          <div className="mt-5 space-y-5">
            <ol className="list-inside list-decimal space-y-1 text-sm text-muted-foreground">
              <li>Scan this QR code with your authenticator app.</li>
              <li>Enter the 6-digit code it shows to confirm.</li>
            </ol>
            <div className="flex flex-col items-center gap-4 sm:flex-row sm:items-start">
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img
                src={qrDataUrl}
                alt="Two-factor QR code"
                className="h-44 w-44 rounded-xl bg-white p-2"
              />
              <div className="min-w-0 flex-1">
                <p className="text-xs text-muted-foreground">Can&apos;t scan? Enter this secret manually:</p>
                <div className="select-all mt-2 break-all rounded-xl bg-secondary/60 px-3 py-2 font-mono text-xs">
                  {totpSecret}
                </div>
              </div>
            </div>
            <form onSubmit={verifyTotp} className="space-y-4">
              <div>
                <label className="label" htmlFor="totp-verify-code">Authenticator code</label>
                <input
                  id="totp-verify-code"
                  type="text"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  maxLength={6}
                  autoFocus
                  value={totpCode}
                  onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ''))}
                  className="input max-w-[220px] text-center font-mono text-lg tracking-[0.4em]"
                  placeholder="000000"
                />
              </div>
              <div className="flex gap-2">
                <button type="submit" disabled={totpBusy || totpCode.length !== 6} className="btn-primary">
                  {totpBusy ? 'Verifying…' : 'Activate Two-Factor'}
                </button>
                <button type="button" onClick={cancelEnrollment} disabled={totpBusy} className="btn-ghost">
                  Cancel
                </button>
              </div>
            </form>
          </div>
        ) : (
          <button onClick={startTotpSetup} disabled={totpBusy} className="btn-primary mt-5">
            {totpBusy ? 'Generating…' : 'Set Up Two-Factor'}
          </button>
        )}
      </section>

      {/* ---- Passkeys ---- */}
      <section className="card p-6">
        <div className="flex items-start gap-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-primary/10">
            <Fingerprint className="h-4 w-4 text-primary" />
          </div>
          <div>
            <h2 className="text-lg font-semibold tracking-tight">Passkeys</h2>
            <p className="mt-1 text-sm leading-relaxed text-muted-foreground">
              Sign in with your fingerprint, face, or device PIN — no password
              needed at login. Passkeys live in this device&apos;s secure hardware
              and never leave it.
            </p>
          </div>
        </div>

        {passkeyError && <div className="alert-error mt-5">{passkeyError}</div>}
        {passkeySuccess && <div className="alert-success mt-5">{passkeySuccess}</div>}

        {passkeys.length > 0 && (
          <ul className="mt-5 divide-y divide-border rounded-xl border border-border">
            {passkeys.map((pk) => (
              <li key={pk.id} className="flex items-center justify-between gap-3 px-4 py-3">
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium">{pk.name || 'Passkey'}</p>
                  <p className="text-xs text-muted-foreground">
                    Added {pk.created_at ? new Date(pk.created_at).toLocaleDateString() : '—'}
                    {pk.last_used_at
                      ? ` · last used ${new Date(pk.last_used_at).toLocaleDateString()}`
                      : ' · never used'}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => removePasskey(pk.id)}
                  className="btn-ghost shrink-0 !px-2 text-muted-foreground hover:text-red-400"
                  aria-label={`Remove ${pk.name || 'passkey'}`}
                >
                  <Trash2 className="h-4 w-4" />
                </button>
              </li>
            ))}
          </ul>
        )}

        {mounted && passkeysSupported() ? (
          <button onClick={addPasskey} disabled={passkeyBusy} className="btn-primary mt-5">
            <Fingerprint className="h-4 w-4" />
            {passkeyBusy ? 'Waiting for authenticator…' : 'Add a passkey'}
          </button>
        ) : (
          <p className="mt-5 text-sm text-muted-foreground">
            This browser does not support passkeys.
          </p>
        )}
      </section>

      <section className="card p-6">
        <div className="flex items-start gap-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-primary/10">
            <KeyRound className="h-4 w-4 text-primary" />
          </div>
          <div>
            <h2 className="text-lg font-semibold tracking-tight">Master Password</h2>
            <p className="mt-1 text-sm leading-relaxed text-muted-foreground">
              Your master password only unlocks a random vault key — changing it
              never re-encrypts your stored items, so it is instant.
            </p>
          </div>
        </div>

        {isUnlocked && meta && !isV2 && (
          <p className="mt-3 flex items-start gap-2 rounded-xl border border-amber-500/20 bg-amber-500/10 px-4 py-3 text-xs leading-relaxed text-amber-300">
            <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            <span>
              This vault still uses the older direct-encryption format. Changing your master
              password here upgrades it to random-key encryption in the same step.
            </span>
          </p>
        )}

        {mpSuccess && <div className="alert-success mt-5">{mpSuccess}</div>}
        {mpError && <div className="alert-error mt-5">{mpError}</div>}

        <form onSubmit={handleChangeMaster} className="mt-5 space-y-4">
          <div>
            <label className="label" htmlFor="current-master">Current Master Password</label>
            <input
              id="current-master"
              type="password"
              autoComplete="current-password"
              value={currentMaster}
              onChange={(e) => setCurrentMaster(e.target.value)}
              className="input"
              placeholder="••••••••••••"
            />
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <div>
              <label className="label" htmlFor="new-master">New Master Password</label>
              <input
                id="new-master"
                type="password"
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
          </div>
          <button type="submit" disabled={mpBusy || !isUnlocked} className="btn-primary">
            {mpBusy ? 'Changing…' : isV2 ? 'Change Master Password' : 'Change & Upgrade Vault'}
          </button>
        </form>
      </section>

      <section className="card p-6">
        <div className="flex items-start gap-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-primary/10">
            <ShieldCheck className="h-4 w-4 text-primary" />
          </div>
          <div>
            <h2 className="text-lg font-semibold tracking-tight">Secret Key (recovery kit)</h2>
            <p className="mt-1 text-sm leading-relaxed text-muted-foreground">
              A printable key that can unlock your vault if you forget your master password.
              It is generated in this browser, shown once, and never stored by the service.
            </p>
          </div>
        </div>

        {isUnlocked && meta && (
          <p className="mt-3 text-sm text-muted-foreground">
            {hasKit
              ? 'A recovery kit is on file for this vault. Generating a new one does not invalidate an existing printed key.'
              : 'No recovery kit on file yet.'}
          </p>
        )}
        {kitError && <div className="alert-error mt-5">{kitError}</div>}

        <button
          onClick={handleGenerateKit}
          disabled={kitBusy || !isUnlocked || (meta != null && !isV2)}
          className="btn-primary mt-5"
          title={
            meta && !isV2
              ? 'Upgrade your vault by changing your master password first'
              : undefined
          }
        >
          {kitBusy ? 'Generating…' : hasKit ? 'Generate a New Secret Key' : 'Generate My Secret Key'}
        </button>
        {meta && !isV2 && (
          <p className="mt-2 text-xs text-muted-foreground">
            Direct-encryption vaults cannot mint a recovery kit — change your master password once to upgrade.
          </p>
        )}
      </section>

      <section className="card p-6">
        <div className="flex items-start gap-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-primary/10">
            <ClipboardX className="h-4 w-4 text-primary" />
          </div>
          <div>
            <h2 className="text-lg font-semibold tracking-tight">Clipboard Security</h2>
            <p className="mt-1 text-sm leading-relaxed text-muted-foreground">
              Copied passwords are automatically cleared from the clipboard after 30
              seconds.
            </p>
          </div>
        </div>
      </section>

      <section className="card p-6">
        <div className="flex items-start gap-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-primary/10">
            <Database className="h-4 w-4 text-primary" />
          </div>
          <div>
            <h2 className="text-lg font-semibold tracking-tight">Data</h2>
            <p className="mt-1 text-sm leading-relaxed text-muted-foreground">
              Encrypted backups happen entirely in your browser: exports are
              AES-256-GCM files locked with a passphrase only you know. The
              server never sees them.
            </p>
          </div>
        </div>

        <div className="mt-5 grid gap-6 lg:grid-cols-2">
          <div className="rounded-xl border border-border/60 p-4">
            <h3 className="text-sm font-semibold">Export vault</h3>
            <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
              Downloads an encrypted <code>.json</code> file with every item and
              folder. Keep the passphrase safe — it is the only way to open the
              file.
            </p>
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <input
                type="password"
                className="input flex-1 min-w-[12rem]"
                placeholder="Export passphrase (min 8 chars)"
                value={exportPass}
                onChange={(e) => setExportPass(e.target.value)}
                autoComplete="new-password"
              />
              <button
                className="btn-primary"
                onClick={handleExport}
                disabled={exportBusy || !vaultKey}
                title={vaultKey ? undefined : 'Unlock the vault first'}
              >
                <Download className="mr-1.5 inline h-4 w-4" />
                {exportBusy ? 'Exporting…' : 'Export Vault'}
              </button>
            </div>
            {exportError && (
              <p className="mt-2 text-xs text-red-400">{exportError}</p>
            )}
          </div>

          <div className="rounded-xl border border-border/60 p-4">
            <h3 className="text-sm font-semibold">Import vault</h3>
            <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
              Merges items from an export file into this vault. Existing items
              are never overwritten; duplicates are skipped.
            </p>
            <div className="mt-3 space-y-2">
              <input
                ref={importFileRef}
                type="file"
                accept="application/json,.json"
                className="input file:mr-3 file:rounded-md file:border-0 file:bg-primary/10 file:px-3 file:py-1 file:text-primary"
                onChange={(e) => setImportFile(e.target.files?.[0] ?? null)}
              />
              <div className="flex flex-wrap items-center gap-2">
                <input
                  type="password"
                  className="input flex-1 min-w-[12rem]"
                  placeholder="Passphrase of the export file"
                  value={importPass}
                  onChange={(e) => setImportPass(e.target.value)}
                  autoComplete="off"
                />
                <button
                  className="btn-primary"
                  onClick={handleImport}
                  disabled={importBusy || !importFile || !vaultKey}
                  title={vaultKey ? undefined : 'Unlock the vault first'}
                >
                  {importBusy ? 'Importing…' : 'Import Vault'}
                </button>
              </div>
            </div>
            {importError && <p className="mt-2 text-xs text-red-400">{importError}</p>}
            {importResult && (
              <p className="mt-2 text-xs text-emerald-400">{importResult}</p>
            )}
          </div>
        </div>

        <div className="mt-6 rounded-xl border border-red-500/30 bg-red-500/5 p-4">
          <div className="flex items-start gap-3">
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-red-500/10">
              <ShieldAlert className="h-4 w-4 text-red-400" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-red-300">Danger zone</h3>
              <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
                Permanently deletes your account, the encrypted vault, every
                device, passkey and session on the server. This cannot be
                undone — export a backup first if you might need the data.
              </p>
            </div>
          </div>
          <div className="mt-3 grid gap-2 sm:grid-cols-2">
            <input
              type="password"
              className="input"
              placeholder="Confirm with your account password"
              value={deletePassword}
              onChange={(e) => setDeletePassword(e.target.value)}
              autoComplete="current-password"
            />
            <input
              type="text"
              className="input"
              placeholder="Type DELETE to confirm"
              value={deleteConfirm}
              onChange={(e) => setDeleteConfirm(e.target.value)}
            />
          </div>
          <button
            className="btn-danger mt-3"
            onClick={handleDeleteAccount}
            disabled={deleteBusy || deleteConfirm !== 'DELETE' || deletePassword.length === 0}
          >
            <Trash2 className="mr-1.5 inline h-4 w-4" />
            {deleteBusy ? 'Deleting…' : 'Permanently Delete Account'}
          </button>
          {deleteError && <p className="mt-2 text-xs text-red-400">{deleteError}</p>}
        </div>
      </section>
    </div>
  );
}
