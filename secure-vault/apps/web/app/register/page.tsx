'use client';

import { useState } from 'react';
import { api } from '@/lib/api';
import { useRouter } from 'next/navigation';
import { KeyRound, Copy, Check, Download, ShieldAlert } from 'lucide-react';
import Link from 'next/link';
import { useVaultStore } from '@/hooks/useVault';
import { encryptEnvelope } from '@/lib/vaultEnvelope';
import {
  WRAP_AAD,
  deriveRecoveryKey,
  deriveVaultKey,
  generateRecoverySecret,
  generateVek,
  normalizeRecoverySecret,
  wrapRawKey,
} from '@/lib/crypto';

type Step = 'form' | 'creating' | 'secret';

export default function RegisterPage() {
  const router = useRouter();
  const unlock = useVaultStore((s) => s.unlock);
  const [step, setStep] = useState<Step>('form');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [masterPassword, setMasterPassword] = useState('');
  const [confirmMaster, setConfirmMaster] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [secretKey, setSecretKey] = useState<string | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [copied, setCopied] = useState(false);
  // Set once the server account exists: retries must re-run only the local
  // vault initialization, never POST /auth/register again (it would 409).
  const [registered, setRegistered] = useState(false);
  const [kdf, setKdf] = useState<{ salt: string; iterations: number } | null>(null);

  /** All steps after the account exists: derive KEK, create the VEK + Secret
   * Key, wrap the VEK twice, upload the empty v1 snapshot, unlock locally.
   * KDF params are passed in (not read from state) so the flow can run
   * synchronously after registration without waiting on a re-render. */
  const initializeVault = async (
    master: string,
    kdfParams: { salt: string; iterations: number }
  ) => {
    const kek = await deriveVaultKey(master, kdfParams.salt, kdfParams.iterations);

    const { raw: rawVek, key: vek } = await generateVek();
    const secret = generateRecoverySecret();
    const normalized = normalizeRecoverySecret(secret);
    const recoveryKey = await deriveRecoveryKey(normalized, kdfParams.iterations);

    const kekWrap = await wrapRawKey(kek, rawVek, WRAP_AAD.kek);
    const recoveryWrap = await wrapRawKey(recoveryKey, rawVek, WRAP_AAD.recovery);
    rawVek.fill(0); // the raw key was only needed for wrapping

    const body = await encryptEnvelope(vek, [], []);
    await api.vault.update({ version: 1, ...body, kek_wrap: kekWrap, recovery_wrap: recoveryWrap });

    // This browser now holds the only copy of the VEK — unlock straight away.
    unlock([], [], vek, 1);
    setLoading(false);
    setSecretKey(secret);
    setStep('secret');
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (masterPassword !== confirmMaster) {
      setError('Master passwords do not match');
      return;
    }
    if (masterPassword.length < 12) {
      setError('Master password must be at least 12 characters');
      return;
    }

    setLoading(true);
    setStep('creating');
    try {
      const res = await api.auth.register({ email, password });
      setRegistered(true);
      const kdfParams = { salt: res.kdf_salt, iterations: res.kdf_iterations };
      setKdf(kdfParams);
      await initializeVault(masterPassword, kdfParams);
    } catch (err: any) {
      // Keep the filled-in form behind the error so a retry can resume.
      setError(
        registered
          ? `Account created, but vault initialization failed — press "Try again" to finish setting up your vault. (${err.message})`
          : err.message
      );
      setStep('form');
      setLoading(false);
    }
  };

  /** Re-validate master password rules and re-run initialization (registration
   * already succeeded — do not POST /auth/register again). */
  const retrySubmit = async () => {
    setError(null);
    if (masterPassword !== confirmMaster) {
      setError('Master passwords do not match');
      return;
    }
    if (masterPassword.length < 12) {
      setError('Master password must be at least 12 characters');
      return;
    }
    setLoading(true);
    setStep('creating');
    try {
      if (!kdf) {
        setError('Registration did not complete — refresh and try again.');
        setStep('form');
        setLoading(false);
        return;
      }
      await initializeVault(masterPassword, kdf);
    } catch (err: any) {
      setError(`Vault initialization failed: ${err.message}`);
      setStep('form');
      setLoading(false);
    }
  };

  const downloadKit = () => {
    if (!secretKey) return;
    const text = [
      'SecureVault — Emergency Kit',
      '===========================',
      '',
      `Account:  ${email}`,
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

  const continueToVault = () => {
    // The recovery kit must not linger in the DOM / state after this point.
    setSecretKey(null);
    router.push('/dashboard');
  };

  // ---- Secret Key reveal step (shown exactly once, right after creation) ----
  if (step === 'secret' && secretKey) {
    return (
      <div className="mx-auto mt-10 flex min-h-[calc(100vh-5rem)] max-w-lg flex-col justify-center py-6">
        <div className="card p-8">
          <div className="icon-disc mx-auto !h-11 !w-11">
            <KeyRound className="h-5 w-5 text-white" />
          </div>
          <h1 className="mt-5 text-center text-2xl font-bold tracking-tight">Your vault is ready</h1>
          <p className="mt-1.5 text-center text-sm leading-relaxed text-muted-foreground">
            Save your <span className="font-semibold text-foreground">Secret Key</span> now — it is
            shown <span className="font-semibold text-foreground">only once</span>. Together with
            your email it can recover your vault if you ever forget your master password. SecureVault
            does not store it and cannot show it again.
          </p>

          <div className="mt-6 rounded-2xl border border-border bg-background p-5">
            <div className="select-all rounded-xl bg-secondary/60 px-4 py-3 text-center font-mono text-lg font-semibold tracking-[0.08em]">
              {secretKey}
            </div>
            <div className="mt-4 flex gap-2">
              <button onClick={copySecret} className="btn-ghost flex-1 cursor-pointer">
                {copied ? <Check className="mr-1.5 inline h-4 w-4" /> : <Copy className="mr-1.5 inline h-4 w-4" />}
                {copied ? 'Copied' : 'Copy'}
              </button>
              <button onClick={downloadKit} className="btn-ghost flex-1 cursor-pointer">
                <Download className="mr-1.5 inline h-4 w-4" />
                Download kit
              </button>
            </div>
          </div>

          <div className="mt-4 flex items-start gap-2.5 rounded-xl border border-orange-500/20 bg-orange-500/10 px-4 py-3 text-xs leading-relaxed text-orange-300">
            <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
            <span>
              Anyone with this key and your email can decrypt your vault. Keep it offline — print it
              or store it in a safe place. Never type it anywhere but the official SecureVault unlock page.
            </span>
          </div>

          <label className="mt-5 flex cursor-pointer items-start gap-2.5 text-sm text-muted-foreground">
            <input
              type="checkbox"
              checked={acknowledged}
              onChange={(e) => setAcknowledged(e.target.checked)}
              className="mt-0.5"
            />
            <span>I have saved my Secret Key somewhere safe and understand it cannot be shown again.</span>
          </label>

          <button
            onClick={continueToVault}
            disabled={!acknowledged || loading}
            className="btn-primary mt-5 w-full"
          >
            Enter my vault
          </button>
        </div>
      </div>
    );
  }

  // ---- Account + master password form ----
  return (
    <div className="mx-auto mt-10 flex min-h-[calc(100vh-5rem)] max-w-md flex-col justify-center py-6">
      <div className="card p-8">
        <div className="icon-disc mx-auto !h-11 !w-11">
          <KeyRound className="h-5 w-5 text-white" />
        </div>
        <h1 className="mt-5 text-center text-2xl font-bold tracking-tight">Create your vault</h1>
        <p className="mt-1.5 text-center text-sm leading-relaxed text-muted-foreground">
          Your master password wraps a random vault key that only you can unlock.
          It cannot be reset by the service — your printed Secret Key is the backup.
        </p>

        {error && <div className="alert-error mt-5">{error}</div>}

        <form onSubmit={handleSubmit} className="mt-6 space-y-4">
          <div>
            <label className="label" htmlFor="email">Email</label>
            <input
              id="email"
              type="email"
              required
              autoComplete="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="input"
              placeholder="you@example.com"
            />
          </div>
          <div>
            <label className="label" htmlFor="password">Account Password</label>
            <input
              id="password"
              type="password"
              required
              autoComplete="new-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="input"
              placeholder="Used to sign in"
            />
          </div>
          <div>
            <label className="label" htmlFor="master-password">Master Password</label>
            <input
              id="master-password"
              type="password"
              required
              autoComplete="new-password"
              value={masterPassword}
              onChange={(e) => setMasterPassword(e.target.value)}
              className="input"
              placeholder="At least 12 characters — unlocks your vault"
            />
          </div>
          <div>
            <label className="label" htmlFor="confirm-master">Confirm Master Password</label>
            <input
              id="confirm-master"
              type="password"
              required
              autoComplete="new-password"
              value={confirmMaster}
              onChange={(e) => setConfirmMaster(e.target.value)}
              className="input"
              placeholder="Repeat your master password"
            />
          </div>
          {registered && (
            <button type="button" onClick={retrySubmit} disabled={loading} className="btn-ghost w-full">
              {loading ? 'Retrying…' : 'Try again'}
            </button>
          )}
          <button type="submit" disabled={loading} className="btn-primary w-full">
            {loading ? 'Creating…' : 'Create Secure Vault'}
          </button>
        </form>
      </div>

      <p className="mt-6 text-center text-sm text-muted-foreground">
        Already have an account?{' '}
        <Link href="/login" className="font-medium text-white hover:underline">
          Sign in
        </Link>
      </p>
    </div>
  );
}
