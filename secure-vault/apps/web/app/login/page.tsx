'use client';

import { useState } from 'react';
import { api } from '@/lib/api';
import { useRouter } from 'next/navigation';
import { Fingerprint, Lock, ShieldCheck } from 'lucide-react';
import Link from 'next/link';
import { createPasskey, getPasskeyAssertion, passkeysSupported } from '@/lib/passkeys';

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  // Step 2 of the flow: the password was accepted but the account has 2FA,
  // so the session is "awaiting" a TOTP code and only accepts the challenge.
  const [awaiting2fa, setAwaiting2fa] = useState(false);
  const [code, setCode] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [passkeyBusy, setPasskeyBusy] = useState(false);

  /** Passkey-only sign-in: usernameless — the authenticator offers its
   * discoverable credentials for this site and the user picks one. */
  const handlePasskeyLogin = async () => {
    setError(null);
    setPasskeyBusy(true);
    try {
      const { ceremony_id, options } = await api.auth.startPasskeyLogin();
      const assertion = await getPasskeyAssertion(options);
      await api.auth.finishPasskeyLogin({ ceremony_id, ...assertion });
      router.push('/unlock');
    } catch (err: any) {
      // The DOM API throws on user cancellation — keep that silent.
      if (err?.name === 'NotAllowedError') {
        setError(null);
      } else {
        setError(err.message);
      }
    } finally {
      setPasskeyBusy(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      if (awaiting2fa) {
        await api.auth.challenge2fa(code.trim());
        router.push('/unlock');
        return;
      }
      const res = await api.auth.login({ email, password });
      if (res.two_factor_required) {
        setAwaiting2fa(true);
        setCode('');
      } else {
        router.push('/unlock');
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="mx-auto mt-10 flex min-h-[calc(100vh-5rem)] max-w-md flex-col justify-center">
      <div className="card p-8">
        <div className="icon-disc mx-auto !h-11 !w-11">
          {awaiting2fa ? (
            <ShieldCheck className="h-5 w-5 text-white" />
          ) : (
            <Lock className="h-5 w-5 text-white" />
          )}
        </div>
        <h1 className="mt-5 text-center text-2xl font-bold tracking-tight">
          {awaiting2fa ? 'Two-factor required' : 'Welcome back'}
        </h1>
        <p className="mt-1.5 text-center text-sm text-muted-foreground">
          {awaiting2fa
            ? `Enter the 6-digit code from your authenticator app for ${email}.`
            : 'Sign in to your account to unlock your vault.'}
        </p>

        {error && <div className="alert-error mt-5">{error}</div>}

        <form onSubmit={handleSubmit} className="mt-6 space-y-4">
          {awaiting2fa ? (
            <>
              <div>
                <label className="label" htmlFor="code">Authenticator code</label>
                <input
                  id="code"
                  type="text"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  autoFocus
                  required
                  maxLength={6}
                  value={code}
                  onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
                  className="input text-center font-mono text-lg tracking-[0.4em]"
                  placeholder="000000"
                />
              </div>
              <button type="submit" disabled={loading || code.length !== 6} className="btn-primary w-full">
                {loading ? 'Verifying…' : 'Verify code'}
              </button>
              <button
                type="button"
                onClick={() => {
                  setAwaiting2fa(false);
                  setCode('');
                  setError(null);
                }}
                className="w-full cursor-pointer text-center text-xs text-muted-foreground hover:text-foreground"
              >
                ← Use a different account
              </button>
            </>
          ) : (
            <>
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
                <label className="label" htmlFor="password">Password</label>
                <input
                  id="password"
                  type="password"
                  required
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="input"
                  placeholder="••••••••••••"
                />
              </div>
              <button type="submit" disabled={loading} className="btn-primary w-full">
                {loading ? 'Signing in…' : 'Sign In'}
              </button>
              {passkeysSupported() && (
                <>
                  <div className="flex items-center gap-3 py-1">
                    <div className="h-px flex-1 bg-border" />
                    <span className="text-xs text-muted-foreground">or</span>
                    <div className="h-px flex-1 bg-border" />
                  </div>
                  <button
                    type="button"
                    onClick={handlePasskeyLogin}
                    disabled={passkeyBusy || loading}
                    className="btn-secondary w-full"
                  >
                    <Fingerprint className="h-4 w-4" />
                    {passkeyBusy ? 'Waiting for authenticator…' : 'Sign in with passkey'}
                  </button>
                </>
              )}
            </>
          )}
        </form>
      </div>

      {!awaiting2fa && (
        <p className="mt-6 text-center text-sm text-muted-foreground">
          New here?{' '}
          <Link href="/register" className="font-medium text-white hover:underline">
            Create a vault
          </Link>
        </p>
      )}
    </div>
  );
}
