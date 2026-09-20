'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import {
  Radar,
  Lock,
  ShieldCheck,
  ShieldAlert,
  Search,
  Loader2,
  AlertTriangle,
  KeyRound,
  RefreshCw,
  ExternalLink,
  Database,
} from 'lucide-react';
import { useVaultStore } from '@/hooks/useVault';
import { useAuthStore } from '@/hooks/useAuth';
import { scanEmail, checkPasswordBreachCount, type EmailBreach } from '@/lib/breaches';

type ScanState = 'idle' | 'scanning' | 'done' | 'error';

interface EmailScan {
  email: string;
  breaches: EmailBreach[];
}

interface PasswordScan {
  total: number;
  scanned: number;
  pwned: { id: string; title: string; count: number }[];
}

function formatDate(value?: string): string | null {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

export default function MonitorPage() {
  const { isLocked, items } = useVaultStore();
  const { user } = useAuthStore();

  const [emailScan, setEmailScan] = useState<ScanState>('idle');
  const [emailError, setEmailError] = useState<string | null>(null);
  const [emailResult, setEmailResult] = useState<EmailScan | null>(null);
  const [customEmail, setCustomEmail] = useState('');

  const [pwScan, setPwScan] = useState<ScanState>('idle');
  const [pwError, setPwError] = useState<string | null>(null);
  const [pwResult, setPwResult] = useState<PasswordScan | null>(null);

  const runEmailScan = useCallback(async (target: string) => {
    setEmailScan('scanning');
    setEmailError(null);
    try {
      const result = await scanEmail(target);
      setEmailResult(result);
      setEmailScan('done');
    } catch (err) {
      setEmailError(err instanceof Error ? err.message : 'Scan failed');
      setEmailScan('error');
    }
  }, []);

  // Auto-scan the signed-in account email once identity is known.
  useEffect(() => {
    if (!isLocked && user?.email && emailScan === 'idle') {
      runEmailScan(user.email);
    }
  }, [isLocked, user?.email, emailScan, runEmailScan]);

  const runPasswordScan = useCallback(async () => {
    const withPasswords = items.filter((i) => i.password);
    setPwScan('scanning');
    setPwError(null);
    const pwned: PasswordScan['pwned'] = [];
    setPwResult({ total: withPasswords.length, scanned: 0, pwned: [] });
    try {
      let scanned = 0;
      for (const item of withPasswords) {
        const count = await checkPasswordBreachCount(item.password!);
        if (count > 0) pwned.push({ id: item.id, title: item.title, count });
        scanned += 1;
        setPwResult({ total: withPasswords.length, scanned, pwned: [...pwned] });
      }
      setPwScan('done');
    } catch (err) {
      setPwError(err instanceof Error ? err.message : 'Password scan failed');
      setPwScan('error');
    }
  }, [items]);

  const totalBreaches = emailResult?.breaches.length ?? 0;
  const exposedClasses = Array.from(
    new Set(emailResult?.breaches.flatMap((b) => b.xposed_data ?? []) ?? [])
  );

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Dark Web Monitor</h1>
        <p className="mt-1.5 text-muted-foreground">
          Checks your email and saved passwords against public breach corpora.
          Lookups are privacy-preserving — full passwords and vault data never leave this browser.
        </p>
      </div>

      {isLocked ? (
        <div className="card flex flex-col items-center gap-4 p-16 text-center">
          <div className="icon-disc !h-12 !w-12">
            <Lock className="h-5 w-5 text-white" />
          </div>
          <div>
            <p className="font-medium">Your vault is locked</p>
            <p className="mt-1 text-sm text-muted-foreground">
              Unlock your vault to scan its passwords against known breaches.
            </p>
          </div>
          <Link href="/unlock" className="btn-primary mt-2">
            Unlock Vault
          </Link>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
          {/* Email exposure — central hero panel */}
          <div className="card p-6 lg:col-span-2">
            <div className="flex items-start justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="icon-disc">
                  <Radar className="h-5 w-5 text-white" />
                </div>
                <div>
                  <h2 className="font-semibold tracking-tight">Email exposure</h2>
                  <p className="text-sm text-muted-foreground">
                    {user?.email ?? 'Loading your account email…'}
                  </p>
                </div>
              </div>
              <button
                onClick={() => user?.email && runEmailScan(user.email)}
                disabled={!user?.email || emailScan === 'scanning'}
                className="btn-ghost shrink-0 px-3 py-2 text-xs"
              >
                <RefreshCw className={`h-3.5 w-3.5 ${emailScan === 'scanning' ? 'animate-spin' : ''}`} />
                Re-scan
              </button>
            </div>

            <div className="mt-5">
              {emailScan === 'scanning' && (
                <div className="flex items-center gap-3 rounded-2xl border border-white/10 bg-white/[0.04] px-4 py-5 text-sm text-muted-foreground">
                  <Loader2 className="h-4 w-4 animate-spin text-white" />
                  Scanning breach indexes…
                </div>
              )}

              {emailScan === 'error' && (
                <div className="alert-error flex items-center justify-between gap-3">
                  <span>{emailError}</span>
                  <button
                    onClick={() => user?.email && runEmailScan(user.email)}
                    className="shrink-0 text-xs font-medium underline underline-offset-2"
                  >
                    Retry
                  </button>
                </div>
              )}

              {emailScan === 'done' && emailResult && (
                <div
                  className={`rounded-xl border px-4 py-4 ${
                    totalBreaches > 0
                      ? 'border-red-500/20 bg-red-500/10'
                      : 'border-emerald-500/20 bg-emerald-500/10'
                  }`}
                >
                  <div className="flex items-center gap-2.5">
                    {totalBreaches > 0 ? (
                      <ShieldAlert className="h-5 w-5 shrink-0 text-red-400" />
                    ) : (
                      <ShieldCheck className="h-5 w-5 shrink-0 text-emerald-400" />
                    )}
                    <p className={`text-sm font-semibold ${totalBreaches > 0 ? 'text-red-300' : 'text-emerald-300'}`}>
                      {totalBreaches > 0
                        ? `Found in ${totalBreaches} known breach${totalBreaches === 1 ? '' : 'es'}`
                        : 'No known breaches for this email'}
                    </p>
                  </div>

                  {exposedClasses.length > 0 && (
                    <div className="mt-3 flex flex-wrap gap-1.5">
                      {exposedClasses.map((cls) => (
                        <span
                          key={cls}
                          className="rounded-full border border-border bg-card px-2.5 py-1 text-[11px] font-medium text-muted-foreground"
                        >
                          {cls}
                        </span>
                      ))}
                    </div>
                  )}

                  {emailResult.breaches.length > 0 && (
                    <div className="mt-4 space-y-2">
                      {emailResult.breaches.map((breach) => {
                        const date = formatDate(breach.breach_date);
                        return (
                          <div
                            key={breach.title}
                            className="flex items-center gap-3 rounded-lg bg-card/70 px-3 py-2.5"
                          >
                            <Database className="h-4 w-4 shrink-0 text-red-400/80" />
                            <div className="min-w-0 flex-1">
                              <p className="truncate text-sm font-medium">{breach.title}</p>
                              {date && (
                                <p className="text-xs text-muted-foreground">Breached {date}</p>
                              )}
                            </div>
                            {breach.domain && (
                              <span className="shrink-0 text-xs text-muted-foreground">{breach.domain}</span>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Scan any other email */}
            <form
              className="mt-5 flex gap-2"
              onSubmit={(e) => {
                e.preventDefault();
                if (customEmail.trim()) runEmailScan(customEmail);
              }}
            >
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <input
                  type="email"
                  value={customEmail}
                  onChange={(e) => setCustomEmail(e.target.value)}
                  placeholder="Check another email address…"
                  className="input pl-9"
                />
              </div>
              <button type="submit" disabled={emailScan === 'scanning' || !customEmail.trim()} className="btn-primary shrink-0">
                {emailScan === 'scanning' ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Scan'}
              </button>
            </form>
          </div>

          {/* Passwords side panel */}
          <div className="card flex flex-col p-6">
            <div className="flex items-center gap-3">
              <div className="icon-disc">
                <KeyRound className="h-5 w-5 text-white" />
              </div>
              <div>
                <h2 className="font-semibold tracking-tight">Saved passwords</h2>
                <p className="text-sm text-muted-foreground">Checked via k-anonymity</p>
              </div>
            </div>

            <div className="mt-5 flex-1">
              {pwScan === 'idle' && (
                <div className="flex h-full flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-border px-4 py-8 text-center">
                  <p className="text-sm text-muted-foreground">
                    Check every saved password against billions of breached credentials.
                  </p>
                  <button onClick={runPasswordScan} className="btn-primary mt-1 w-full">
                    Scan {items.filter((i) => i.password).length} password
                    {items.filter((i) => i.password).length === 1 ? '' : 's'}
                  </button>
                </div>
              )}

              {pwScan === 'scanning' && pwResult && (
                <div className="space-y-3">
                  <div className="flex items-center gap-2 text-sm text-muted-foreground">
                    <Loader2 className="h-4 w-4 animate-spin text-white" />
                    Scanning… {pwResult.pwned.length} flagged so far
                  </div>
                  <div className="h-1.5 overflow-hidden rounded-full bg-white/10">
                    <div
                      className="h-full rounded-full bg-silver transition-all"
                      style={{ width: `${pwResult.total ? (pwResult.scanned / pwResult.total) * 100 : 0}%` }}
                    />
                  </div>
                </div>
              )}

              {pwScan === 'error' && (
                <div className="alert-error text-xs">{pwError}</div>
              )}

              {pwScan === 'done' && pwResult && (
                <div>
                  <div
                    className={`rounded-xl border px-4 py-3 ${
                      pwResult.pwned.length > 0
                        ? 'border-orange-500/20 bg-orange-500/10'
                        : 'border-emerald-500/20 bg-emerald-500/10'
                    }`}
                  >
                    <p className={`text-sm font-semibold ${pwResult.pwned.length > 0 ? 'text-orange-300' : 'text-emerald-300'}`}>
                      {pwResult.pwned.length > 0
                        ? `${pwResult.pwned.length} of ${pwResult.total} passwords exposed`
                        : 'All saved passwords are clean'}
                    </p>
                  </div>
                  {pwResult.pwned.length > 0 && (
                    <div className="mt-3 space-y-1.5">
                      {pwResult.pwned.map((p) => (
                        <Link
                          key={p.id}
                          href={`/vault/${p.id}`}
                          className="flex items-center justify-between gap-2 rounded-lg px-2.5 py-2 transition-colors hover:bg-accent"
                        >
                          <span className="truncate text-sm">{p.title}</span>
                          <span className="shrink-0 rounded-full bg-orange-500/15 px-2 py-0.5 text-[11px] font-semibold text-orange-300">
                            ×{p.count.toLocaleString()}
                          </span>
                        </Link>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>

            <p className="mt-4 flex items-start gap-1.5 text-[11px] leading-relaxed text-muted-foreground">
              <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0" />
              Only a 5-character hash prefix is sent for password checks; the
              password itself stays local.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
