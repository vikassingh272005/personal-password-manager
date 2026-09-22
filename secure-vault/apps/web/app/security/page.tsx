'use client';

import { useVaultStore } from '@/hooks/useVault';
import { getPasswordStrength } from '@/lib/crypto';
import { KeyRound, ShieldCheck, AlertTriangle, Repeat, CheckCircle2, Lock } from 'lucide-react';
import Link from 'next/link';

export default function SecurityPage() {
  const { items, isLocked } = useVaultStore();

  // The analysis only exists after local decryption — never show a misleading
  // "score 100" for data that isn't loaded (mirrors /dashboard and /monitor).
  if (isLocked) {
    return (
      <div className="rise space-y-8">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Security Center</h1>
          <p className="mt-1.5 text-muted-foreground">
            Password analysis happens locally after vault decryption. Nothing is sent to the server.
          </p>
        </div>
        <div className="card flex flex-col items-center gap-4 p-16 text-center">
          <div className="icon-disc !h-12 !w-12">
            <Lock className="h-5 w-5 text-white" />
          </div>
          <div>
            <p className="font-medium">Your vault is locked</p>
            <p className="mt-1 text-sm text-muted-foreground">
              Unlock to analyze password strength, reuse, and coverage.
            </p>
          </div>
          <Link href="/unlock" className="btn-primary mt-2">
            Unlock Vault
          </Link>
        </div>
      </div>
    );
  }

  const analysis = items.reduce(
    (acc, item) => {
      if (!item.password) {
        acc.missing += 1;
        return acc;
      }
      const strength = getPasswordStrength(item.password);
      const seen = item.password.toLowerCase();
      if (acc.passwordCounts.has(seen)) {
        acc.reused += 1;
      } else {
        acc.passwordCounts.set(seen, true);
      }
      if (strength.score <= 1) acc.weak += 1;
      else acc.strong += 1;
      return acc;
    },
    { strong: 0, weak: 0, reused: 0, missing: 0, passwordCounts: new Map() }
  );

  const total = items.length;
  const score = total === 0 ? 100 : Math.max(
    0,
    100 -
      analysis.weak * 8 -
      analysis.reused * 5 -
      analysis.missing * 3
  );

  const scoreColor =
    score >= 80 ? 'text-emerald-400' : score >= 50 ? 'text-amber-400' : 'text-red-400';
  const scoreBar =
    score >= 80 ? 'bg-emerald-500' : score >= 50 ? 'bg-amber-500' : 'bg-red-500';

  const stats = [
    { label: 'Accounts', value: total, icon: KeyRound, tint: 'bg-primary/10 text-primary' },
    { label: 'Strong Passwords', value: analysis.strong, icon: ShieldCheck, tint: 'bg-emerald-500/10 text-emerald-400' },
    { label: 'Weak Passwords', value: analysis.weak, icon: AlertTriangle, tint: 'bg-orange-500/10 text-orange-400' },
    { label: 'Reused Passwords', value: analysis.reused, icon: Repeat, tint: 'bg-amber-500/10 text-amber-400' },
  ];

  return (
    <div className="rise space-y-8">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Security Center</h1>
        <p className="mt-1.5 text-muted-foreground">
          Password analysis happens locally after vault decryption. Nothing is sent to the server.
        </p>
      </div>

      <div className="card p-8 text-center">
        <div className={`text-6xl font-bold tracking-tight ${scoreColor}`}>{score}</div>
        <div className="mt-2 text-sm text-muted-foreground">Security Score / 100</div>
        <div className="mx-auto mt-5 h-1.5 max-w-xs overflow-hidden rounded-full bg-secondary">
          <div
            className={`h-full rounded-full transition-all ${scoreBar}`}
            style={{ width: `${score}%` }}
          />
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {stats.map((stat) => (
          <div key={stat.label} className="card flex items-center gap-4 p-5">
            <div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-xl ${stat.tint}`}>
              <stat.icon className="h-5 w-5" />
            </div>
            <div>
              <div className="text-xl font-bold tracking-tight">{stat.value}</div>
              <div className="text-xs text-muted-foreground">{stat.label}</div>
            </div>
          </div>
        ))}
      </div>

      <div className="card p-6">
        <h2 className="text-lg font-semibold tracking-tight">Recommendations</h2>
        <div className="mt-4 space-y-3">
          {analysis.weak > 0 && (
            <div className="flex items-start gap-3 rounded-xl border border-orange-500/20 bg-orange-500/10 px-4 py-3 text-sm text-orange-300">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
              <span>
                {analysis.weak} weak {analysis.weak === 1 ? 'password' : 'passwords'} detected.
                Consider replacing them with the generator.
              </span>
            </div>
          )}
          {analysis.reused > 0 && (
            <div className="flex items-start gap-3 rounded-xl border border-amber-500/20 bg-amber-500/10 px-4 py-3 text-sm text-amber-300">
              <Repeat className="mt-0.5 h-4 w-4 shrink-0" />
              <span>
                {analysis.reused} reused {analysis.reused === 1 ? 'password' : 'passwords'} found.
                Reuse weakens security across accounts.
              </span>
            </div>
          )}
          {analysis.missing > 0 && (
            <div className="flex items-start gap-3 rounded-xl border border-orange-500/20 bg-orange-500/10 px-4 py-3 text-sm text-orange-300">
              <Lock className="mt-0.5 h-4 w-4 shrink-0" />
              <span>{analysis.missing} accounts missing passwords.</span>
            </div>
          )}
          {analysis.weak === 0 && analysis.reused === 0 && analysis.missing === 0 && (
            <div className="flex items-start gap-3 rounded-xl border border-emerald-500/20 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-300">
              <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" />
              <span>No issues detected in your vault.</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}