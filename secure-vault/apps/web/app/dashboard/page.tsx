'use client';

import { useVaultStore } from '@/hooks/useVault';
import { useAuthStore } from '@/hooks/useAuth';
import { getPasswordStrength } from '@/lib/crypto';
import Link from 'next/link';
import {
  KeyRound,
  ShieldCheck,
  AlertTriangle,
  Lock,
  ArrowRight,
  ChevronRight,
  Radar,
  Sparkles,
  Shield,
  Repeat,
} from 'lucide-react';

export default function DashboardPage() {
  const { isLocked, items } = useVaultStore();
  const { user } = useAuthStore();

  const withPasswords = items.filter((i) => i.password);
  const strong = withPasswords.filter((i) =>
    ['Strong', 'Very Strong'].includes(getPasswordStrength(i.password!).label)
  ).length;
  const weak = withPasswords.filter((i) =>
    ['Very Weak', 'Weak'].includes(getPasswordStrength(i.password!).label)
  ).length;

  // Same heuristic as the Security Center: reused passwords share identical values.
  const seen = new Set<string>();
  let reused = 0;
  for (const item of withPasswords) {
    const key = item.password!.toLowerCase();
    if (seen.has(key)) reused += 1;
    else seen.add(key);
  }

  const score =
    items.length === 0
      ? 100
      : Math.max(0, 100 - weak * 8 - reused * 5 - (items.length - withPasswords.length) * 3);
  const scoreColor =
    score >= 80 ? 'text-emerald-400' : score >= 50 ? 'text-amber-400' : 'text-red-400';

  const recent = [...items]
    .sort((a, b) => (a.updated_at < b.updated_at ? 1 : -1))
    .slice(0, 5);

  const firstName = user?.email.split('@')[0] ?? 'there';

  if (isLocked) {
    return (
      <div className="space-y-8">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Security Overview</h1>
          <p className="mt-1.5 text-muted-foreground">Your security at a glance.</p>
        </div>
          <div className="card flex flex-col items-center gap-4 p-16 text-center">
          <div className="icon-disc !h-12 !w-12">
            <Lock className="h-5 w-5 text-white" />
          </div>
          <div>
            <p className="font-medium">Your vault is locked</p>
            <p className="mt-1 text-sm text-muted-foreground">
              Enter your master password to view your security overview.
            </p>
          </div>
          <Link href="/unlock" className="btn-primary mt-2">
            Unlock Vault
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">
          Welcome back, {firstName}
        </h1>
        <p className="mt-1.5 text-muted-foreground">
          {items.length === 0
            ? 'Your vault is ready — add your first credential to get started.'
            : `Your vault holds ${items.length} credential${items.length === 1 ? '' : 's'}, decrypted locally.`}
        </p>
      </div>

      {/* Central area flanked by smaller side panels (lg and up). On smaller
          screens the center panel flows first. */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[260px_minmax(0,1fr)_260px]">
        {/* ---- Left side panel: security score ---- */}
        <div className="order-2 flex flex-col gap-4 lg:order-1">
          <div className="card flex flex-col items-center p-6 text-center">
            <div className={`text-5xl font-bold tracking-tight ${scoreColor}`}>{score}</div>
            <div className="mt-1 text-xs text-muted-foreground">Security Score</div>
            <div className="mt-4 h-1.5 w-full overflow-hidden rounded-full bg-white/10">
              <div
                className={`h-full rounded-full transition-all ${
                  score >= 80 ? 'bg-emerald-400' : score >= 50 ? 'bg-silver' : 'bg-red-500'
                }`}
                style={{ width: `${score}%` }}
              />
            </div>
            <Link
              href="/security"
              className="mt-4 inline-flex items-center gap-1 text-xs font-medium text-white hover:underline"
            >
              <Shield className="h-3 w-3" /> Security Center
            </Link>
          </div>

          <div className="card divide-y divide-border/60 p-2">
            {[
              { label: 'Strong', value: strong, icon: ShieldCheck, tint: 'text-emerald-400' },
              { label: 'Weak', value: weak, icon: AlertTriangle, tint: 'text-orange-400' },
              { label: 'Reused', value: reused, icon: Repeat, tint: 'text-amber-400' },
            ].map((row) => (
              <div key={row.label} className="flex items-center justify-between px-3 py-2.5">
                <span className="flex items-center gap-2 text-xs text-muted-foreground">
                  <row.icon className={`h-3.5 w-3.5 ${row.tint}`} />
                  {row.label}
                </span>
                <span className="text-sm font-semibold">{row.value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* ---- Central large area: vault + recent accounts ---- */}
        <div className="order-1 flex flex-col gap-4 lg:order-2">
          <div className="card relative overflow-hidden p-6">
            <div
              aria-hidden
              className="pointer-events-none absolute inset-0 bg-[radial-gradient(60%_60%_at_15%_0%,rgba(255,255,255,0.08),transparent_70%)]"
            />
            <div className="relative flex flex-wrap items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="icon-disc !h-11 !w-11">
                  <KeyRound className="h-5 w-5 text-white" />
                </div>
                <div>
                  <p className="text-sm font-semibold">Vault pulse</p>
                  <p className="text-xs text-muted-foreground">
                    {items.length === 0
                      ? 'No credentials stored yet'
                      : `${strong} of ${withPasswords.length || 0} saved passwords rated strong`}
                  </p>
                </div>
              </div>
              <div className="flex gap-2">
                <Link href="/vault/new" className="btn-primary">
                  Add Account
                  <ArrowRight className="h-4 w-4" />
                </Link>
              </div>
            </div>
          </div>

          <div className="card flex-1 p-6">
            <div className="flex flex-wrap items-center justify-between gap-4">
              <h2 className="text-lg font-semibold tracking-tight">Recent accounts</h2>
              <Link
                href="/vault"
                className="inline-flex items-center gap-1 text-xs font-medium text-white hover:underline"
              >
                View all <ChevronRight className="h-3 w-3" />
              </Link>
            </div>

            {recent.length === 0 ? (
              <p className="mt-4 rounded-xl border border-dashed border-border px-4 py-8 text-center text-sm text-muted-foreground">
                Nothing here yet. Add your first credential to populate your vault.
              </p>
            ) : (
              <div className="mt-3 divide-y divide-border/60">
                {recent.map((item) => (
                  <Link
                    key={item.id}
                    href={`/vault/${item.id}`}
                    className="flex items-center gap-3 py-3 transition-colors hover:bg-accent/50"
                  >
                    <div className="icon-disc !h-9 !w-9 text-sm font-bold text-white">
                      {item.title.charAt(0).toUpperCase()}
                    </div>
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm font-medium">{item.title}</p>
                      {item.username && (
                        <p className="truncate text-xs text-muted-foreground">{item.username}</p>
                      )}
                    </div>
                    <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground" />
                  </Link>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* ---- Right side panel: monitor + tools ---- */}
        <div className="order-3 flex flex-col gap-4">
          <Link
            href="/monitor"
            className="card group relative overflow-hidden p-6 transition-colors hover:border-white/20"
          >
            <div className="icon-disc">
              <Radar className="h-5 w-5 text-white" />
            </div>
            <p className="mt-3 text-sm font-semibold">Dark Web Monitor</p>
            <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
              Check your email and passwords against public breach corpora.
            </p>
            <span className="mt-3 inline-flex items-center gap-1 text-xs font-medium text-white">
              Run a scan
              <ArrowRight className="h-3 w-3 transition-transform group-hover:translate-x-0.5" />
            </span>
          </Link>

          <Link
            href="/generator"
            className="card group p-6 transition-colors hover:border-white/20"
          >
            <div className="icon-disc">
              <Sparkles className="h-5 w-5 text-white" />
            </div>
            <p className="mt-3 text-sm font-semibold">Generator</p>
            <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
              Create a cryptographically secure password in one click.
            </p>
          </Link>
        </div>
      </div>
    </div>
  );
}
