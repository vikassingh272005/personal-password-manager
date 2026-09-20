'use client';

import Link from 'next/link';
import { useAuthStore } from '@/hooks/useAuth';
import { cn } from '@/lib/crypto';
import { Activity, ShieldAlert, Users, ScrollText, Lock, AlertTriangle } from 'lucide-react';

const tabs = [
  { name: 'Overview', href: '/admin', icon: Activity },
  { name: 'Users', href: '/admin/users', icon: Users },
  { name: 'Audit Log', href: '/admin/audit', icon: ScrollText },
];

const activeHrefs: Record<string, string> = {
  overview: '/admin',
  users: '/admin/users',
  audit: '/admin/audit',
};

export function AdminShell({
  active,
  title,
  subtitle,
  children,
}: {
  active: 'overview' | 'users' | 'audit';
  title: string;
  subtitle: string;
  children: React.ReactNode;
}) {
  // Identity is resolved by the Sidebar (it re-checks on every route change),
  // so by the time this renders on the client the role is known.
  const { user, loading } = useAuthStore();

  let body: React.ReactNode;

  if (loading && !user) {
    body = (
      <div className="card flex items-center justify-center gap-3 p-16 text-sm text-muted-foreground">
        <span className="animate-pulse">Checking session…</span>
      </div>
    );
  } else if (!user) {
    body = (
      <div className="card flex flex-col items-center gap-4 p-16 text-center">
        <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-primary/10">
          <Lock className="h-5 w-5 text-primary" />
        </div>
        <div>
          <p className="font-medium">Sign in required</p>
          <p className="mt-1 text-sm text-muted-foreground">
            The admin console needs an authenticated session.
          </p>
        </div>
        <Link href="/login" className="btn-primary mt-2">
          Go to Sign In
        </Link>
      </div>
    );
  } else if (user.role !== 'admin') {
    body = (
      <div className="card flex flex-col items-center gap-4 p-16 text-center">
        <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-orange-500/10">
          <ShieldAlert className="h-5 w-5 text-orange-400" />
        </div>
        <div>
          <p className="font-medium">Admin access required</p>
          <p className="mx-auto mt-1 max-w-md text-sm leading-relaxed text-muted-foreground">
            Your account has the role “user”. Ask an existing admin to promote
            you, or list your email in the server’s <code>ADMIN_EMAILS</code>{' '}
            environment variable and sign in again.
          </p>
        </div>
        <Link href="/dashboard" className="btn-ghost mt-2">
          Back to Dashboard
        </Link>
      </div>
    );
  } else {
    body = (
      <div className="space-y-6">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">{title}</h1>
          <p className="mt-1.5 text-muted-foreground">{subtitle}</p>
        </div>
        <div className="flex items-center gap-1.5 rounded-xl border border-border bg-card/60 p-1.5">
          {tabs.map((tab) => {
            const isActive = tab.href === activeHrefs[active];
            return (
              <Link
                key={tab.href}
                href={tab.href}
                className={cn(
                  'flex items-center gap-2 rounded-lg px-3.5 py-2 text-sm font-medium transition-colors',
                  isActive
                    ? 'bg-primary/10 text-primary'
                    : 'text-muted-foreground hover:bg-accent hover:text-foreground'
                )}
              >
                <tab.icon className="h-4 w-4" />
                {tab.name}
              </Link>
            );
          })}
        </div>
        {children}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {user?.role === 'admin' && (
        <div className="flex items-center gap-2 rounded-xl border border-primary/20 bg-primary/5 px-4 py-2.5 text-xs text-primary/90">
          <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
          Server-side admin console — you are seeing accounts, sessions, sync
          activity and the audit trail. Vault contents stay end-to-end encrypted
          and are never visible here.
        </div>
      )}
      {body}
    </div>
  );
}
