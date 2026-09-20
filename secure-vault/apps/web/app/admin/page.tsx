'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { api, type AdminOverview } from '@/lib/api';
import { AdminShell } from '@/components/admin/AdminShell';
import { EventFeed } from '@/components/admin/EventFeed';
import { useAuthStore } from '@/hooks/useAuth';
import {
  Users,
  ShieldCheck,
  MonitorSmartphone,
  History,
  Database,
  UserPlus,
  Activity,
  RefreshCw,
} from 'lucide-react';

export default function AdminOverviewPage() {
  const { user: me } = useAuthStore();
  const [data, setData] = useState<AdminOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = () => {
    if (me?.role !== 'admin') return;
    setLoading(true);
    setError(null);
    api.admin
      .overview()
      .then(setData)
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  };

  // Only fetch server-side data once the session role is confirmed as admin.
  useEffect(load, [me?.role]);

  const stats = data
    ? [
        { label: 'Users', value: data.totals.users, icon: Users, tint: 'bg-primary/10 text-primary' },
        { label: 'Admins', value: data.totals.admins, icon: ShieldCheck, tint: 'bg-rose-500/10 text-rose-400' },
        { label: 'Active sessions', value: data.totals.active_sessions, icon: MonitorSmartphone, tint: 'bg-sky-500/10 text-sky-400' },
        { label: 'Active devices', value: data.totals.active_devices, icon: History, tint: 'bg-teal-500/10 text-teal-400' },
        { label: 'Vault syncs', value: data.totals.vault_syncs, icon: Database, tint: 'bg-violet-500/10 text-violet-400' },
        { label: 'Signups · 24h', value: data.totals.signups_24h, icon: UserPlus, tint: 'bg-emerald-500/10 text-emerald-400' },
        { label: 'Events · 24h', value: data.totals.events_24h, icon: Activity, tint: 'bg-orange-500/10 text-orange-400' },
        { label: 'Events · total', value: data.totals.events_total, icon: History, tint: 'bg-secondary/60 text-muted-foreground' },
      ]
    : [];

  return (
    <AdminShell
      active="overview"
      title="Data Overview"
      subtitle="What is happening across the system — accounts, sessions, sync activity and the audit trail."
    >
      {error && <div className="alert-error">{error}</div>}

      {loading && !data ? (
        <div className="card flex items-center justify-center p-14 text-sm text-muted-foreground">
          <span className="animate-pulse">Loading overview…</span>
        </div>
      ) : (
        <div className="space-y-8">
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            {stats.map((stat) => (
              <div key={stat.label} className="card flex items-center gap-4 p-5">
                <div className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-xl ${stat.tint}`}>
                  <stat.icon className="h-5 w-5" />
                </div>
                <div className="min-w-0">
                  <div className="text-2xl font-bold tracking-tight">{stat.value}</div>
                  <div className="truncate text-xs text-muted-foreground">{stat.label}</div>
                </div>
              </div>
            ))}
          </div>

          <section>
            <div className="mb-3 flex items-center justify-between">
              <div>
                <h2 className="text-lg font-semibold tracking-tight">Recent activity</h2>
                <p className="text-sm text-muted-foreground">
                  Latest entries in the audit log, newest first.
                </p>
              </div>
              <div className="flex items-center gap-2">
                <button onClick={load} className="btn-ghost px-3 py-2 text-xs" disabled={loading}>
                  <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
                  Refresh
                </button>
                <Link href="/admin/audit" className="btn-primary px-3 py-2 text-xs">
                  Full audit log
                </Link>
              </div>
            </div>
            {data && <EventFeed events={data.recent_events} />}
          </section>

          <section className="card border-dashed p-5 text-sm leading-relaxed text-muted-foreground">
            <span className="font-medium text-foreground">What you can and can&apos;t see here:</span>{' '}
            The admin console observes accounts, sessions, devices, vault sync
            sizes/versions and every audit event — including admin actions like
            role changes, which are logged with the actor and target. Because
            SecureVault is zero-knowledge, the server never stores decrypted
            vault items, so individual entries are not visible on this side by
            design; each sync appears as a versioned ciphertext snapshot.
          </section>
        </div>
      )}
    </AdminShell>
  );
}
