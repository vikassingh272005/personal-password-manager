'use client';

import { useEffect, useState } from 'react';
import { api, type AdminUser } from '@/lib/api';
import { AdminShell } from '@/components/admin/AdminShell';
import { useAuthStore } from '@/hooks/useAuth';
import { formatTime } from '@/components/admin/eventMeta';
import { cn } from '@/lib/crypto';
import { RefreshCw, ShieldCheck, User as UserIcon, Ban, LogOut } from 'lucide-react';

export default function AdminUsersPage() {
  const { user: me } = useAuthStore();
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const load = () => {
    if (me?.role !== 'admin') return;
    setLoading(true);
    setError(null);
    api.admin
      .users()
      .then(setUsers)
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  };

  // Only fetch server-side data once the session role is confirmed as admin.
  useEffect(load, [me?.role]);

  const run = async (id: string, action: () => Promise<unknown>, confirmMsg: string) => {
    if (!confirm(confirmMsg)) return;
    setBusy(id);
    setError(null);
    try {
      await action();
      await api.admin.users().then(setUsers);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Action failed');
    } finally {
      setBusy(null);
    }
  };

  const toggleRole = (u: AdminUser) =>
    run(
      u.id,
      () => api.admin.setRole(u.id, u.role === 'admin' ? 'user' : 'admin'),
      u.role === 'admin'
        ? `Demote ${u.email} to a regular user?`
        : `Grant ${u.email} the admin role?`
    );

  const revokeSessions = (u: AdminUser) =>
    run(u.id, () => api.admin.revokeSessions(u.id), `Sign out every session for ${u.email}?`);

  return (
    <AdminShell
      active="users"
      title="Users & Access"
      subtitle="Every account on the server. Promote or demote roles and revoke sessions to control access."
    >
      {error && <div className="alert-error">{error}</div>}

      <div className="flex items-center justify-end">
        <button onClick={load} className="btn-ghost px-3 py-2 text-xs" disabled={loading}>
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {loading && users.length === 0 ? (
        <div className="card flex items-center justify-center p-14 text-sm text-muted-foreground">
          <span className="animate-pulse">Loading users…</span>
        </div>
      ) : (
        <div className="card overflow-x-auto">
          <table className="w-full min-w-[760px] text-left text-sm">
            <thead>
              <tr className="border-b border-border text-xs uppercase tracking-wide text-muted-foreground">
                <th className="px-5 py-3 font-medium">Account</th>
                <th className="px-3 py-3 font-medium">Created</th>
                <th className="px-3 py-3 font-medium">Last active</th>
                <th className="px-3 py-3 text-center font-medium">Devices</th>
                <th className="px-3 py-3 text-center font-medium">Sessions</th>
                <th className="px-3 py-3 text-center font-medium">Syncs</th>
                <th className="px-5 py-3 text-right font-medium">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {users.map((u) => {
                const isSelf = me?.user_id === u.id;
                return (
                  <tr key={u.id} className="transition-colors hover:bg-accent/40">
                    <td className="px-5 py-3.5">
                      <div className="flex items-center gap-2.5">
                        <div
                          className={cn(
                            'flex h-8 w-8 shrink-0 items-center justify-center rounded-lg',
                            u.role === 'admin' ? 'bg-rose-500/10' : 'bg-secondary'
                          )}
                        >
                          {u.role === 'admin' ? (
                            <ShieldCheck className="h-4 w-4 text-rose-400" />
                          ) : (
                            <UserIcon className="h-4 w-4 text-muted-foreground" />
                          )}
                        </div>
                        <div className="min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="truncate font-medium">{u.email}</span>
                            {isSelf && (
                              <span className="rounded-md bg-primary/10 px-1.5 py-0.5 text-[10px] font-semibold text-primary">
                                you
                              </span>
                            )}
                          </div>
                          <div className="mt-0.5 flex items-center gap-1.5 text-[11px] text-muted-foreground">
                            <span
                              className={cn(
                                'rounded px-1.5 py-px font-mono uppercase tracking-wide',
                                u.role === 'admin'
                                  ? 'bg-rose-500/15 text-rose-400'
                                  : 'bg-secondary text-muted-foreground'
                              )}
                            >
                              {u.role}
                            </span>
                            <span
                              title={
                                u.two_factor_enabled
                                  ? 'TOTP two-factor authentication is active'
                                  : 'Two-factor authentication is not enabled'
                              }
                              className={cn(
                                'rounded px-1.5 py-px font-mono uppercase tracking-wide',
                                u.two_factor_enabled
                                  ? 'bg-emerald-500/15 text-emerald-400'
                                  : 'bg-secondary text-muted-foreground/70'
                              )}
                            >
                              {u.two_factor_enabled ? '2FA on' : '2FA off'}
                            </span>
                            {u.vault_version != null && (
                              <span>vault v{u.vault_version}</span>
                            )}
                          </div>
                        </div>
                      </div>
                    </td>
                    <td className="whitespace-nowrap px-3 py-3.5 text-xs text-muted-foreground">
                      {formatTime(u.created_at)}
                    </td>
                    <td className="whitespace-nowrap px-3 py-3.5 text-xs text-muted-foreground">
                      {u.last_active_at ? formatTime(u.last_active_at) : '—'}
                    </td>
                    <td className="px-3 py-3.5 text-center text-xs">{u.device_count}</td>
                    <td className="px-3 py-3.5 text-center text-xs">{u.session_count}</td>
                    <td className="px-3 py-3.5 text-center text-xs">{u.sync_count}</td>
                    <td className="whitespace-nowrap px-5 py-3.5 text-right">
                      {isSelf ? (
                        <span className="text-xs text-muted-foreground">
                          you can&apos;t change your own access
                        </span>
                      ) : (
                        <div className="flex items-center justify-end gap-2">
                          <button
                            onClick={() => toggleRole(u)}
                            disabled={busy === u.id}
                            className="btn-ghost px-2.5 py-1.5 text-xs"
                          >
                            {u.role === 'admin' ? (
                              <>
                                <Ban className="h-3.5 w-3.5" />
                                Demote
                              </>
                            ) : (
                              <>
                                <ShieldCheck className="h-3.5 w-3.5" />
                                Make admin
                              </>
                            )}
                          </button>
                          <button
                            onClick={() => revokeSessions(u)}
                            disabled={busy === u.id || u.session_count === 0}
                            className="btn-danger px-2.5 py-1.5 text-xs"
                          >
                            <LogOut className="h-3.5 w-3.5" />
                            Revoke sessions
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      <section className="card border-dashed p-5 text-sm leading-relaxed text-muted-foreground">
        <span className="font-medium text-foreground">Control &amp; audit:</span> role changes and
        session revocations are themselves written to the audit log with your
        identity and the target account, so every administrative action is
        traceable. Accounts are never hard-deleted from this console — deleting
        would cascade away their audit history.
      </section>
    </AdminShell>
  );
}
