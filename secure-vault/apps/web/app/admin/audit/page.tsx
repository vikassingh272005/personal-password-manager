'use client';

import { useEffect, useState } from 'react';
import { api, type AdminAuditPage } from '@/lib/api';
import { AdminShell } from '@/components/admin/AdminShell';
import { EventFeed } from '@/components/admin/EventFeed';
import { useAuthStore } from '@/hooks/useAuth';
import { EVENT_TYPES } from '@/components/admin/eventMeta';
import { ChevronLeft, ChevronRight, FilterX, RefreshCw } from 'lucide-react';

const PAGE_SIZE = 50;

export default function AdminAuditPage() {
  const { user: me } = useAuthStore();
  const [page, setPage] = useState<AdminAuditPage | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [eventType, setEventType] = useState('');
  const [offset, setOffset] = useState(0);

  // Only fetch server-side data once the session role is confirmed as admin.
  useEffect(() => {
    if (me?.role !== 'admin') return;
    setLoading(true);
    setError(null);
    api.admin
      .audit({ limit: PAGE_SIZE, offset, event_type: eventType || undefined })
      .then(setPage)
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  }, [me?.role, eventType, offset]);

  const hasPrev = offset > 0;
  const hasNext = page ? offset + page.limit < page.total : false;

  return (
    <AdminShell
      active="audit"
      title="Audit Log"
      subtitle="Every recorded event, in order: logins, vault syncs, device changes and admin actions."
    >
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex items-center gap-2">
          <span className="text-xs font-medium text-muted-foreground">Event type</span>
          <select
            value={eventType}
            onChange={(e) => {
              setEventType(e.target.value);
              setOffset(0);
            }}
            className="input w-auto py-2 text-sm"
          >
            <option value="">All events</option>
            {EVENT_TYPES.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </div>
        {eventType && (
          <button
            onClick={() => {
              setEventType('');
              setOffset(0);
            }}
            className="btn-ghost px-3 py-2 text-xs"
          >
            <FilterX className="h-3.5 w-3.5" />
            Clear filter
          </button>
        )}
        <div className="ml-auto flex items-center gap-2">
          {page && (
            <span className="text-xs text-muted-foreground">
              {page.total.toLocaleString()} event{page.total === 1 ? '' : 's'}
              {eventType ? ` of type ${eventType}` : ''}
            </span>
          )}
          <button
            onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
            disabled={!hasPrev || loading}
            className="btn-ghost px-3 py-2 text-xs"
          >
            <ChevronLeft className="h-3.5 w-3.5" />
            Newer
          </button>
          <button
            onClick={() => setOffset(offset + PAGE_SIZE)}
            disabled={!hasNext || loading}
            className="btn-ghost px-3 py-2 text-xs"
          >
            Older
            <ChevronRight className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      {error && <div className="alert-error">{error}</div>}

      {loading && !page ? (
        <div className="card flex items-center justify-center p-14 text-sm text-muted-foreground">
          <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
          <span className="animate-pulse">Loading audit log…</span>
        </div>
      ) : (
        <EventFeed
          events={page?.events ?? []}
          empty={
            eventType
              ? `No ${eventType} events recorded.`
              : 'No events recorded yet — they appear as accounts sign in, sync and take admin actions.'
          }
        />
      )}
    </AdminShell>
  );
}
