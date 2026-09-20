'use client';

import type { AuditEvent } from '@/lib/api';
import { eventTone, formatTime } from '@/components/admin/eventMeta';

function MetadataPreview({ metadata }: { metadata: AuditEvent['metadata'] }) {
  if (!metadata) return null;
  const text = JSON.stringify(metadata);
  return (
    <span className="mt-1 block truncate font-mono text-[11px] text-muted-foreground/70" title={text}>
      {text}
    </span>
  );
}

export function EventFeed({ events, empty }: { events: AuditEvent[]; empty?: string }) {
  if (events.length === 0) {
    return (
      <div className="card flex items-center justify-center border-dashed p-10 text-sm text-muted-foreground">
        {empty ?? 'No events recorded yet.'}
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {events.map((event) => (
        <div key={event.id} className="card flex items-start gap-3.5 p-4">
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <span
                className={`inline-flex items-center rounded-md border px-2 py-0.5 font-mono text-[11px] font-semibold ${eventTone(event.event_type)}`}
              >
                {event.event_type}
              </span>
              <span className="truncate text-sm font-medium">{event.email}</span>
            </div>
            <MetadataPreview metadata={event.metadata} />
          </div>
          <span className="shrink-0 pt-0.5 text-xs text-muted-foreground">
            {formatTime(event.created_at)}
          </span>
        </div>
      ))}
    </div>
  );
}
