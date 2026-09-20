export const EVENT_TYPES = [
  'USER_REGISTERED',
  'LOGIN_SUCCESS',
  'LOGIN_FAILED',
  'LOGOUT',
  'VAULT_UPDATED',
  'DEVICE_ADDED',
  'DEVICE_REVOKED',
  'ADMIN_ROLE_CHANGED',
  'ADMIN_SESSIONS_REVOKED',
] as const;

const TONES: Record<string, string> = {
  USER_REGISTERED: 'border-emerald-500/25 bg-emerald-500/10 text-emerald-400',
  LOGIN_SUCCESS: 'border-sky-500/25 bg-sky-500/10 text-sky-400',
  LOGIN_FAILED: 'border-orange-500/25 bg-orange-500/10 text-orange-400',
  LOGOUT: 'border-border bg-secondary/60 text-muted-foreground',
  VAULT_UPDATED: 'border-violet-500/25 bg-violet-500/10 text-violet-400',
  DEVICE_ADDED: 'border-teal-500/25 bg-teal-500/10 text-teal-400',
  DEVICE_REVOKED: 'border-yellow-500/25 bg-yellow-500/10 text-yellow-400',
  ADMIN_ROLE_CHANGED: 'border-red-500/30 bg-red-500/15 text-red-400',
  ADMIN_SESSIONS_REVOKED: 'border-red-500/30 bg-red-500/15 text-red-400',
};

export function eventTone(eventType: string): string {
  return TONES[eventType] ?? 'border-border bg-secondary/60 text-muted-foreground';
}


export function formatTime(iso: string): string {
  return new Date(iso).toLocaleString();
}
