const API_BASE = '/api/v1';

interface RequestOptions {
  method?: string;
  body?: unknown;
  headers?: Record<string, string>;
}

async function request<T>(endpoint: string, options: RequestOptions = {}): Promise<T> {
  const { method = 'GET', body, headers = {} } = options;

  const res = await fetch(`${API_BASE}${endpoint}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...headers,
    },
    body: body ? JSON.stringify(body) : undefined,
    credentials: 'include',
  });

  if (!res.ok) {
    const error = await res.json().catch(() => ({ error: 'Request failed' }));
    throw new Error(error.error || `HTTP ${res.status}`);
  }

  return res.json();
}

export interface Me {
  user_id: string;
  email: string;
  role: 'user' | 'admin';
  /** Whether TOTP two-factor authentication is active for this account. */
  totp_enabled: boolean;
}

/** A registered passkey (WebAuthn credential) on the account. */
export interface PasskeyInfo {
  id: string;
  name: string | null;
  created_at: string | null;
  last_used_at: string | null;
}

/** A wrapped copy of the vault encryption key (base64 over the wire). */
export interface KeyWrap {
  ciphertext: string;
  nonce: string;
}

/** Key material the server returns about the vault — everything the client
 * needs to derive its KEK and decrypt, without the secrets themselves. */
export interface VaultMeta {
  version: number;
  /** Latest encrypted snapshot; null until the vault has synced once. */
  ciphertext: string | null;
  nonce: string | null;
  updated_at: string | null;
  kdf_algorithm: string;
  kdf_memory: number;
  kdf_iterations: number;
  kdf_parallelism: number;
  kdf_salt: string;
  /** Legacy placeholder — not used by the v2 key hierarchy. */
  encrypted_vault_key: string;
  /** Wrapped VEK under the master-password KEK. Null on legacy vaults. */
  kek_wrap: KeyWrap | null;
  /** Wrapped VEK under the Secret Key recovery key. Null until a kit exists. */
  recovery_wrap: KeyWrap | null;
}

export interface AuditEvent {
  id: string;
  email: string;
  event_type: string;
  created_at: string;
  metadata: Record<string, unknown> | null;
}

export interface AdminOverview {
  totals: {
    users: number;
    admins: number;
    active_sessions: number;
    active_devices: number;
    vault_syncs: number;
    events_24h: number;
    events_total: number;
    signups_24h: number;
  };
  recent_events: AuditEvent[];
}

export interface AdminUser {
  id: string;
  email: string;
  role: 'user' | 'admin';
  created_at: string;
  last_active_at: string | null;
  device_count: number;
  session_count: number;
  sync_count: number;
  vault_version: number | null;
  vault_updated_at: string | null;
  two_factor_enabled: boolean;
}

export interface AdminAuditPage {
  total: number;
  limit: number;
  offset: number;
  events: AuditEvent[];
}

export const api = {
  auth: {
    register: (data: { email: string; password: string }) =>
      request<{
        user_id: string;
        email: string;
        role: string;
        message: string;
        kdf_algorithm: string;
        kdf_iterations: number;
        kdf_salt: string;
      }>('/auth/register', { method: 'POST', body: data }),
    login: (data: { email: string; password: string }) =>
      request<{
        user_id: string;
        email: string;
        role: string;
        message: string;
        /** True when the password half succeeded but a TOTP code is still
         * required (HTTP 202). The session cookie is already set but only
         * accepts POST /auth/2fa/challenge until the code is verified. */
        two_factor_required?: boolean;
      }>('/auth/login', { method: 'POST', body: data }),
    logout: () =>
      request<{ message: string }>('/auth/logout', { method: 'POST' }),
    refresh: () =>
      request<Me>('/auth/refresh', { method: 'GET' }),
    me: () =>
      request<Me>('/auth/me', { method: 'GET' }),
    /** Begin TOTP enrollment: returns the raw secret (manual entry) and the
     * otpauth:// URI to render as a QR code. The secret is pending until
     * verify2fa confirms a live code. */
    start2faSetup: () =>
      request<{ secret: string; otpauth_uri: string }>('/auth/2fa/setup', { method: 'POST' }),
    /** Confirm a code from the authenticator app to activate 2FA. */
    verify2fa: (code: string) =>
      request<{ enabled: boolean; message: string }>('/auth/2fa/verify', { method: 'POST', body: { code } }),
    /** Turn 2FA off — needs a current code AND the account password. */
    disable2fa: (code: string, password: string) =>
      request<{ enabled: boolean; message: string }>('/auth/2fa/disable', {
        method: 'POST',
        body: { code, password },
      }),
    /** Complete a half-login (202 from /auth/login) with the TOTP code. */
    challenge2fa: (code: string) =>
      request<{ user_id: string; email: string; message: string }>('/auth/2fa/challenge', {
        method: 'POST',
        body: { code },
      }),
    // ---- WebAuthn passkeys ----
    listPasskeys: () =>
      request<{ passkeys: PasskeyInfo[] }>('/auth/passkeys', { method: 'GET' }),
    revokePasskey: (id: string) =>
      request<{ revoked: boolean }>(`/auth/passkeys/${id}`, { method: 'DELETE' }),
    /** Begin adding a passkey: returns PublicKeyCredentialCreationOptions plus
     * the ceremony id that must accompany the finish call. */
    startPasskeyRegistration: () =>
      request<{ ceremony_id: string; options: PublicKeyCredentialCreationOptionsJSON }>(
        '/auth/passkeys/register/options',
        { method: 'POST' }
      ),
    finishPasskeyRegistration: (data: {
      ceremony_id: string;
      credential_id: string;
      attestation_object: string;
      client_data_json: string;
      name?: string;
    }) =>
      request<{ registered: boolean; message: string }>('/auth/passkeys/register/finish', {
        method: 'POST',
        body: data,
      }),
    /** Begin passkey sign-in. Empty email = usernameless (discoverable). */
    startPasskeyLogin: (email?: string) =>
      request<{ ceremony_id: string; options: PublicKeyCredentialRequestOptionsJSON }>(
        '/auth/passkeys/login/options',
        { method: 'POST', body: { email: email || null } }
      ),
    finishPasskeyLogin: (data: {
      ceremony_id: string;
      credential_id: string;
      authenticator_data: string;
      client_data_json: string;
      signature: string;
    }) =>
      request<{ user_id: string; email: string; role: string; message: string }>(
        '/auth/passkeys/login/finish',
        { method: 'POST', body: data }
      ),
  },
  vault: {
    get: () => request<VaultMeta>('/vault'),
    update: (data: {
      version: number;
      ciphertext: string;
      nonce: string;
      kek_wrap?: KeyWrap;
      recovery_wrap?: KeyWrap;
    }) => request<{ message: string; version: number }>('/vault', { method: 'PUT', body: data }),
    /** Re-wrap the vault key (master-password change / recovery-kit generation)
     * without touching the snapshot or bumping the version. */
    updateKeys: (data: { kek_wrap?: KeyWrap; recovery_wrap?: KeyWrap }) =>
      request<{ message: string }>('/vault/keys', { method: 'PUT', body: data }),
  },
  devices: {
    list: () =>
      request<Array<{
        id: string;
        name: string;
        device_type: string | null;
        last_seen_at: string | null;
        created_at: string;
        is_current: boolean;
      }>>('/devices'),
    revoke: (id: string) =>
      request<{ message: string }>(`/devices/${id}`, { method: 'DELETE' }),
  },
  admin: {
    overview: () =>
      request<AdminOverview>('/admin/overview'),
    users: () =>
      request<AdminUser[]>('/admin/users'),
    setRole: (userId: string, role: 'user' | 'admin') =>
      request<{ user_id: string; email: string; role: string; message: string }>(
        `/admin/users/${userId}/role`,
        { method: 'PATCH', body: { role } }
      ),
    revokeSessions: (userId: string) =>
      request<{ message: string }>(`/admin/users/${userId}/revoke-sessions`, { method: 'POST' }),
    audit: (params?: { limit?: number; offset?: number; event_type?: string; user_id?: string }) => {
      const qs = new URLSearchParams();
      if (params?.limit != null) qs.set('limit', String(params.limit));
      if (params?.offset != null) qs.set('offset', String(params.offset));
      if (params?.event_type) qs.set('event_type', params.event_type);
      if (params?.user_id) qs.set('user_id', params.user_id);
      const query = qs.toString();
      return request<AdminAuditPage>(`/admin/audit${query ? `?${query}` : ''}`);
    },
  },
  health: {
    check: () => fetch('/health').then(r => r.json()),
    ready: () => fetch('/ready').then(r => r.json()),
  },
};
