/**
 * Privacy-preserving breach lookups, all client-side.
 *
 * - Passwords use HIBP's k-anonymity Pwned Passwords range API: only a 5-char
 *   SHA-1 prefix leaves the browser; the full hash never does.
 * - Emails use XposedOrNot's keyless check-email API.
 *
 * Neither API receives your master password, vault key, or vault contents.
 * Results are cached in memory for the tab's lifetime.
 */

// ---- SHA-1 ------------------------------------------------------------------

async function sha1Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// ---- HIBP Pwned Passwords (k-anonymity) -------------------------------------

const PWNED_PASSWORDS_API = 'https://api.pwnedpasswords.com/range/';
const RANGE_CACHE = new Map<string, string>();
const PASSWORD_CACHE = new Map<string, number>();

/**
 * Check a password against the Pwned Passwords corpus using k-anonymity:
 * hash the password locally, send only the first 5 hex chars, match the full
 * hash among returned suffixes. Returns the total breach count, 0 if safe.
 */
export async function checkPasswordBreachCount(password: string): Promise<number> {
  if (!password) return 0;
  const hash = (await sha1Hex(password)).toUpperCase();
  if (PASSWORD_CACHE.has(hash)) return PASSWORD_CACHE.get(hash)!;

  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);

  let suffixes: string;
  const cached = RANGE_CACHE.get(prefix);
  if (cached !== undefined) {
    suffixes = cached;
  } else {
    const res = await fetch(`${PWNED_PASSWORDS_API}${prefix}`, {
      headers: { 'Add-Padding': 'true' },
    });
    if (!res.ok) throw new Error(`Pwned Passwords responded ${res.status}`);
    suffixes = await res.text();
    RANGE_CACHE.set(prefix, suffixes);
  }

  let count = 0;
  for (const line of suffixes.split('\n')) {
    const [hashSuffix, countStr] = line.trim().split(':');
    if (hashSuffix === suffix) {
      count = parseInt(countStr ?? '0', 10) || 0;
      break;
    }
  }

  PASSWORD_CACHE.set(hash, count);
  return count;
}

// ---- XposedOrNot email breach check ------------------------------------------

/** A single breach an email address appeared in. */
export interface EmailBreach {
  title: string;
  xist_date?: string; // date the breach entered the XON index
  breach_date?: string;
  domain?: string;
  description?: string;
  xposed_records?: string;
  xposed_date?: string;
  xposed_data?: string[]; // exposed data classes, e.g. ["Email addresses", "Passwords"]
}

interface XonCheckResponse {
  ExposureStatus?: string;
  breaches?: { breaches?: EmailBreach[] };
  exposed?: string; // e.g. "xposed_records: <n>"
}

/**
 * Look up breaches for an email via XposedOrNot (free, no API key).
 * Returns the list of breaches; empty array when the address is clean.
 * Throws on network/API failure — callers should distinguish "clean" from
 * "could not check".
 */
export async function fetchEmailBreaches(email: string): Promise<EmailBreach[]> {
  const cleaned = email.trim().toLowerCase();
  if (!cleaned || !cleaned.includes('@')) {
    throw new Error('Enter a valid email address to scan.');
  }

  const res = XON_CACHE.get(cleaned);
  if (res) return extractBreaches(res);

  const response = await fetch(
    `https://api.xposedornot.com/v1/check-email/${encodeURIComponent(cleaned)}`
  );
  if (response.status === 429) throw new Error('Breach lookup rate-limited — try again in a minute.');
  if (!response.ok) throw new Error(`Breach lookup failed (${response.status}).`);

  const data = (await response.json()) as XonCheckResponse;
  XON_CACHE.set(cleaned, data);
  return extractBreaches(data);
}

const XON_CACHE = hoistXonCache();

function hoistXonCache() {
  return ((globalThis as any).__secureVaultXonCache ??= new Map<string, XonCheckResponse>());
}

function extractBreaches(data: XonCheckResponse): EmailBreach[] {
  if (data.ExposureStatus !== 'Exposed') return [];
  return data.breaches?.breaches ?? [];
}

// ---- Scan aggregation ---------------------------------------------------------

export interface EmailScanResult {
  email: string;
  breaches: EmailBreach[];
}

/** Scan one email (used for the account email). */
export async function scanEmail(email: string): Promise<EmailScanResult> {
  return { email: email.trim().toLowerCase(), breaches: await fetchEmailBreaches(email) };
}
