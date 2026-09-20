function generatePassword(
  length: number = 24,
  uppercase: boolean = true,
  lowercase: boolean = true,
  numbers: boolean = true,
  symbols: boolean = true
): string {
  const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const lower = 'abcdefghijklmnopqrstuvwxyz';
  const nums = '0123456789';
  const syms = '!@#$%^&*()_+-=[]{}|;:,.<>?';

  let charset = '';
  if (uppercase) charset += upper;
  if (lowercase) charset += lower;
  if (numbers) charset += nums;
  if (symbols) charset += syms;
  if (!charset) charset = lower;

  const array = new Uint32Array(length);
  crypto.getRandomValues(array);

  return Array.from(array, (x) => charset[x % charset.length]).join('');
}

function calculateEntropy(password: string): number {
  let charsetSize = 0;
  if (/[a-z]/.test(password)) charsetSize += 26;
  if (/[A-Z]/.test(password)) charsetSize += 26;
  if (/[0-9]/.test(password)) charsetSize += 10;
  if (/[^a-zA-Z0-9]/.test(password)) charsetSize += 32;

  if (charsetSize === 0) return 0;
  return Math.floor(password.length * Math.log2(charsetSize));
}

function getPasswordStrength(password: string): {
  score: number;
  label: string;
  color: string;
} {
  const entropy = calculateEntropy(password);

  if (entropy < 28) return { score: 0, label: 'Very Weak', color: 'bg-red-500' };
  if (entropy < 36) return { score: 1, label: 'Weak', color: 'bg-orange-500' };
  if (entropy < 60) return { score: 2, label: 'Fair', color: 'bg-yellow-500' };
  if (entropy < 80) return { score: 3, label: 'Strong', color: 'bg-green-500' };
  return { score: 4, label: 'Very Strong', color: 'bg-emerald-500' };
}

function cn(...classes: (string | boolean | undefined | null)[]): string {
  return classes.filter(Boolean).join(' ');
}

// ---- Key hierarchy helpers ------------------------------------------------
// Two-layer design: a random 32-byte vault encryption key (VEK) encrypts the
// item envelopes. The master password never encrypts data directly — it only
// derives a KEK (below) that *wraps* the VEK, and a printable Secret Key wraps
// the same VEK under an independent key. The server stores both wraps and
// never sees the VEK, the KEK, or the Secret Key.
//
// Legacy vaults (created before this design, or re-keyed by migration 003)
// encrypt items directly under a key derived from the master password. That
// derivation is *the same function* as the KEK derivation, so this one helper
// serves both: `deriveVaultKey` is the KEK in v2 vaults and the data key in
// legacy vaults. Vaults are detected by the presence of the server-side
// kek_wrap: v2 vaults unwrap the VEK, legacy vaults decrypt straight.

/**
 * PBKDF2-SHA256 (per-account salt + iteration count from GET /vault) to an
 * AES-256-GCM key. Never transmitted; used only in this tab.
 */
async function deriveVaultKey(
  password: string,
  saltB64: string,
  iterations: number
): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const passwordKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: b64decode(saltB64),
      iterations,
      hash: 'SHA-256',
    },
    passwordKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// Domain-separation tags: a wrap encrypted under the KEK can never be replayed
// as a recovery wrap (or vice versa), even if an attacker swaps the stored
// blobs.
export const WRAP_AAD = {
  kek: 'SecureVault:v1:kek',
  recovery: 'SecureVault:v1:recovery',
} as const;

export interface KeyWrap {
  ciphertext: string;
  nonce: string;
}

// Crockford base32 alphabet (no I, L, O, U). 32 chars => 5 bits each.
const RECOVERY_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const RECOVERY_KEY_LENGTH = 32; // chars => 160 bits of entropy
const RECOVERY_GROUP = 8; // displayed as 4 groups of 8

/** Generate a fresh printable Secret Key (display form with group separators). */
function generateRecoverySecret(): string {
  const rand = new Uint32Array(RECOVERY_KEY_LENGTH);
  crypto.getRandomValues(rand);
  // 32 divides 2^32 exactly, so modulo sampling is unbiased.
  let chars = '';
  for (let i = 0; i < RECOVERY_KEY_LENGTH; i++) {
    chars += RECOVERY_ALPHABET[rand[i] % RECOVERY_ALPHABET.length];
  }
  return chars.replace(new RegExp(`(.{${RECOVERY_GROUP}})(?=.)`, 'g'), '$1-');
}

/**
 * Normalize user-typed Secret Key input: strip separators/whitespace, fold
 * case, map common lookalikes (I/L -> 1, O -> 0), and reject anything outside
 * the alphabet. The normalized string (not the display form) is what feeds the
 * recovery KDF, so formatting never matters — only the characters do.
 */
function normalizeRecoverySecret(input: string): string {
  const cleaned = input
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, '')
    .replace(/[IL]/g, '1')
    .replace(/O/g, '0');
  for (const ch of cleaned) {
    if (!RECOVERY_ALPHABET.includes(ch)) {
      throw new Error(`"${ch}" is not a valid Secret Key character`);
    }
  }
  if (cleaned.length !== RECOVERY_KEY_LENGTH) {
    throw new Error(
      `Your Secret Key is ${cleaned.length} characters long — it should be ${RECOVERY_KEY_LENGTH}.`
    );  
  }
  return cleaned;
}

/**
 * Derive the recovery wrapping key from a normalized Secret Key. The salt is a
 * fixed application constant: the Secret Key itself carries 160 bits of
 * entropy, so a per-user salt adds nothing and a constant keeps unlock
 * derivable from just the key + iteration count.
 */
async function deriveRecoveryKey(
  normalizedSecret: string,
  iterations: number
): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const passwordKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(normalizedSecret),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: encoder.encode('SecureVault Recovery Key v1'),
      iterations,
      hash: 'SHA-256',
    },
    passwordKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/** Random 32-byte vault encryption key. Raw bytes are returned once (for
 * wrapping); callers should zeroize them with `raw.fill(0)` when done. */
async function generateVek(): Promise<{ raw: Uint8Array<ArrayBuffer>; key: CryptoKey }> {
  const raw = crypto.getRandomValues(new Uint8Array(32));
  return { raw, key: await importVek(raw) };
}

/** Import raw VEK bytes as an AES-256-GCM key (extractable so re-wrapping
 * flows can export it when the KEK is not in memory). */
async function importVek(raw: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, true, [
    'encrypt',
    'decrypt',
  ]);
}

/** Wrap the raw 32-byte VEK under a wrapping key, tagged with the AAD purpose. */
async function wrapRawKey(
  wrappingKey: CryptoKey,
  rawVek: Uint8Array<ArrayBuffer>,
  aad: string
): Promise<KeyWrap> {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: new TextEncoder().encode(aad) },
    wrappingKey,
    rawVek
  );
  return { ciphertext: b64encode(new Uint8Array(ciphertext)), nonce: b64encode(nonce) };
}

/** Unwrap the raw 32-byte VEK. Throws when the wrapping key is wrong — that is
 * how an incorrect master password / Secret Key is detected. */
async function unwrapRawKey(
  wrappingKey: CryptoKey,
  wrap: KeyWrap,
  aad: string
): Promise<Uint8Array<ArrayBuffer>> {
  const plaintext = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: b64decode(wrap.nonce),
      additionalData: new TextEncoder().encode(aad),
    },
    wrappingKey,
    b64decode(wrap.ciphertext)
  );
  return new Uint8Array(plaintext);
}

// ---- Vault sync helpers ---------------------------------------------------
function b64encode(bytes: Uint8Array<ArrayBuffer> | ArrayBuffer): string {
  const buf = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const list = Array.from(buf);
  let bin = '';
  for (let i = 0; i < list.length; i += 0x8000) {
    bin += String.fromCharCode(...list.slice(i, i + 0x8000));
  }
  return btoa(bin);
}

function b64decode(b64: string): Uint8Array<ArrayBuffer> {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    bytes[i] = bin.charCodeAt(i);
  }
  return bytes;
}

/** AES-256-GCM encrypt a UTF-8 string. Returns base64 ciphertext + nonce. */
async function encryptString(
  key: CryptoKey,
  plaintext: string
): Promise<{ ciphertext: string; nonce: string }> {
  const encoder = new TextEncoder();
  const nonceBytes = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonceBytes },
    key,
    encoder.encode(plaintext)
  );
  return {
    ciphertext: b64encode(new Uint8Array(ciphertext)),
    nonce: b64encode(nonceBytes),
  };
}

/**
 * AES-256-GCM decrypt a base64 ciphertext + nonce. Rejects (throws) when the
 * key is wrong or the blob was tampered with — that is how the unlock flow
 * detects an incorrect master password.
 */
async function decryptString(
  key: CryptoKey,
  ciphertextB64: string,
  nonceB64: string
): Promise<string> {
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: b64decode(nonceB64) },
    key,
    b64decode(ciphertextB64)
  );
  return new TextDecoder().decode(plaintext);
}

async function encryptData(
  data: ArrayBuffer,
  key: CryptoKey
): Promise<{ ciphertext: ArrayBuffer; iv: Uint8Array<ArrayBuffer> }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
  return { ciphertext, iv };
}

async function decryptData(
  ciphertext: ArrayBuffer,
  key: CryptoKey,
  iv: Uint8Array<ArrayBuffer>
): Promise<ArrayBuffer> {
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
}

export {
  generatePassword,
  calculateEntropy,
  getPasswordStrength,
  cn,
  encryptData,
  decryptData,
  b64encode,
  b64decode,
  deriveVaultKey,
  deriveRecoveryKey,
  generateRecoverySecret,
  normalizeRecoverySecret,
  generateVek,
  importVek,
  wrapRawKey,
  unwrapRawKey,
  encryptString,
  decryptString,
};

