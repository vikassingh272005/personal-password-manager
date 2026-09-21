#!/usr/bin/env node
/**
 * Demo seed — creates the demo account through the REAL registration
 * pipeline (server API + client-side key ceremony, exactly like the browser
 * does it), then fills the vault with sample items.
 *
 * Why a script instead of SQL: the vault's ciphertext can only be produced
 * by the zero-knowledge client (PBKDF2 KEK → wraps random VEK). Inserting
 * rows by hand would create an unopenable vault.
 *
 * Usage:
 *   node scripts/seed-demo.mjs [--reset]
 *     --reset   delete the demo account first (idempotent reseed)
 *
 * Environment (defaults match `npm run dev`):
 *   SEED_API        default http://localhost:3001/api/v1
 *   SEED_EMAIL      default demo@securevault.local
 *   SEED_PASSWORD   default demo-password-123
 *   SEED_MASTER     default demo-master-456
 */

import crypto from 'node:crypto';

const API = process.env.SEED_API ?? 'http://localhost:3001/api/v1';
const EMAIL = process.env.SEED_EMAIL ?? 'demo@securevault.local';
const PASSWORD = process.env.SEED_PASSWORD ?? 'demo-password-123';
const MASTER = process.env.SEED_MASTER ?? 'demo-master-456';
const RESET = process.argv.includes('--reset');

const b64 = (bytes) => Buffer.from(bytes).toString('base64');
const fromB64 = (s) => new Uint8Array(Buffer.from(s, 'base64'));
const ab = (bytes) => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);

async function call(method, path, body, cookie) {
  const res = await fetch(API + path, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(cookie ? { Cookie: cookie } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const setCookie = res.headers.get('set-cookie');
  let json = null;
  try { json = await res.json(); } catch { /* 204s etc. */ }
  return { status: res.status, json, cookie: setCookie?.split(';')[0] };
}

// ---- The client-side key ceremony (mirrors apps/web/lib/crypto.ts) ----------

async function deriveVaultKey(password, saltB64, iterations) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: ab(fromB64(saltB64)), iterations, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function wrapRawKey(wrappingKey, rawVek, aad) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: new TextEncoder().encode(aad) },
    wrappingKey,
    rawVek
  );
  return { ciphertext: b64(new Uint8Array(ciphertext)), nonce: b64(nonce) };
}

async function encryptEnvelope(vek, items, folders) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify({ items, folders }));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, vek, plaintext);
  return { ciphertext: b64(new Uint8Array(ciphertext)), nonce: b64(nonce) };
}

const WRAP_AAD = { kek: 'SecureVault:v1:kek', recovery: 'SecureVault:v1:recovery' };

// Crockford alphabet, fixed salt — see lib/crypto.ts deriveRecoveryKey.
async function deriveRecoveryKey(normalizedSecret, iterations) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(normalizedSecret), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: new TextEncoder().encode('SecureVault Recovery Key v1'),
      iterations,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// ---- Demo data --------------------------------------------------------------

const DEMO_ITEMS = [
  {
    type: 'login', title: 'GitHub', username: 'demo-builder',
    password: 'X9#vQ2m!pLw4zR8k', urls: ['https://github.com'],
    notes: 'Work + personal. 2FA via authenticator.', favorite: true,
  },
  {
    type: 'login', title: 'AWS Console', username: 'demo-admin',
    password: 'Kj7!nP9@wQx2vB6m', urls: ['https://console.aws.amazon.com'],
    notes: 'Root access locked in vault — use IAM roles day-to-day.', favorite: true,
  },
  {
    type: 'login', title: 'Figma', username: 'demo.designer',
    password: 'Fg5@mN8#kJq3wR7z', urls: ['https://figma.com'], notes: '', favorite: false,
  },
  {
    type: 'card', title: 'Team Card', username: 'VI 4242 4242 4242',
    password: '4242', urls: [], notes: 'Demo card (test number). CVV 123, 12/29.', favorite: false,
  },
  {
    type: 'note', title: 'Wi-Fi (office)', username: '', password: '',
    urls: [], notes: 'SSID: securevault-guest · key: "coffee first, then code"', favorite: false,
  },
];
const DEMO_FOLDERS = ['Work', 'Personal'];

// ---- Main -------------------------------------------------------------------

const now = () => new Date().toISOString();
const item = (template, i) => ({
  ...template,
  id: crypto.randomUUID(),
  created_at: now(),
  updated_at: now(),
  folder: i < 2 ? 'Work' : 'Personal',
});

console.log(`Seeding demo account ${EMAIL} against ${API}`);

if (RESET) {
  // Best-effort cleanup so a reseed never collides with the old account.
  const admin = await call('POST', '/auth/login', { email: EMAIL, password: PASSWORD });
  if (admin.status === 200 || admin.status === 202) {
    console.log('Existing demo account found; deleting its data via admin API is not');
    console.log('implemented — the seed will fail with 409 unless you clear the DB.');
    console.log('Tip: docker exec secure-vault-postgres-5433 psql -U postgres -d secure_vault \\');
    console.log('  -c "DELETE FROM users WHERE email = \'' + EMAIL + '\'"');
    process.exit(1);
  }
}

// 1. Register (server creates the account + empty vault row).
const reg = await call('POST', '/auth/register', {
  email: EMAIL,
  password: PASSWORD,
  kdf_params: {
    algorithm: 'PBKDF2-SHA256',
    iterations: 310000,
    // Fixed salt so reseeds stay deterministic; entropy lives in the VEK.
    salt: b64(Buffer.from('securevault-demo-salt-16b')),
    nonce_used: true,
  },
  master_password_hash: 'seed',
});
if (reg.status !== 201) {
  console.error(`Register failed (${reg.status}):`, reg.json?.error ?? '(no body)');
  process.exit(1);
}
console.log('  account created');

// 2. Key ceremony — same shape the browser produces.
const { kdf_iterations, kdf_salt } = reg.json;
const kek = await deriveVaultKey(MASTER, kdf_salt, kdf_iterations);

const rawVek = crypto.getRandomValues(new Uint8Array(32));
const vek = await crypto.subtle.importKey('raw', ab(rawVek), { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);

// A printable Secret Key (Crockford base32, 32 chars in 4 groups).
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const secretChars = Array.from(crypto.getRandomValues(new Uint32Array(32)), (x) => ALPHABET[x % 32]).join('');
const secretKey = secretChars.replace(/(.{8})(?=.)/g, '$1-');
const recoveryKey = await deriveRecoveryKey(secretChars, kdf_iterations);

const kekWrap = await wrapRawKey(kek, rawVek, WRAP_AAD.kek);
const recoveryWrap = await wrapRawKey(recoveryKey, rawVek, WRAP_AAD.recovery);
rawVek.fill(0);

// 3. Upload the vault snapshot (v2: kek + recovery wraps, encrypted items).
const items = DEMO_ITEMS.map(item);
const envelope = await encryptEnvelope(vek, items, DEMO_FOLDERS);
const put = await call('PUT', '/vault', {
  version: 1,
  ...envelope,
  kek_wrap: kekWrap,
  recovery_wrap: recoveryWrap,
}, reg.cookie);
if (put.status !== 200) {
  console.error(`Vault upload failed (${put.status}):`, put.json?.error ?? '(no body)');
  process.exit(1);
}
console.log(`  vault seeded with ${items.length} items, ${DEMO_FOLDERS.length} folders`);

console.log('');
console.log('Demo account ready:');
console.log(`  email:            ${EMAIL}`);
console.log(`  account password: ${PASSWORD}`);
console.log(`  master password:  ${MASTER}`);
console.log(`  secret key:       ${secretKey}`);
console.log('');
console.log('Store these in a password manager — the Secret Key is shown only here.');
