import type { VaultItem } from '@/hooks/useVault';
import {
  b64decode,
  b64encode,
  decryptString,
  deriveVaultKey,
  encryptString,
} from '@/lib/crypto';

/**
 * Encrypted vault export/import ("Data" section in Settings).
 *
 * Everything happens client-side: the export file is AES-256-GCM ciphertext
 * encrypted under a key derived (PBKDF2-SHA256) from a passphrase the user
 * types. The server never sees exports or imports, and no plaintext file ever
 * touches disk. The file format is intentionally self-describing so a future
 * importer (or another client) can verify the algorithm and parameters before
 * decrypting.
 */

const EXPORT_FORMAT = 'secure-vault-export';
const EXPORT_VERSION = 1;
const EXPORT_ITERATIONS = 310_000;
const EXPORT_CIPHER = 'AES-256-GCM';

/** Shape of the downloadable `.json` export file. */
export interface VaultExportFile {
  format: typeof EXPORT_FORMAT;
  version: number;
  kdf: {
    algorithm: 'PBKDF2-SHA256';
    iterations: number;
    /** base64 per-file random salt. */
    salt: string;
  };
  cipher: typeof EXPORT_CIPHER;
  /** base64 AES-256-GCM ciphertext of the JSON envelope. */
  ciphertext: string;
  /** base64 12-byte nonce. */
  nonce: string;
}

/** Plaintext payload that gets encrypted inside the export file. */
interface ExportPayload {
  kind: 'vault';
  exported_at: string;
  items: VaultItem[];
  folders: string[];
}

function isVaultExportFile(value: unknown): value is VaultExportFile {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    v.format === EXPORT_FORMAT &&
    v.version === EXPORT_VERSION &&
    typeof v.ciphertext === 'string' &&
    typeof v.nonce === 'string' &&
    typeof v.kdf === 'object' &&
    v.kdf !== null &&
    (v.kdf as Record<string, unknown>).algorithm === 'PBKDF2-SHA256'
  );
}

function isExportPayload(value: unknown): value is ExportPayload {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    v.kind === 'vault' && Array.isArray(v.items) && Array.isArray(v.folders)
  );
}

/** Build the encrypted export file bytes for the current vault contents. */
export async function createEncryptedExport(
  passphrase: string,
  items: VaultItem[],
  folders: string[]
): Promise<VaultExportFile> {
  const saltBytes = crypto.getRandomValues(new Uint8Array(16));
  const salt = b64encode(saltBytes);
  const key = await deriveVaultKey(passphrase, salt, EXPORT_ITERATIONS);

  const payload: ExportPayload = {
    kind: 'vault',
    exported_at: new Date().toISOString(),
    items,
    folders,
  };
  const { ciphertext, nonce } = await encryptString(key, JSON.stringify(payload));

  return {
    format: EXPORT_FORMAT,
    version: EXPORT_VERSION,
    kdf: { algorithm: 'PBKDF2-SHA256', iterations: EXPORT_ITERATIONS, salt },
    cipher: EXPORT_CIPHER,
    ciphertext,
    nonce,
  };
}

/**
 * Decrypt a parsed export file. Throws with a user-safe message when the
 * format is unknown or the passphrase is wrong (GCM authentication failure).
 */
export async function openEncryptedExport(
  passphrase: string,
  parsed: unknown
): Promise<{ items: VaultItem[]; folders: string[]; exportedAt: string | null }> {
  if (!isVaultExportFile(parsed)) {
    throw new Error('That file is not a SecureVault export (unrecognized format).');
  }

  const key = await deriveVaultKey(
    passphrase,
    parsed.kdf.salt,
    parsed.kdf.iterations
  );
  let plaintext: string;
  try {
    plaintext = await decryptString(key, parsed.ciphertext, parsed.nonce);
  } catch {
    throw new Error('Wrong passphrase — the export file could not be decrypted.');
  }

  const payload: unknown = JSON.parse(plaintext);
  if (!isExportPayload(payload)) {
    throw new Error('Export file contents are malformed.');
  }
  return {
    items: payload.items,
    folders: payload.folders,
    exportedAt:
      typeof payload.exported_at === 'string' ? payload.exported_at : null,
  };
}

/** Read + JSON.parse a user-selected export file. */
export async function readExportFile(file: File): Promise<unknown> {
  const text = await file.text();
  try {
    return JSON.parse(text);
  } catch {
    throw new Error('That file is not valid JSON.');
  }
}

/** Download helper: turn an export file into a client-side download. */
export function downloadExportFile(exportFile: VaultExportFile): void {
  const blob = new Blob([JSON.stringify(exportFile, null, 2)], {
    type: 'application/json',
  });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  const date = new Date().toISOString().slice(0, 10);
  anchor.href = url;
  anchor.download = `securevault-export-${date}.json`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}
