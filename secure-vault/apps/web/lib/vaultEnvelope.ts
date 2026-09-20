import type { VaultItem } from '@/hooks/useVault';
import { decryptString, encryptString } from '@/lib/crypto';

/** Plaintext shape encrypted into every vault snapshot. */
export interface VaultEnvelope {
  items: VaultItem[];
  folders: string[];
}

export async function encryptEnvelope(
  key: CryptoKey,
  items: VaultItem[],
  folders: string[]
): Promise<{ ciphertext: string; nonce: string }> {
  const payload: VaultEnvelope = { items, folders };
  return encryptString(key, JSON.stringify(payload));
}

/**
 * Decrypt and validate a vault snapshot. Throws when the key is wrong (an
 * incorrect master password) or the blob is malformed.
 */
export async function decryptEnvelope(
  key: CryptoKey,
  ciphertext: string,
  nonce: string
): Promise<VaultEnvelope> {
  const plaintext = await decryptString(key, ciphertext, nonce);
  const parsed: unknown = JSON.parse(plaintext);
  if (
    typeof parsed !== 'object' ||
    parsed === null ||
    !Array.isArray((parsed as VaultEnvelope).items) ||
    !Array.isArray((parsed as VaultEnvelope).folders)
  ) {
    throw new Error('Vault snapshot has an unexpected format');
  }
  return parsed as VaultEnvelope;
}
