import type { VaultMeta } from '@/lib/api';
import {
  WRAP_AAD,
  deriveRecoveryKey,
  deriveVaultKey,
  importVek,
  unwrapRawKey,
} from '@/lib/crypto';

/**
 * Shared key-resolution for every flow that opens a vault:
 *
 * - v2 vaults (server has kek_wrap): derive the KEK from the master password,
 *   unwrap the random VEK, and use the VEK as the data key. A wrong password
 *   fails at the GCM unwrap — nothing is ever sent to the server.
 * - legacy vaults (no kek_wrap): the master password derives the data key
 *   directly (PBKDF2 output used straight as the AES key).
 *
 * All crypto stays in this tab; only ciphertext ever leaves it.
 */
export async function resolveVaultKeyWithMasterPassword(
  meta: VaultMeta,
  masterPassword: string
): Promise<{ dataKey: CryptoKey; mode: 'v2' | 'legacy' }> {
  const kek = await deriveVaultKey(masterPassword, meta.kdf_salt, meta.kdf_iterations);

  if (meta.kek_wrap) {
    const raw = await unwrapRawKey(kek, meta.kek_wrap, WRAP_AAD.kek); // throws on wrong password
    return { dataKey: await importVek(raw), mode: 'v2' };
  }

  return { dataKey: kek, mode: 'legacy' };
}

/**
 * Unlock with the printable Secret Key: derive the recovery wrapping key from
 * the normalized secret and unwrap the recovery copy of the VEK. The raw VEK
 * is returned too (the caller re-wraps it under a fresh master password after
 * a recovery and must zeroize it afterwards).
 */
export async function resolveVaultKeyWithSecretKey(
  meta: VaultMeta,
  normalizedSecret: string
): Promise<{ dataKey: CryptoKey; rawVek: Uint8Array<ArrayBuffer> }> {
  if (!meta.recovery_wrap) {
    throw new Error('This account has no Secret Key recovery kit on file.');
  }
  const rk = await deriveRecoveryKey(normalizedSecret, meta.kdf_iterations);
  const rawVek = await unwrapRawKey(rk, meta.recovery_wrap, WRAP_AAD.recovery); // throws on wrong key
  return { dataKey: await importVek(rawVek), rawVek };
}
