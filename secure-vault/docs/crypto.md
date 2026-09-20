# Crypto Design

## Primitives

| Purpose | Algorithm |
|---------|-----------|
| Password hashing (login) | Argon2id |
| Key derivation (vault) | Argon2id |
| Key separation | HKDF-SHA256 |
| Authenticated encryption | AES-256-GCM |
| CSPRNG | `rand::rngs::OsRng` / Web Crypto |

## Encryption Envelope

```json
{
  "version": 1,
  "algorithm": "AES-256-GCM",
  "nonce": "...",
  "ciphertext": "..."
}
```

Every encryption uses a unique random 12-byte nonce. AES-GCM provides authenticated encryption — any tampering causes decryption failure.

## Key Hierarchy

Why this design?

1. **Vault Encryption Key (VEK)** is random 256-bit, generated once.
2. The master password never directly encrypts the vault.
3. **KEK** is derived from the master password via Argon2id, then wrapped with HKDF.
4. KEK encrypts the VEK (a small fixed-size key), not the potentially large vault.

## Master Password Change

```
Old password → Old KEK → decrypt VEK
New password → New KEK → encrypt VEK (same vault, no re-encryption)
```

## AAD (Associated Authenticated Data)

Ciphertext is bound to context:
- Vault ciphertext: AAD = `"secure-vault-v1"`
- Key wrapping: AAD = `"vault-key-wrap"`

This prevents ciphertext from being replayed in an unintended context.

## Zeroization

Sensitive buffers use `zeroize` in Rust so keys are cleared from memory when dropped. The frontend must never store decrypted vault data in `localStorage`; it lives only in application state.

## KDF Parameters

Production baseline:
- Algorithm: Argon2id
- Memory: 65536 KiB (64 MiB)
- Iterations: 3
- Parallelism: 2
- Salt: 32 random bytes

> **Never replace Argon2id with SHA-256 for password derivation.**
