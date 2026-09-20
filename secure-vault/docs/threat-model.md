# Threat Model

## Actors
- **User** — legitimate owner of the account.
- **DB leak** — attacker obtains a full copy of PostgreSQL data.
- **Backend admin** — privileged access to server and database.
- **Network attacker** — intercepts traffic in transit.
- **Offline attacker** — has ciphertext and attempts to guess the master password.

## Protected Against

| Threat | Mitigation |
|--------|-----------|
| Database leak | Only ciphertext stored; no plaintext keys |
| Backend admin reads vault | Zero-knowledge: keys never leave client |
| Stolen session | Only hashed tokens stored; short expiry; revocation |
| Network interception | TLS/HTTPS required in production |
| Modified ciphertext | AES-GCM authenticated encryption |
| Password guessing | Argon2id memory-hard KDF, high cost |
| Brute-force login | Rate limiting on auth endpoints |
| Device revocation abuse | Sessions tied to devices, revoked together |

## Harder Problems (Documented Limitations)

- Malware on an unlocked device can read decrypted vault data in memory.
- Keyloggers can capture the master password when typed.
- Compromised OS or physical memory attacks.
- Browser extensions can read DOM.

**No web application can make a compromised device trustworthy.** We document this limitation; we do not claim "unhackable."

## What We Defend That Normal CRUD Apps Don't

Even if the entire database and server are compromised, an attacker cannot:
- Read any stored password
- Read vault metadata
- Decrypt the vault without the master password or recovery material

## Recovery

If the user loses both the master password and recovery key, the service **cannot** recover the vault. This is by design — the server never holds the decryption capability.
