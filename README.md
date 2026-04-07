# @untoldly/e2ee-crypto

End-to-end encryption core for [Untoldly](https://untoldly.com). Platform-agnostic, audit-focused.

## Purpose

This package contains all security-sensitive cryptographic logic for Untoldly's E2EE private entries feature. It exists as a standalone repository for external security audit — it is not a general-purpose SDK.

## Architecture

```
Encryption password (separate from login password, 6+ chars)
      |
      v
PBKDF2-SHA512(password, salt, 600k iterations)  -->  KEK (256-bit)
      |
      v
AES-GCM-wrap(KEK, DEK)  -->  wrapped_dek (stored server-side)
      |
      v
DEK (256-bit random)  -->  cached via injected StorageAdapter
      |
      v
AES-256-GCM(DEK, nonce, plaintext, AAD=entryId)  -->  ciphertext
```

**Key separation**: DEK encrypts data; KEK (derived from encryption password) wraps DEK. Password change re-wraps DEK without re-encrypting entries. A 12-word BIP39 recovery mnemonic provides an alternate KEK to unwrap the same DEK.

### Encryption format

`version_byte(0x01) || nonce(12B) || ciphertext || auth_tag(16B)` encoded as Base64.

Entry ID is used as AAD (Additional Authenticated Data) to bind ciphertext to a specific entry and prevent swapping.

### KDF parameters

| Parameter | Value |
|-----------|-------|
| Algorithm | PBKDF2-SHA512 |
| Iterations | 600,000 |
| Output | 32 bytes (256-bit KEK) |
| Salt | 16 bytes random, stored per-user |

## Usage

The package uses a factory pattern with an injected storage adapter for DEK persistence:

```typescript
import { createE2EE, type StorageAdapter } from "@untoldly/e2ee-crypto";

const storage: StorageAdapter = {
  get: (key) => SecureStore.getItemAsync(key),
  set: (key, value) => SecureStore.setItemAsync(key, value),
  clear: (key) => SecureStore.deleteItemAsync(key),
};

const e2ee = createE2EE(storage);

// Setup (creates DEK, wraps with password, generates recovery mnemonic)
const result = await e2ee.setupE2EE(userId, password);

// Unlock (derives KEK from password, unwraps DEK, stores locally)
await e2ee.unlockE2EE(userId, password, cryptoProfile);

// Encrypt / decrypt
const ciphertext = await e2ee.encryptDescription(userId, "secret text", entryId);
const plaintext = await e2ee.decryptDescription(userId, ciphertext, entryId);

// Recovery (unwrap DEK with mnemonic, re-wrap with new password)
const recovered = await e2ee.recoverE2EE(userId, mnemonic, newPassword, profile);

// Re-wrap DEK after password change
const newWrappedDek = await e2ee.rewrapDEK(userId, newPassword, profile);

// Batch decrypt
const entries = await e2ee.decryptEntries(userId, encryptedEntries);
```

### Standalone functions (no storage needed)

```typescript
import { generateMnemonic, regenerateRecoveryKey } from "@untoldly/e2ee-crypto";

const mnemonic = generateMnemonic(); // 12-word BIP39

const { wrappedDekRecovery, mnemonic: newMnemonic } =
  regenerateRecoveryKey(password, cryptoProfile);
```

## API

### `createE2EE(storage: StorageAdapter)`

Returns a bound API object with all functions that need DEK persistence:

| Function | Description |
|----------|-------------|
| `setupE2EE(userId, password)` | Full setup: generate DEK, wrap, store, return mnemonic |
| `unlockE2EE(userId, password, profile)` | Derive KEK, unwrap DEK, store locally |
| `recoverE2EE(userId, mnemonic, newPassword, profile)` | Recover with mnemonic, re-wrap for new password |
| `rewrapDEK(userId, newPassword, profile)` | Re-wrap stored DEK with new password |
| `encryptDescription(userId, description, entryId)` | Encrypt with DEK, entryId as AAD |
| `decryptDescription(userId, ciphertext, entryId)` | Decrypt with DEK |
| `decryptEntries(userId, entries)` | Batch decrypt, graceful per-entry failure |
| `isDEKAvailable(userId)` | Check if DEK is in storage |
| `clearDEK(userId)` | Remove DEK from storage |

### Standalone exports

| Export | Description |
|--------|-------------|
| `generateMnemonic()` | Generate 12-word BIP39 recovery mnemonic |
| `regenerateRecoveryKey(password, profile)` | Verify password, generate new recovery key |

### Types

```typescript
interface StorageAdapter {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  clear(key: string): Promise<void>;
}

interface CryptoProfile {
  id: string;
  salt: string;              // base64
  wrapped_dek: string;       // base64
  wrapped_dek_recovery: string; // base64
  kdf_params: KdfParams;
  version: number;
}
```

## Peer dependencies

- `react-native-quick-crypto` >= 1.0.0 (provides native AES-GCM + PBKDF2)

## Testing

```bash
npm test
```

Tests alias `react-native-quick-crypto` to `node:crypto` and use an in-memory storage adapter. 50 tests covering crypto primitives, key management flows, recovery, and batch decryption.

## Security considerations

- **Nonce uniqueness**: 12-byte random per encryption. Birthday collision negligible for realistic entry counts.
- **AAD binding**: Entry ID prevents ciphertext swapping between entries.
- **Memory**: DEK held in JS `Uint8Array`, zeroed after use. Not cryptographically wiped (JS limitation) — acceptable for the threat model (server breach, not device compromise).
- **No logging**: All crypto values are never logged. `__DEV__` guards on error warnings only.
- **Scope**: Private entry descriptions only. Titles, locations, images stay plaintext.

## What this package does NOT contain

- React, Expo, Supabase, Tamagui, or any UI code
- Device storage implementation (injected via `StorageAdapter`)
- Network calls or server communication
- Retry/sync logic for failed server updates
- Database migrations (referenced in docs as audit context only)

## Database context (for audit reference)

The server enforces E2EE via a PostgreSQL trigger (`enforce_e2ee_private_entries`): when `e2ee_enabled = true` and `visibility = 'private'`, the `description` column must be NULL and `encrypted_description` must be non-NULL. This prevents a buggy client from storing plaintext. See `supabase/migrations/00032_e2ee_support.sql` in the app repo.

## License

Private. Not for redistribution.
