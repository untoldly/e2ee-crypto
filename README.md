# @untoldly/e2ee-crypto

E2EE crypto core for [Untoldly](https://untoldly.com). Extracted for external security audit.

## Architecture

```
Encryption password --> PBKDF2-SHA512(600k) --> KEK (256-bit)
                                                  |
                                         AES-GCM-wrap(KEK, DEK)
                                                  |
DEK (256-bit random) <-- stored via StorageAdapter
  |
AES-256-GCM(DEK, nonce, plaintext, AAD=entryId) --> ciphertext
```

DEK encrypts data. KEK wraps DEK. Password change = re-wrap only. 12-word BIP39 mnemonic provides an alternate KEK for recovery.

**Encryption format**: `version(0x01) || nonce(12B) || ciphertext || tag(16B)` as Base64, with entry ID as AAD.

## Usage

```typescript
import { createE2EE, type StorageAdapter } from "@untoldly/e2ee-crypto";

const e2ee = createE2EE(myStorageAdapter);

await e2ee.setupE2EE(userId, password);          // returns { salt, wrappedDek, wrappedDekRecovery, kdfParams, mnemonic }
await e2ee.unlockE2EE(userId, password, profile); // derive KEK, unwrap DEK, store
await e2ee.encryptDescription(userId, text, entryId);
await e2ee.decryptDescription(userId, ciphertext, entryId);
await e2ee.recoverE2EE(userId, mnemonic, newPassword, profile);
await e2ee.rewrapDEK(userId, newPassword, profile);
await e2ee.decryptEntries(userId, entries);        // batch, graceful per-entry failure
```

Standalone (no storage needed):

```typescript
import { generateMnemonic, regenerateRecoveryKey } from "@untoldly/e2ee-crypto";
```

### StorageAdapter

```typescript
interface StorageAdapter {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  clear(key: string): Promise<void>;
}
```

## Peer dependencies

`react-native-quick-crypto` >= 0.7.17 < 2

## Testing

```bash
npm test   # 50 tests, aliases react-native-quick-crypto to node:crypto
```

## Security notes

- 12-byte random nonce per encryption
- Entry ID as AAD prevents ciphertext swapping
- DEK zeroed after use (JS limitation: not cryptographically wiped)
- No logging of crypto values
- Server-side trigger enforces ciphertext-only for E2EE private entries

## Scope

This package contains only crypto logic. No React, Expo, Supabase, UI, storage implementation, network calls, or retry logic.

## License

Private. Not for redistribution.
