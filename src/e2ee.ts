/**
 * High-level E2EE operations.
 *
 * All functions that persist the DEK are created via `createE2EE(storage)`,
 * which closes over an injected `StorageAdapter`. This keeps the crypto
 * core platform-agnostic — the app provides its own secure storage
 * implementation (e.g. expo-secure-store).
 */

import { BIP39_WORDLIST } from "./bip39-wordlist";
import {
  aesGcmDecrypt,
  aesGcmEncrypt,
  bytesToText,
  DEFAULT_KDF_PARAMS,
  deriveKEK,
  fromBase64,
  generateDEK,
  generateSalt,
  type KdfParams,
  randomBytes,
  sha256,
  textToBytes,
  toBase64,
  unwrapDEK,
  wrapDEK,
  zeroFill,
} from "./crypto";
import type {
  CryptoProfile,
  CryptoSetupResult,
  RecoverResult,
  RegenerateRecoveryKeyResult,
  StorageAdapter,
} from "./types";

const isDevelopment =
  typeof process !== "undefined" && process.env.NODE_ENV !== "production";

// ── Storage key helper ───────────────────────────────────────────

const dekKey = (userId: string) => `e2ee_dek_${userId}`;

// ── Mnemonic generation ──────────────────────────────────────────

/**
 * Generate a 12-word BIP39 mnemonic from 128 bits of entropy.
 * Uses the standard algorithm: entropy → SHA-256 checksum → word indices.
 */
export function generateMnemonic(): string {
  // 128 bits = 16 bytes → 12 words (128 + 4 checksum bits = 132 bits / 11 = 12)
  const entropy = randomBytes(16);

  // Compute checksum (first 4 bits of SHA-256)
  const hash = sha256(entropy);
  const checksumByte = hash[0]; // first byte, we need 4 bits

  // Convert entropy + checksum to bit string
  let bits = "";
  for (const byte of entropy) {
    bits += byte.toString(2).padStart(8, "0");
  }
  bits += checksumByte.toString(2).padStart(8, "0").slice(0, 4);

  // Split into 11-bit groups → word indices
  const words: string[] = [];
  for (let i = 0; i < 12; i++) {
    const index = Number.parseInt(bits.slice(i * 11, (i + 1) * 11), 2);
    words.push(BIP39_WORDLIST[index]);
  }

  return words.join(" ");
}

/**
 * Derive a KEK from a BIP39 mnemonic (used as the "password" for recovery).
 * Uses the same KDF but with the mnemonic as the password input.
 */
function deriveRecoveryKEK(
  mnemonic: string,
  salt: Uint8Array,
  params: KdfParams = DEFAULT_KDF_PARAMS,
): Uint8Array {
  return deriveKEK(mnemonic, salt, params);
}

// ── Standalone functions (no storage needed) ─────────────────────

/**
 * Regenerate the recovery key for an existing E2EE profile.
 * Verifies the encryption password, generates a new mnemonic, and
 * returns the new wrapped recovery DEK. Does not touch storage.
 */
export function regenerateRecoveryKey(
  password: string,
  profile: CryptoProfile,
): RegenerateRecoveryKeyResult {
  const salt = fromBase64(profile.salt);
  const kek = deriveKEK(password, salt, profile.kdf_params);
  const wrappedDek = fromBase64(profile.wrapped_dek);
  const dek = unwrapDEK(kek, wrappedDek); // throws if wrong password

  const mnemonic = generateMnemonic();
  const recoveryKek = deriveRecoveryKEK(mnemonic, salt, profile.kdf_params);
  const wrappedDekRecovery = wrapDEK(recoveryKek, dek);

  zeroFill(kek);
  zeroFill(dek);
  zeroFill(recoveryKek);

  return {
    wrappedDekRecovery: toBase64(wrappedDekRecovery),
    mnemonic,
  };
}

// ── Factory ──────────────────────────────────────────────────────

/**
 * Create a bound E2EE API that uses the provided storage adapter
 * for DEK persistence.
 */
export function createE2EE(storage: StorageAdapter) {
  // ── Setup ────────────────────────────────────────────────────

  async function setupE2EE(
    userId: string,
    password: string,
  ): Promise<CryptoSetupResult> {
    const salt = generateSalt();
    const dek = generateDEK();
    const kdfParams = DEFAULT_KDF_PARAMS;

    const kek = deriveKEK(password, salt, kdfParams);
    const wrappedDek = wrapDEK(kek, dek);

    const mnemonic = generateMnemonic();
    const recoveryKek = deriveRecoveryKEK(mnemonic, salt, kdfParams);
    const wrappedDekRecovery = wrapDEK(recoveryKek, dek);

    await storage.set(dekKey(userId), toBase64(dek));

    zeroFill(kek);
    zeroFill(recoveryKek);
    zeroFill(dek);

    return {
      salt: toBase64(salt),
      wrappedDek: toBase64(wrappedDek),
      wrappedDekRecovery: toBase64(wrappedDekRecovery),
      kdfParams,
      mnemonic,
    };
  }

  // ── Unlock ───────────────────────────────────────────────────

  async function unlockE2EE(
    userId: string,
    password: string,
    profile: CryptoProfile,
  ): Promise<void> {
    const salt = fromBase64(profile.salt);
    const wrappedDek = fromBase64(profile.wrapped_dek);

    const kek = deriveKEK(password, salt, profile.kdf_params);
    const dek = unwrapDEK(kek, wrappedDek);

    await storage.set(dekKey(userId), toBase64(dek));

    zeroFill(kek);
    zeroFill(dek);
  }

  // ── Recovery ─────────────────────────────────────────────────

  async function recoverE2EE(
    userId: string,
    mnemonic: string,
    newPassword: string,
    profile: CryptoProfile,
  ): Promise<RecoverResult> {
    const salt = fromBase64(profile.salt);
    const wrappedDekRecovery = fromBase64(profile.wrapped_dek_recovery);

    const recoveryKek = deriveRecoveryKEK(mnemonic, salt, profile.kdf_params);
    const dek = unwrapDEK(recoveryKek, wrappedDekRecovery);

    const newKek = deriveKEK(newPassword, salt, profile.kdf_params);
    const newWrappedDek = wrapDEK(newKek, dek);
    const newWrappedDekRecovery = wrapDEK(recoveryKek, dek);

    await storage.set(dekKey(userId), toBase64(dek));

    zeroFill(recoveryKek);
    zeroFill(newKek);
    zeroFill(dek);

    return {
      wrappedDek: toBase64(newWrappedDek),
      wrappedDekRecovery: toBase64(newWrappedDekRecovery),
    };
  }

  // ── Re-wrap ──────────────────────────────────────────────────

  async function rewrapDEK(
    userId: string,
    newPassword: string,
    profile: CryptoProfile,
  ): Promise<string> {
    const dekBase64 = await storage.get(dekKey(userId));
    if (!dekBase64) throw new Error("DEK not found in secure storage");

    const dek = fromBase64(dekBase64);
    const salt = fromBase64(profile.salt);

    const newKek = deriveKEK(newPassword, salt, profile.kdf_params);
    const newWrappedDek = wrapDEK(newKek, dek);

    zeroFill(newKek);
    zeroFill(dek);

    return toBase64(newWrappedDek);
  }

  // ── Entry encryption / decryption ────────────────────────────

  async function encryptDescription(
    userId: string,
    description: string,
    entryId: string,
  ): Promise<string> {
    const dekBase64 = await storage.get(dekKey(userId));
    if (!dekBase64) throw new Error("DEK not available — E2EE not unlocked");

    const dek = fromBase64(dekBase64);
    const plaintext = textToBytes(description);
    const aad = textToBytes(entryId);

    const ciphertext = aesGcmEncrypt(dek, plaintext, aad);
    zeroFill(dek);

    return toBase64(ciphertext);
  }

  async function decryptDescription(
    userId: string,
    encryptedDescription: string,
    entryId: string,
  ): Promise<string> {
    const dekBase64 = await storage.get(dekKey(userId));
    if (!dekBase64) throw new Error("DEK not available — E2EE not unlocked");

    const dek = fromBase64(dekBase64);
    const ciphertext = fromBase64(encryptedDescription);
    const aad = textToBytes(entryId);

    const plaintext = aesGcmDecrypt(dek, ciphertext, aad);
    zeroFill(dek);

    return bytesToText(plaintext);
  }

  async function decryptEntries<
    T extends {
      id: string;
      description: string | null;
      encrypted_description?: string | null;
    },
  >(userId: string, entries: T[]): Promise<T[]> {
    const dekBase64 = await storage.get(dekKey(userId));
    if (!dekBase64) return entries;

    const dek = fromBase64(dekBase64);

    const result = entries.map((entry) => {
      if (!entry.encrypted_description) return entry;
      try {
        const ciphertext = fromBase64(entry.encrypted_description);
        const aad = textToBytes(entry.id);
        const plaintext = aesGcmDecrypt(dek, ciphertext, aad);
        return { ...entry, description: bytesToText(plaintext) };
      } catch (err) {
        if (isDevelopment)
          console.warn(`[E2EE] Failed to decrypt entry ${entry.id}`, err);
        return entry;
      }
    });

    zeroFill(dek);
    return result;
  }

  // ── Cleanup / status ─────────────────────────────────────────

  async function clearDEK(userId: string): Promise<void> {
    await storage.clear(dekKey(userId));
  }

  async function isDEKAvailable(userId: string): Promise<boolean> {
    const dek = await storage.get(dekKey(userId));
    return dek !== null;
  }

  return {
    setupE2EE,
    unlockE2EE,
    recoverE2EE,
    rewrapDEK,
    encryptDescription,
    decryptDescription,
    decryptEntries,
    clearDEK,
    isDEKAvailable,
  };
}
