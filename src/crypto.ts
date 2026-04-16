/**
 * Low-level cryptographic primitives for E2EE.
 *
 * Uses react-native-quick-crypto for native AES-256-GCM and PBKDF2.
 * PBKDF2-SHA512 with 600k iterations is used instead of Argon2id
 * to avoid an additional native dependency — acceptable for the
 * threat model (server-breach protection, not offline brute-force
 * on a stolen device).
 */

import { Buffer } from "@craftzdog/react-native-buffer";
import QuickCrypto from "react-native-quick-crypto";

// ── Constants ─────────────────────────────────────────────────────

const AES_KEY_BYTES = 32; // 256-bit
const NONCE_BYTES = 12; // 96-bit GCM nonce
const AUTH_TAG_BYTES = 16; // 128-bit GCM auth tag
const SALT_BYTES = 16;
const VERSION_BYTE = 0x01;

/** Default KDF parameters (stored per-user for future flexibility). */
export const DEFAULT_KDF_PARAMS = {
  algorithm: "pbkdf2" as const,
  iterations: 600_000,
  hash: "SHA-512" as const,
  keyLength: AES_KEY_BYTES,
};

export type KdfParams = typeof DEFAULT_KDF_PARAMS;

type QuickCryptoBuffer = Exclude<
  ReturnType<typeof QuickCrypto.randomBytes>,
  void
>;

function toQuickCryptoBuffer(
  data: Uint8Array,
): QuickCryptoBuffer {
  return Buffer.from(data) as QuickCryptoBuffer;
}

// ── Random bytes ──────────────────────────────────────────────────

export function randomBytes(length: number): Uint8Array {
  return new Uint8Array(QuickCrypto.randomBytes(length));
}

export function generateSalt(): Uint8Array {
  return randomBytes(SALT_BYTES);
}

export function generateDEK(): Uint8Array {
  return randomBytes(AES_KEY_BYTES);
}

// ── Key derivation (PBKDF2-SHA512) ────────────────────────────────

export function deriveKEK(
  password: string,
  salt: Uint8Array,
  params: KdfParams = DEFAULT_KDF_PARAMS,
): Uint8Array {
  const key = QuickCrypto.pbkdf2Sync(
    password,
    Buffer.from(salt),
    params.iterations,
    params.keyLength,
    "sha512",
  );
  return new Uint8Array(key);
}

// ── AES-256-GCM encrypt / decrypt ─────────────────────────────────

/**
 * Encrypt plaintext with AES-256-GCM.
 * Returns: version_byte(1) || nonce(12) || ciphertext || auth_tag(16)
 */
export function aesGcmEncrypt(
  key: Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array,
): Uint8Array {
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = QuickCrypto.createCipheriv(
    "aes-256-gcm",
    Buffer.from(key),
    Buffer.from(nonce),
  );

  if (aad) {
    cipher.setAAD(toQuickCryptoBuffer(aad));
  }

  const encrypted = cipher.update(Buffer.from(plaintext));
  const final = cipher.final();
  const authTag = cipher.getAuthTag();

  // Assemble: version || nonce || ciphertext || authTag
  const ciphertext = Buffer.concat([encrypted, final]);
  const result = new Uint8Array(
    1 + NONCE_BYTES + ciphertext.length + AUTH_TAG_BYTES,
  );
  result[0] = VERSION_BYTE;
  result.set(nonce, 1);
  result.set(new Uint8Array(ciphertext), 1 + NONCE_BYTES);
  result.set(new Uint8Array(authTag), 1 + NONCE_BYTES + ciphertext.length);
  return result;
}

/**
 * Decrypt ciphertext produced by aesGcmEncrypt.
 */
export function aesGcmDecrypt(
  key: Uint8Array,
  data: Uint8Array,
  aad?: Uint8Array,
): Uint8Array {
  if (data[0] !== VERSION_BYTE) {
    throw new Error(`Unsupported encryption version: ${data[0]}`);
  }

  const nonce = data.slice(1, 1 + NONCE_BYTES);
  const authTag = data.slice(data.length - AUTH_TAG_BYTES);
  const ciphertext = data.slice(1 + NONCE_BYTES, data.length - AUTH_TAG_BYTES);

  const decipher = QuickCrypto.createDecipheriv(
    "aes-256-gcm",
    Buffer.from(key),
    Buffer.from(nonce),
  );

  decipher.setAuthTag(toQuickCryptoBuffer(authTag));
  if (aad) {
    decipher.setAAD(toQuickCryptoBuffer(aad));
  }

  const decrypted = decipher.update(Buffer.from(ciphertext));
  const final = decipher.final();
  return new Uint8Array(Buffer.concat([decrypted, final]));
}

// ── Key wrapping (AES-GCM wrap/unwrap DEK with KEK) ──────────────

/** Wrap (encrypt) the DEK with the KEK. */
export function wrapDEK(kek: Uint8Array, dek: Uint8Array): Uint8Array {
  return aesGcmEncrypt(kek, dek);
}

/** Unwrap (decrypt) the DEK with the KEK. */
export function unwrapDEK(kek: Uint8Array, wrappedDek: Uint8Array): Uint8Array {
  return aesGcmDecrypt(kek, wrappedDek);
}

// ── Encoding helpers ──────────────────────────────────────────────

export function toBase64(data: Uint8Array): string {
  return Buffer.from(data).toString("base64");
}

export function fromBase64(b64: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64, "base64"));
}

export function textToBytes(text: string): Uint8Array {
  return new Uint8Array(Buffer.from(text, "utf-8"));
}

export function bytesToText(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("utf-8");
}

/** SHA-256 hash of input bytes. */
export function sha256(data: Uint8Array): Uint8Array {
  const hash = QuickCrypto.createHash("sha256")
    .update(toQuickCryptoBuffer(data))
    .digest();
  return new Uint8Array(hash);
}

/** Zero-fill a Uint8Array for defense-in-depth memory cleanup. */
export function zeroFill(arr: Uint8Array): void {
  arr.fill(0);
}
