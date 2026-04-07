// ── Factory ──────────────────────────────────────────────────────
export { createE2EE } from "./e2ee";

// ── Standalone functions (no storage needed) ─────────────────────
export { generateMnemonic, regenerateRecoveryKey } from "./e2ee";

// ── Types ────────────────────────────────────────────────────────
export type {
  CryptoProfile,
  CryptoSetupResult,
  RecoverResult,
  RegenerateRecoveryKeyResult,
  StorageAdapter,
} from "./types";

export type { KdfParams } from "./crypto";

// ── Low-level primitives (for advanced use / auditing) ───────────
export {
  aesGcmDecrypt,
  aesGcmEncrypt,
  bytesToText,
  DEFAULT_KDF_PARAMS,
  deriveKEK,
  fromBase64,
  generateDEK,
  generateSalt,
  randomBytes,
  sha256,
  textToBytes,
  toBase64,
  unwrapDEK,
  wrapDEK,
  zeroFill,
} from "./crypto";

// ── Static data ──────────────────────────────────────────────────
export { BIP39_WORDLIST } from "./bip39-wordlist";
