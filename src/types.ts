import type { KdfParams } from "./crypto";

// ── Storage adapter ──────────────────────────────────────────────

/** Minimal async key-value interface for DEK persistence. */
export interface StorageAdapter {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  clear(key: string): Promise<void>;
}

// ── Crypto profile ───────────────────────────────────────────────

export interface CryptoProfile {
  id: string;
  salt: string; // base64
  wrapped_dek: string; // base64
  wrapped_dek_recovery: string; // base64
  kdf_params: KdfParams;
  version: number;
}

// ── Result types ─────────────────────────────────────────────────

export interface CryptoSetupResult {
  salt: string; // base64
  wrappedDek: string; // base64
  wrappedDekRecovery: string; // base64
  kdfParams: KdfParams;
  mnemonic: string; // 12 space-separated words
}

export interface RecoverResult {
  wrappedDek: string; // base64
  wrappedDekRecovery: string; // base64
}

export interface RegenerateRecoveryKeyResult {
  wrappedDekRecovery: string; // base64
  mnemonic: string; // 12 space-separated words
}
