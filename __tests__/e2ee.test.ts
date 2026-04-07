import {
  BIP39_WORDLIST,
  createE2EE,
  deriveKEK,
  fromBase64,
  generateMnemonic,
  regenerateRecoveryKey,
  toBase64,
  unwrapDEK,
  type CryptoProfile,
  type StorageAdapter,
} from "../src/index";

// In-memory storage adapter for tests
const memoryStore = new Map<string, string>();
const testStorage: StorageAdapter = {
  get: async (key) => memoryStore.get(key) ?? null,
  set: async (key, value) => {
    memoryStore.set(key, value);
  },
  clear: async (key) => {
    memoryStore.delete(key);
  },
};

const e2ee = createE2EE(testStorage);
const {
  setupE2EE,
  unlockE2EE,
  recoverE2EE,
  rewrapDEK,
  encryptDescription,
  decryptDescription,
  decryptEntries,
  isDEKAvailable,
  clearDEK,
} = e2ee;

const TEST_USER_ID = "test-user-123";

beforeEach(() => {
  memoryStore.clear();
});

describe("generateMnemonic", () => {
  it("returns 12 space-separated words", () => {
    const mnemonic = generateMnemonic();
    const words = mnemonic.split(" ");
    expect(words).toHaveLength(12);
  });

  it("uses only words from the BIP39 wordlist", () => {
    const mnemonic = generateMnemonic();
    const words = mnemonic.split(" ");
    for (const word of words) {
      expect(BIP39_WORDLIST).toContain(word);
    }
  });

  it("produces different mnemonics each time", () => {
    const a = generateMnemonic();
    const b = generateMnemonic();
    expect(a).not.toBe(b);
  });
});

describe("setupE2EE", () => {
  it("returns salt, wrappedDek, wrappedDekRecovery, kdfParams, and mnemonic", async () => {
    const result = await setupE2EE(TEST_USER_ID, "testpassword");
    expect(result.salt).toBeTruthy();
    expect(result.wrappedDek).toBeTruthy();
    expect(result.wrappedDekRecovery).toBeTruthy();
    expect(result.kdfParams).toEqual({
      algorithm: "pbkdf2",
      iterations: 600_000,
      hash: "SHA-512",
      keyLength: 32,
    });
    expect(result.mnemonic.split(" ")).toHaveLength(12);
  });

  it("stores DEK in secure storage", async () => {
    await setupE2EE(TEST_USER_ID, "testpassword");
    expect(await isDEKAvailable(TEST_USER_ID)).toBe(true);
  });
});

describe("unlockE2EE", () => {
  it("stores DEK after unlocking with correct password", async () => {
    const setup = await setupE2EE(TEST_USER_ID, "mypassword");
    await clearDEK(TEST_USER_ID);
    expect(await isDEKAvailable(TEST_USER_ID)).toBe(false);

    const profile: CryptoProfile = {
      id: "user-123",
      salt: setup.salt,
      wrapped_dek: setup.wrappedDek,
      wrapped_dek_recovery: setup.wrappedDekRecovery,
      kdf_params: setup.kdfParams,
      version: 1,
    };

    await unlockE2EE(TEST_USER_ID, "mypassword", profile);
    expect(await isDEKAvailable(TEST_USER_ID)).toBe(true);
  });

  it("throws with wrong password", async () => {
    const setup = await setupE2EE(TEST_USER_ID, "correctpassword");
    await clearDEK(TEST_USER_ID);

    const profile: CryptoProfile = {
      id: "user-123",
      salt: setup.salt,
      wrapped_dek: setup.wrappedDek,
      wrapped_dek_recovery: setup.wrappedDekRecovery,
      kdf_params: setup.kdfParams,
      version: 1,
    };

    await expect(
      unlockE2EE(TEST_USER_ID, "wrongpassword", profile),
    ).rejects.toThrow();
  });
});

describe("rewrapDEK", () => {
  it("rewraps the stored DEK for a new password", async () => {
    const setup = await setupE2EE(TEST_USER_ID, "old-password");
    const dekBase64 = await testStorage.get(`e2ee_dek_${TEST_USER_ID}`);

    const profile: CryptoProfile = {
      id: "user-123",
      salt: setup.salt,
      wrapped_dek: setup.wrappedDek,
      wrapped_dek_recovery: setup.wrappedDekRecovery,
      kdf_params: setup.kdfParams,
      version: 1,
    };

    const rewrapped = await rewrapDEK(TEST_USER_ID, "new-password", profile);
    const newKek = deriveKEK(
      "new-password",
      fromBase64(setup.salt),
      setup.kdfParams,
    );
    const unwrappedDek = unwrapDEK(newKek, fromBase64(rewrapped));

    expect(rewrapped).toBeTruthy();
    expect(rewrapped).not.toBe(setup.wrappedDek);
    expect(toBase64(unwrappedDek)).toBe(dekBase64);
  });

  it("throws when DEK is not in secure storage", async () => {
    const setup = await setupE2EE(TEST_USER_ID, "password");
    await clearDEK(TEST_USER_ID);

    const profile: CryptoProfile = {
      id: "user-123",
      salt: setup.salt,
      wrapped_dek: setup.wrappedDek,
      wrapped_dek_recovery: setup.wrappedDekRecovery,
      kdf_params: setup.kdfParams,
      version: 1,
    };

    await expect(
      rewrapDEK(TEST_USER_ID, "new-password", profile),
    ).rejects.toThrow("DEK not found");
  });
});

describe("recoverE2EE", () => {
  it("recovers DEK with correct mnemonic and re-wraps for new password", async () => {
    const setup = await setupE2EE(TEST_USER_ID, "original-password");
    await clearDEK(TEST_USER_ID);

    const profile: CryptoProfile = {
      id: "user-123",
      salt: setup.salt,
      wrapped_dek: setup.wrappedDek,
      wrapped_dek_recovery: setup.wrappedDekRecovery,
      kdf_params: setup.kdfParams,
      version: 1,
    };

    const result = await recoverE2EE(
      TEST_USER_ID,
      setup.mnemonic,
      "new-password",
      profile,
    );

    expect(result.wrappedDek).toBeTruthy();
    expect(result.wrappedDekRecovery).toBeTruthy();
    expect(result.wrappedDek).not.toBe(setup.wrappedDek);
    expect(await isDEKAvailable(TEST_USER_ID)).toBe(true);
  });

  it("allows unlocking with new password after recovery", async () => {
    const setup = await setupE2EE(TEST_USER_ID, "original-password");
    await clearDEK(TEST_USER_ID);

    const profile: CryptoProfile = {
      id: "user-123",
      salt: setup.salt,
      wrapped_dek: setup.wrappedDek,
      wrapped_dek_recovery: setup.wrappedDekRecovery,
      kdf_params: setup.kdfParams,
      version: 1,
    };

    const result = await recoverE2EE(
      TEST_USER_ID,
      setup.mnemonic,
      "new-password",
      profile,
    );
    await clearDEK(TEST_USER_ID);

    const updatedProfile: CryptoProfile = {
      ...profile,
      wrapped_dek: result.wrappedDek,
      wrapped_dek_recovery: result.wrappedDekRecovery,
    };

    await unlockE2EE(TEST_USER_ID, "new-password", updatedProfile);
    expect(await isDEKAvailable(TEST_USER_ID)).toBe(true);
  });

  it("old password no longer works after recovery", async () => {
    const setup = await setupE2EE(TEST_USER_ID, "original-password");
    await clearDEK(TEST_USER_ID);

    const profile: CryptoProfile = {
      id: "user-123",
      salt: setup.salt,
      wrapped_dek: setup.wrappedDek,
      wrapped_dek_recovery: setup.wrappedDekRecovery,
      kdf_params: setup.kdfParams,
      version: 1,
    };

    const result = await recoverE2EE(
      TEST_USER_ID,
      setup.mnemonic,
      "new-password",
      profile,
    );
    await clearDEK(TEST_USER_ID);

    const updatedProfile: CryptoProfile = {
      ...profile,
      wrapped_dek: result.wrappedDek,
      wrapped_dek_recovery: result.wrappedDekRecovery,
    };

    await expect(
      unlockE2EE(TEST_USER_ID, "original-password", updatedProfile),
    ).rejects.toThrow();
  });

  it("preserves ability to decrypt existing entries after recovery", async () => {
    const setup = await setupE2EE(TEST_USER_ID, "original-password");
    const entryId = "entry-recovery-test";
    const originalText = "Secret entry before recovery";
    const encrypted = await encryptDescription(
      TEST_USER_ID,
      originalText,
      entryId,
    );
    await clearDEK(TEST_USER_ID);

    const profile: CryptoProfile = {
      id: "user-123",
      salt: setup.salt,
      wrapped_dek: setup.wrappedDek,
      wrapped_dek_recovery: setup.wrappedDekRecovery,
      kdf_params: setup.kdfParams,
      version: 1,
    };

    await recoverE2EE(TEST_USER_ID, setup.mnemonic, "new-password", profile);

    const decrypted = await decryptDescription(
      TEST_USER_ID,
      encrypted,
      entryId,
    );
    expect(decrypted).toBe(originalText);
  });

  it("throws with wrong mnemonic", async () => {
    const setup = await setupE2EE(TEST_USER_ID, "password");
    await clearDEK(TEST_USER_ID);

    const profile: CryptoProfile = {
      id: "user-123",
      salt: setup.salt,
      wrapped_dek: setup.wrappedDek,
      wrapped_dek_recovery: setup.wrappedDekRecovery,
      kdf_params: setup.kdfParams,
      version: 1,
    };

    const wrongMnemonic =
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    await expect(
      recoverE2EE(TEST_USER_ID, wrongMnemonic, "new-password", profile),
    ).rejects.toThrow();
  });
});

describe("regenerateRecoveryKey", () => {
  it("generates a new recovery key with valid mnemonic", async () => {
    const setup = await setupE2EE(TEST_USER_ID, "mypassword");

    const profile: CryptoProfile = {
      id: "user-123",
      salt: setup.salt,
      wrapped_dek: setup.wrappedDek,
      wrapped_dek_recovery: setup.wrappedDekRecovery,
      kdf_params: setup.kdfParams,
      version: 1,
    };

    const result = regenerateRecoveryKey("mypassword", profile);

    expect(result.wrappedDekRecovery).toBeTruthy();
    expect(result.wrappedDekRecovery).not.toBe(setup.wrappedDekRecovery);
    expect(result.mnemonic.split(" ")).toHaveLength(12);
  });

  it("throws with wrong password", async () => {
    const setup = await setupE2EE(TEST_USER_ID, "mypassword");

    const profile: CryptoProfile = {
      id: "user-123",
      salt: setup.salt,
      wrapped_dek: setup.wrappedDek,
      wrapped_dek_recovery: setup.wrappedDekRecovery,
      kdf_params: setup.kdfParams,
      version: 1,
    };

    expect(() => regenerateRecoveryKey("wrongpassword", profile)).toThrow();
  });

  it("new recovery key can be used to recover", async () => {
    const setup = await setupE2EE(TEST_USER_ID, "mypassword");
    await clearDEK(TEST_USER_ID);

    const profile: CryptoProfile = {
      id: "user-123",
      salt: setup.salt,
      wrapped_dek: setup.wrappedDek,
      wrapped_dek_recovery: setup.wrappedDekRecovery,
      kdf_params: setup.kdfParams,
      version: 1,
    };

    const { wrappedDekRecovery, mnemonic } = regenerateRecoveryKey(
      "mypassword",
      profile,
    );

    const updatedProfile: CryptoProfile = {
      ...profile,
      wrapped_dek_recovery: wrappedDekRecovery,
    };

    const result = await recoverE2EE(
      TEST_USER_ID,
      mnemonic,
      "newpassword",
      updatedProfile,
    );
    expect(result.wrappedDek).toBeTruthy();
    expect(await isDEKAvailable(TEST_USER_ID)).toBe(true);
  });
});

describe("encryptDescription / decryptDescription", () => {
  it("round-trips a description", async () => {
    await setupE2EE(TEST_USER_ID, "password");
    const entryId = "550e8400-e29b-41d4-a716-446655440000";
    const text = "My secret diary entry about the trip to Stockholm.";

    const encrypted = await encryptDescription(TEST_USER_ID, text, entryId);
    expect(encrypted).not.toBe(text);
    expect(typeof encrypted).toBe("string");

    const decrypted = await decryptDescription(
      TEST_USER_ID,
      encrypted,
      entryId,
    );
    expect(decrypted).toBe(text);
  });

  it("round-trips an empty description", async () => {
    await setupE2EE(TEST_USER_ID, "password");
    const entryId = "550e8400-e29b-41d4-a716-446655440001";

    const encrypted = await encryptDescription(TEST_USER_ID, "", entryId);
    const decrypted = await decryptDescription(
      TEST_USER_ID,
      encrypted,
      entryId,
    );

    expect(decrypted).toBe("");
  });

  it("fails to decrypt with wrong entry ID (AAD mismatch)", async () => {
    await setupE2EE(TEST_USER_ID, "password");
    const encrypted = await encryptDescription(
      TEST_USER_ID,
      "secret",
      "entry-1",
    );
    await expect(
      decryptDescription(TEST_USER_ID, encrypted, "entry-2"),
    ).rejects.toThrow();
  });

  it("throws when DEK is not available", async () => {
    await expect(
      encryptDescription(TEST_USER_ID, "text", "entry-id"),
    ).rejects.toThrow("DEK not available");
  });
});

describe("decryptEntries", () => {
  it("decrypts entries with encrypted_description", async () => {
    await setupE2EE(TEST_USER_ID, "password");
    const entryId = "entry-abc";
    const encrypted = await encryptDescription(
      TEST_USER_ID,
      "secret text",
      entryId,
    );

    const entries = [
      { id: entryId, description: null, encrypted_description: encrypted },
    ];

    const result = await decryptEntries(TEST_USER_ID, entries);
    expect(result[0].description).toBe("secret text");
  });

  it("passes through entries without encrypted_description", async () => {
    await setupE2EE(TEST_USER_ID, "password");

    const entries = [
      { id: "entry-1", description: "plaintext", encrypted_description: null },
    ];

    const result = await decryptEntries(TEST_USER_ID, entries);
    expect(result[0].description).toBe("plaintext");
  });

  it("handles mixed encrypted and plaintext entries", async () => {
    await setupE2EE(TEST_USER_ID, "password");
    const encrypted = await encryptDescription(
      TEST_USER_ID,
      "secret",
      "entry-2",
    );

    const entries = [
      { id: "entry-1", description: "plain", encrypted_description: null },
      { id: "entry-2", description: null, encrypted_description: encrypted },
      {
        id: "entry-3",
        description: "also plain",
        encrypted_description: null,
      },
    ];

    const result = await decryptEntries(TEST_USER_ID, entries);
    expect(result[0].description).toBe("plain");
    expect(result[1].description).toBe("secret");
    expect(result[2].description).toBe("also plain");
  });

  it("returns entry unchanged when its encrypted_description is corrupt", async () => {
    await setupE2EE(TEST_USER_ID, "password");

    const entries = [
      {
        id: "entry-good",
        description: null,
        encrypted_description: await encryptDescription(
          TEST_USER_ID,
          "works",
          "entry-good",
        ),
      },
      {
        id: "entry-bad",
        description: null,
        encrypted_description: "not-valid-base64-ciphertext!!!",
      },
      {
        id: "entry-plain",
        description: "plaintext",
        encrypted_description: null,
      },
    ];

    const result = await decryptEntries(TEST_USER_ID, entries);
    expect(result[0].description).toBe("works");
    expect(result[1].description).toBeNull();
    expect(result[1].encrypted_description).toBe(
      "not-valid-base64-ciphertext!!!",
    );
    expect(result[2].description).toBe("plaintext");
  });

  it("returns entries as-is when DEK is not available", async () => {
    const entries = [
      {
        id: "entry-1",
        description: null,
        encrypted_description: "base64stuff",
      },
    ];

    const result = await decryptEntries(TEST_USER_ID, entries);
    expect(result[0].description).toBeNull();
    expect(result[0].encrypted_description).toBe("base64stuff");
  });
});
