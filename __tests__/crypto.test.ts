import {
  aesGcmDecrypt,
  aesGcmEncrypt,
  bytesToText,
  deriveKEK,
  fromBase64,
  generateDEK,
  generateSalt,
  randomBytes,
  textToBytes,
  toBase64,
  unwrapDEK,
  wrapDEK,
  zeroFill,
} from "../src/crypto";

describe("randomBytes / generateSalt / generateDEK", () => {
  it("returns the requested number of bytes", () => {
    expect(randomBytes(16)).toHaveLength(16);
    expect(randomBytes(32)).toHaveLength(32);
  });

  it("generateSalt returns 16 bytes", () => {
    expect(generateSalt()).toHaveLength(16);
  });

  it("generateDEK returns 32 bytes", () => {
    expect(generateDEK()).toHaveLength(32);
  });

  it("produces different values each call", () => {
    const a = randomBytes(32);
    const b = randomBytes(32);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });
});

describe("deriveKEK", () => {
  it("produces a 32-byte key", () => {
    const salt = generateSalt();
    const kek = deriveKEK("password", salt);
    expect(kek).toHaveLength(32);
  });

  it("is deterministic for the same password and salt", () => {
    const salt = generateSalt();
    const a = deriveKEK("password", salt);
    const b = deriveKEK("password", salt);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(true);
  });

  it("produces different keys for different passwords", () => {
    const salt = generateSalt();
    const a = deriveKEK("password1", salt);
    const b = deriveKEK("password2", salt);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });

  it("produces different keys for different salts", () => {
    const a = deriveKEK("password", generateSalt());
    const b = deriveKEK("password", generateSalt());
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });
});

describe("aesGcmEncrypt / aesGcmDecrypt", () => {
  it("round-trips plaintext", () => {
    const key = generateDEK();
    const plaintext = textToBytes("Hello, E2EE!");
    const ciphertext = aesGcmEncrypt(key, plaintext);
    const decrypted = aesGcmDecrypt(key, ciphertext);
    expect(bytesToText(decrypted)).toBe("Hello, E2EE!");
  });

  it("round-trips with AAD", () => {
    const key = generateDEK();
    const plaintext = textToBytes("secret");
    const aad = textToBytes("entry-id-123");
    const ciphertext = aesGcmEncrypt(key, plaintext, aad);
    const decrypted = aesGcmDecrypt(key, ciphertext, aad);
    expect(bytesToText(decrypted)).toBe("secret");
  });

  it("fails to decrypt with wrong key", () => {
    const key1 = generateDEK();
    const key2 = generateDEK();
    const ciphertext = aesGcmEncrypt(key1, textToBytes("secret"));
    expect(() => aesGcmDecrypt(key2, ciphertext)).toThrow();
  });

  it("fails to decrypt with wrong AAD", () => {
    const key = generateDEK();
    const plaintext = textToBytes("secret");
    const ciphertext = aesGcmEncrypt(key, plaintext, textToBytes("aad-1"));
    expect(() =>
      aesGcmDecrypt(key, ciphertext, textToBytes("aad-2")),
    ).toThrow();
  });

  it("fails to decrypt with missing AAD when AAD was used", () => {
    const key = generateDEK();
    const plaintext = textToBytes("secret");
    const ciphertext = aesGcmEncrypt(key, plaintext, textToBytes("aad"));
    expect(() => aesGcmDecrypt(key, ciphertext)).toThrow();
  });

  it("rejects unsupported version byte", () => {
    const key = generateDEK();
    const ciphertext = aesGcmEncrypt(key, textToBytes("test"));
    // Tamper with version byte
    ciphertext[0] = 0xff;
    expect(() => aesGcmDecrypt(key, ciphertext)).toThrow(
      "Unsupported encryption version",
    );
  });

  it("produces different ciphertexts for the same plaintext (random nonce)", () => {
    const key = generateDEK();
    const plaintext = textToBytes("same input");
    const a = aesGcmEncrypt(key, plaintext);
    const b = aesGcmEncrypt(key, plaintext);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });

  it("handles empty plaintext", () => {
    const key = generateDEK();
    const plaintext = textToBytes("");
    const ciphertext = aesGcmEncrypt(key, plaintext);
    const decrypted = aesGcmDecrypt(key, ciphertext);
    expect(bytesToText(decrypted)).toBe("");
  });

  it("handles unicode plaintext", () => {
    const key = generateDEK();
    const text = "Untoldly: resor med karta";
    const ciphertext = aesGcmEncrypt(key, textToBytes(text));
    expect(bytesToText(aesGcmDecrypt(key, ciphertext))).toBe(text);
  });
});

describe("wrapDEK / unwrapDEK", () => {
  it("round-trips a DEK", () => {
    const kek = deriveKEK("password", generateSalt());
    const dek = generateDEK();
    const wrapped = wrapDEK(kek, dek);
    const unwrapped = unwrapDEK(kek, wrapped);
    expect(Buffer.from(unwrapped).equals(Buffer.from(dek))).toBe(true);
  });

  it("fails to unwrap with wrong KEK", () => {
    const salt = generateSalt();
    const kek1 = deriveKEK("password1", salt);
    const kek2 = deriveKEK("password2", salt);
    const dek = generateDEK();
    const wrapped = wrapDEK(kek1, dek);
    expect(() => unwrapDEK(kek2, wrapped)).toThrow();
  });
});

describe("toBase64 / fromBase64", () => {
  it("round-trips binary data", () => {
    const original = randomBytes(64);
    const encoded = toBase64(original);
    const decoded = fromBase64(encoded);
    expect(Buffer.from(decoded).equals(Buffer.from(original))).toBe(true);
  });

  it("produces a valid base64 string", () => {
    const encoded = toBase64(randomBytes(32));
    expect(encoded).toMatch(/^[A-Za-z0-9+/]+=*$/);
  });
});

describe("textToBytes / bytesToText", () => {
  it("round-trips a string", () => {
    expect(bytesToText(textToBytes("hello"))).toBe("hello");
  });

  it("handles empty string", () => {
    expect(bytesToText(textToBytes(""))).toBe("");
  });
});

describe("zeroFill", () => {
  it("fills array with zeros", () => {
    const arr = new Uint8Array([1, 2, 3, 4]);
    zeroFill(arr);
    expect(arr.every((b) => b === 0)).toBe(true);
  });
});
