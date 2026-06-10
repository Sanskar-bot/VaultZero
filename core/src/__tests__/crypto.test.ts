/**
 * ═══════════════════════════════════════════════════════════════════
 * VaultZero Crypto Core — Unit Tests
 * ═══════════════════════════════════════════════════════════════════
 *
 * Day 2 tests (8 tests):
 *   - AES-256-GCM encrypt/decrypt round-trip
 *   - Decryption with wrong key throws
 *   - IV uniqueness (same plaintext → different ciphertext)
 *   - Vault key wrap/unwrap round-trip
 *   - Unwrap with wrong KEK throws
 *   - Password generator respects length
 *   - Password generator produces different results
 *   - Entropy calculation scales with length
 *
 * Day 3 tests (13 tests):
 *   Vault Serialization (4):
 *   - encryptVault/decryptVault round-trip with entries
 *   - Empty vault round-trip
 *   - Decrypting with wrong key throws
 *   - Two encryptions of same vault produce different ciphertext (fresh IV)
 *
 *   Recovery Phrase (5):
 *   - generateRecoveryPhrase returns exactly 24 words
 *   - All words are valid BIP39 words
 *   - Two phrases are different (randomness check)
 *   - hashRecoveryPhrase is deterministic
 *   - hashRecoveryPhrase returns 64-char hex string
 *
 *   Recovery KEK (2):
 *   - deriveRecoveryKEK returns 32 bytes
 *   - Same phrase + salt always produces same KEK (deterministic)
 *
 *   Validation (2):
 *   - validateRecoveryPhrase accepts valid phrase
 *   - validateRecoveryPhrase rejects wrong word count / invalid words
 * ═══════════════════════════════════════════════════════════════════
 */

import { encryptData, decryptData } from "../crypto/aes-gcm";
import {
  generateVaultKey,
  wrapVaultKey,
  unwrapVaultKey,
} from "../crypto/keys";
import {
  generatePassword,
  calculateEntropy,
} from "../crypto/generator";
import {
  createVault,
  addEntry,
  encryptVault,
  decryptVault,
} from "../vault/vault";
import {
  generateRecoveryPhrase,
  hashRecoveryPhrase,
  deriveRecoveryKEK,
  validateRecoveryPhrase,
} from "../recovery/bip39";
import { BIP39_WORDLIST } from "../recovery/wordlist";
import { generateSalt } from "../crypto/argon2";

// ─────────────────────────────────────────────────────────────
// Day 2 — Crypto Core Tests
// ─────────────────────────────────────────────────────────────

describe("AES-256-GCM Encryption", () => {
  let testKey: Uint8Array;

  beforeAll(async () => {
    testKey = await generateVaultKey();
  });

  test("encrypt then decrypt returns original plaintext", async () => {
    const plaintext = "Hello, VaultZero! 🔐 Special chars: <>&\"'";
    const ciphertext = await encryptData(plaintext, testKey);
    const decrypted = await decryptData(ciphertext, testKey);
    expect(decrypted).toBe(plaintext);
  });

  test("decryption with wrong key throws an error", async () => {
    const plaintext = "secret password 123";
    const wrongKey = await generateVaultKey();
    const ciphertext = await encryptData(plaintext, testKey);
    await expect(decryptData(ciphertext, wrongKey)).rejects.toThrow(
      /wrong key|tampered/i
    );
  });

  test("two encryptions of same plaintext produce different ciphertext", async () => {
    const plaintext = "identical plaintext for IV uniqueness test";
    const ciphertext1 = await encryptData(plaintext, testKey);
    const ciphertext2 = await encryptData(plaintext, testKey);

    // Different IVs → different ciphertext
    expect(ciphertext1).not.toBe(ciphertext2);

    // Both still decrypt correctly
    expect(await decryptData(ciphertext1, testKey)).toBe(plaintext);
    expect(await decryptData(ciphertext2, testKey)).toBe(plaintext);
  });
});

describe("Vault Key Wrapping", () => {
  test("wrapVaultKey then unwrapVaultKey returns equivalent key", async () => {
    const vaultKey = await generateVaultKey();
    const kek = await generateVaultKey();
    const wrappedKey = await wrapVaultKey(vaultKey, kek);
    const unwrappedKey = await unwrapVaultKey(wrappedKey, kek);
    expect(Buffer.from(unwrappedKey).equals(Buffer.from(vaultKey))).toBe(true);
  });

  test("unwrapVaultKey with wrong KEK throws an error", async () => {
    const vaultKey = await generateVaultKey();
    const correctKek = await generateVaultKey();
    const wrongKek = await generateVaultKey();
    const wrappedKey = await wrapVaultKey(vaultKey, correctKek);
    await expect(unwrapVaultKey(wrappedKey, wrongKek)).rejects.toThrow(
      /wrong KEK|tampered/i
    );
  });
});

describe("Password Generator", () => {
  test("generatePassword respects length option", () => {
    for (const length of [8, 16, 32, 64, 128]) {
      const password = generatePassword({
        length,
        uppercase: true,
        lowercase: true,
        numbers: true,
        symbols: true,
      });
      expect(password).toHaveLength(length);
    }
  });

  test("generatePassword with same options produces different results each time", () => {
    const options = {
      length: 32,
      uppercase: true,
      lowercase: true,
      numbers: true,
      symbols: true,
    };
    const password1 = generatePassword(options);
    const password2 = generatePassword(options);
    expect(password1).not.toBe(password2);
  });
});

describe("Entropy Calculator", () => {
  test("calculateEntropy returns higher value for longer passwords", () => {
    const shortPassword = generatePassword({
      length: 8,
      uppercase: true,
      lowercase: true,
      numbers: true,
      symbols: true,
    });
    const longPassword = generatePassword({
      length: 32,
      uppercase: true,
      lowercase: true,
      numbers: true,
      symbols: true,
    });
    expect(calculateEntropy(longPassword)).toBeGreaterThan(
      calculateEntropy(shortPassword)
    );
    expect(calculateEntropy(shortPassword)).toBeGreaterThan(0);
  });
});

// ─────────────────────────────────────────────────────────────
// Day 3 — Vault Serialization Tests
// ─────────────────────────────────────────────────────────────

describe("Vault Serialization (encryptVault / decryptVault)", () => {
  let vaultKey: Uint8Array;

  beforeAll(async () => {
    vaultKey = await generateVaultKey();
  });

  test("encryptVault then decryptVault round-trips a vault with entries", async () => {
    // Build a vault with two entries
    let vault = createVault();
    vault = addEntry(vault, {
      url: "https://github.com",
      username: "sanskar@example.com",
      password: "S3cur3P@ss!123",
      notes: "Work account",
    });
    vault = addEntry(vault, {
      url: "https://google.com",
      username: "sanskar@gmail.com",
      password: "Anoth3rP@ss!456",
    });

    const encrypted = await encryptVault(vault, vaultKey);

    // Ensure it produced a ciphertext string and a timestamp
    expect(typeof encrypted.ciphertext).toBe("string");
    expect(encrypted.ciphertext.length).toBeGreaterThan(0);
    expect(encrypted.updatedAt).toBeGreaterThan(0);

    // Decrypt and verify all entries survived the round-trip
    const decrypted = await decryptVault(encrypted, vaultKey);
    expect(decrypted.entries).toHaveLength(2);
    expect(decrypted.entries[0].url).toBe("https://github.com");
    expect(decrypted.entries[0].username).toBe("sanskar@example.com");
    expect(decrypted.entries[0].password).toBe("S3cur3P@ss!123");
    expect(decrypted.entries[0].notes).toBe("Work account");
    expect(decrypted.entries[1].url).toBe("https://google.com");
    expect(decrypted.entries[1].password).toBe("Anoth3rP@ss!456");
  });

  test("encryptVault then decryptVault round-trips an empty vault", async () => {
    const vault = createVault();
    const encrypted = await encryptVault(vault, vaultKey);
    const decrypted = await decryptVault(encrypted, vaultKey);
    expect(decrypted.entries).toHaveLength(0);
  });

  test("decryptVault with wrong key throws", async () => {
    const vault = createVault();
    const encrypted = await encryptVault(vault, vaultKey);
    const wrongKey = await generateVaultKey();
    await expect(decryptVault(encrypted, wrongKey)).rejects.toThrow();
  });

  test("two calls to encryptVault produce different ciphertext (fresh IV per call)", async () => {
    const vault = createVault();
    const encrypted1 = await encryptVault(vault, vaultKey);
    const encrypted2 = await encryptVault(vault, vaultKey);

    // Same vault, same key → but different IVs → different ciphertexts
    expect(encrypted1.ciphertext).not.toBe(encrypted2.ciphertext);

    // Both still decrypt to the same vault
    const d1 = await decryptVault(encrypted1, vaultKey);
    const d2 = await decryptVault(encrypted2, vaultKey);
    expect(d1.entries).toHaveLength(0);
    expect(d2.entries).toHaveLength(0);
  });
});

// ─────────────────────────────────────────────────────────────
// Day 3 — Recovery Phrase Tests
// ─────────────────────────────────────────────────────────────

describe("Recovery Phrase Generation", () => {
  test("generateRecoveryPhrase returns exactly 24 words", async () => {
    const phrase = await generateRecoveryPhrase();
    const words = phrase.split(" ");
    expect(words).toHaveLength(24);
  });

  test("all 24 words are valid BIP39 words", async () => {
    const phrase = await generateRecoveryPhrase();
    const wordSet = new Set(BIP39_WORDLIST);
    const words = phrase.split(" ");
    for (const word of words) {
      expect(wordSet.has(word)).toBe(true);
    }
  });

  test("two generated phrases are different", async () => {
    const phrase1 = await generateRecoveryPhrase();
    const phrase2 = await generateRecoveryPhrase();
    // With 2^256 possible phrases, collision is astronomically unlikely
    expect(phrase1).not.toBe(phrase2);
  });
});

describe("Recovery Phrase Hashing", () => {
  test("hashRecoveryPhrase returns a 64-character hex string", async () => {
    const phrase = await generateRecoveryPhrase();
    const hash = await hashRecoveryPhrase(phrase);
    expect(hash).toHaveLength(64);
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  test("hashRecoveryPhrase is deterministic — same phrase → same hash", async () => {
    const phrase = await generateRecoveryPhrase();
    const hash1 = await hashRecoveryPhrase(phrase);
    const hash2 = await hashRecoveryPhrase(phrase);
    expect(hash1).toBe(hash2);
  });

  test("different phrases produce different hashes", async () => {
    const phrase1 = await generateRecoveryPhrase();
    const phrase2 = await generateRecoveryPhrase();
    const hash1 = await hashRecoveryPhrase(phrase1);
    const hash2 = await hashRecoveryPhrase(phrase2);
    expect(hash1).not.toBe(hash2);
  });
});

describe("Recovery KEK Derivation", () => {
  // Note: Argon2id is slow by design (64 MiB, 3 iterations).
  // These tests may take 2–5 seconds each on CI — that is expected and correct.
  jest.setTimeout(30_000);

  test("deriveRecoveryKEK returns exactly 32 bytes", async () => {
    const phrase = await generateRecoveryPhrase();
    const salt = await generateSalt();
    const kek = await deriveRecoveryKEK(phrase, salt);
    expect(kek).toHaveLength(32);
    expect(kek).toBeInstanceOf(Uint8Array);
  });

  test("same phrase + salt always derives the same KEK (deterministic)", async () => {
    const phrase = await generateRecoveryPhrase();
    const salt = await generateSalt();

    const kek1 = await deriveRecoveryKEK(phrase, salt);
    const kek2 = await deriveRecoveryKEK(phrase, salt);

    expect(Buffer.from(kek1).equals(Buffer.from(kek2))).toBe(true);
  });

  test("different phrases produce different KEKs", async () => {
    const phrase1 = await generateRecoveryPhrase();
    const phrase2 = await generateRecoveryPhrase();
    const salt = await generateSalt();

    const kek1 = await deriveRecoveryKEK(phrase1, salt);
    const kek2 = await deriveRecoveryKEK(phrase2, salt);

    expect(Buffer.from(kek1).equals(Buffer.from(kek2))).toBe(false);
  });
});

describe("Recovery Phrase Validation", () => {
  test("accepts a valid 24-word BIP39 phrase", async () => {
    const phrase = await generateRecoveryPhrase();
    const result = validateRecoveryPhrase(phrase);
    expect(result.valid).toBe(true);
    expect(result.error).toBeUndefined();
  });

  test("rejects phrase with wrong word count", () => {
    const result = validateRecoveryPhrase("abandon ability able");
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/24 words/i);
  });

  test("rejects phrase with invalid (non-BIP39) words", () => {
    // Build 24 words but replace one with a non-BIP39 word
    const words = Array(24).fill("abandon");
    words[5] = "notaword";
    const result = validateRecoveryPhrase(words.join(" "));
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/notaword/i);
  });

  test("rejects empty input", () => {
    expect(validateRecoveryPhrase("").valid).toBe(false);
    expect(validateRecoveryPhrase("   ").valid).toBe(false);
  });
});
