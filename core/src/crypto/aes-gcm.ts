/**
 * ═══════════════════════════════════════════════════════════════════
 * AES-256-GCM Symmetric Encryption (AEAD)
 * ═══════════════════════════════════════════════════════════════════
 *
 * Algorithm: AES-256-GCM (Galois/Counter Mode)
 *   - Provides both confidentiality AND authenticity (AEAD)
 *   - 256-bit key, 96-bit (12-byte) IV/nonce, 128-bit auth tag
 *   - The auth tag is appended to the ciphertext by Web Crypto API
 *
 * IV/Nonce strategy:
 *   - EVERY call to encryptData() generates a FRESH 12-byte random IV
 *     using crypto.getRandomValues() — NEVER Math.random()
 *   - IV is PREPENDED to the ciphertext output (first 12 bytes)
 *   - decryptData() reads the IV from the first 12 bytes before decrypting
 *
 * Output format:
 *   base64( IV[12 bytes] || ciphertext[N bytes] || authTag[16 bytes] )
 *   Web Crypto API appends the auth tag to the ciphertext automatically.
 *
 * What would break if misused:
 *   - Reusing an IV with the same key → catastrophic: attacker can
 *     recover plaintext via XOR of ciphertext blocks (GCM nonce reuse attack)
 *   - Not checking the auth tag → attacker can modify ciphertext undetected
 *   - Using CBC mode instead → no built-in authenticity, padding oracle attacks
 *
 * Implementation uses Web Crypto API (crypto.subtle) for AES-256-GCM,
 * which is available in Node.js 18+ and all modern browsers. This avoids
 * the AES-NI hardware requirement of libsodium's crypto_aead_aes256gcm.
 * ═══════════════════════════════════════════════════════════════════
 */

import { webcrypto } from "crypto";
import { toBase64, fromBase64, utf8Encode, utf8Decode } from "../utils/encoding";

/** Use Node.js's webcrypto CryptoKey type */
type CryptoKey = webcrypto.CryptoKey;


/** AES-GCM uses a 12-byte (96-bit) IV/nonce — the standard for GCM mode */
const IV_LENGTH = 12;

/** AES-256 requires a 32-byte (256-bit) key */
const KEY_LENGTH = 32;

/** Algorithm identifier for Web Crypto API */
const ALGORITHM = "AES-GCM";

/**
 * Import a raw 32-byte key into a Web Crypto CryptoKey object.
 *
 * This is an internal helper — the rest of the codebase works with
 * Uint8Array keys. The CryptoKey is only needed for crypto.subtle calls.
 *
 * @param rawKey - 32-byte AES-256 key as Uint8Array
 * @returns CryptoKey usable for AES-GCM encrypt/decrypt
 */
async function importAesKey(rawKey: Uint8Array): Promise<CryptoKey> {
  if (rawKey.length !== KEY_LENGTH) {
    throw new Error(
      `AES-256 key must be exactly ${KEY_LENGTH} bytes, got ${rawKey.length}`
    );
  }

  return webcrypto.subtle.importKey(
    "raw",
    rawKey,
    { name: ALGORITHM },
    false, // not extractable — we already have the raw bytes
    ["encrypt", "decrypt"]
  );
}

/**
 * Encrypt plaintext with AES-256-GCM.
 *
 * Generates a FRESH random 12-byte IV for every call. The IV is prepended
 * to the ciphertext so the decryptor can extract it. The auth tag (16 bytes)
 * is appended by Web Crypto automatically.
 *
 * Output: base64( IV[12] || ciphertext || authTag[16] )
 *
 * @param plaintext - The string to encrypt (e.g., JSON-serialized vault)
 * @param key - 32-byte AES-256 key as Uint8Array
 * @returns Base64-encoded string containing IV + ciphertext + auth tag
 * @throws Error if encryption fails or key is invalid
 */
export async function encryptData(
  plaintext: string,
  key: Uint8Array
): Promise<string> {
  try {
    const cryptoKey = await importAesKey(key);

    // Generate a FRESH random IV for every encryption call.
    // This is critical: reusing an IV with the same key in GCM mode
    // allows an attacker to recover plaintext.
    const iv = webcrypto.getRandomValues(new Uint8Array(IV_LENGTH));

    const plaintextBytes = utf8Encode(plaintext);

    const ciphertextBuffer = await webcrypto.subtle.encrypt(
      { name: ALGORITHM, iv },
      cryptoKey,
      plaintextBytes
    );

    // Combine IV + ciphertext+authTag into a single buffer
    const ciphertextBytes = new Uint8Array(ciphertextBuffer);
    const combined = new Uint8Array(IV_LENGTH + ciphertextBytes.length);
    combined.set(iv, 0);
    combined.set(ciphertextBytes, IV_LENGTH);

    return toBase64(combined);
  } catch (error) {
    if (error instanceof Error && error.message.includes("key must be")) {
      throw error;
    }
    throw new Error(
      `AES-256-GCM encryption failed: ${error instanceof Error ? error.message : "unknown error"}`
    );
  }
}

/**
 * Decrypt AES-256-GCM ciphertext back to plaintext.
 *
 * Reads the 12-byte IV from the start of the ciphertext, then decrypts
 * the remainder. If the key is wrong or data has been tampered with,
 * the GCM authentication check will FAIL and this function will throw
 * an explicit error — it will NEVER return garbage data.
 *
 * @param ciphertext - Base64-encoded string from encryptData()
 * @param key - 32-byte AES-256 key (must match the key used to encrypt)
 * @returns The original plaintext string
 * @throws Error with clear message if decryption fails (wrong key, tampered data)
 */
export async function decryptData(
  ciphertext: string,
  key: Uint8Array
): Promise<string> {
  try {
    const cryptoKey = await importAesKey(key);

    const combined = fromBase64(ciphertext);

    if (combined.length < IV_LENGTH + 1) {
      throw new Error(
        "Ciphertext too short — expected at least IV (12 bytes) + 1 byte of data"
      );
    }

    // Split IV from ciphertext+authTag
    const iv = combined.slice(0, IV_LENGTH);
    const encryptedData = combined.slice(IV_LENGTH);

    const plaintextBuffer = await webcrypto.subtle.decrypt(
      { name: ALGORITHM, iv },
      cryptoKey,
      encryptedData
    );

    return utf8Decode(new Uint8Array(plaintextBuffer));
  } catch (error) {
    if (error instanceof Error && error.message.includes("key must be")) {
      throw error;
    }
    if (error instanceof Error && error.message.includes("Ciphertext too short")) {
      throw error;
    }
    // Web Crypto throws an OperationError when GCM auth tag verification fails.
    // This means either the key is wrong or the data has been tampered with.
    throw new Error(
      "Decryption failed: wrong key or data has been tampered with (AES-GCM authentication failed)"
    );
  }
}
