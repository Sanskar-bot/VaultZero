/**
 * ═══════════════════════════════════════════════════════════════════
 * BIP39-style Recovery Phrase — Generation, Hashing, KEK Derivation
 * ═══════════════════════════════════════════════════════════════════
 *
 * WHAT IS A RECOVERY PHRASE?
 *   A 24-word mnemonic generated from cryptographically secure randomness.
 *   It provides a human-writable backup that can restore vault access if
 *   the master password is forgotten.
 *
 * ENTROPY MODEL:
 *   - 24 random words × 11 bits each = 264 bits total
 *   - First 256 bits = entropy  |  Last 8 bits = checksum
 *   - 2^256 possible phrases ≈ 10^77  (effectively unguessable)
 *
 * SECURITY INVARIANTS:
 *   - Phrase is shown ONCE at registration → user writes it on paper
 *   - Phrase is NEVER stored in plaintext anywhere (not client, not server)
 *   - Server stores only SHA-256(phrase) for recovery verification
 *   - Recovery KEK is derived from phrase via Argon2id (same as master password)
 *
 * RECOVERY FLOW (when master password is forgotten):
 *   1. User enters 24-word phrase
 *   2. Client: SHA-256(phrase) → sends to server to verify
 *   3. Server verifies hash match, returns wrapped_vault_key
 *   4. Client: Argon2id(phrase, salt) → recoveryKEK
 *   5. Client: AES-GCM.decrypt(wrapped_vault_key, recoveryKEK) → vaultKey
 *   6. Client: prompts new master password → new KEK → re-wraps vaultKey
 *   7. Client: pushes new wrapped_vault_key to server
 *   8. Server: AUDIT_LOG: RECOVERY_USED
 *
 * WHY ARGON2id FOR THE RECOVERY KEK?
 *   The 24-word phrase, while long, is a structured string. Using a raw
 *   SHA-256 or HKDF would make brute-force attacks feasible on GPUs.
 *   Argon2id with the same parameters as the master password KDF forces
 *   ~64 MiB RAM per guess, making attacks prohibitively expensive.
 * ═══════════════════════════════════════════════════════════════════
 */

import { webcrypto } from "crypto";
import { BIP39_WORDLIST } from "./wordlist";
import { deriveKEK } from "../crypto/argon2";
import { toHex } from "../utils/encoding";

/** Number of words in a recovery phrase */
const PHRASE_WORD_COUNT = 24;

/** Number of bits encoded per word (log2 of 2048) */
const BITS_PER_WORD = 11;

/** Total entropy bits: 24 words × 11 bits = 264 bits, but we use 256 for the random source */
const ENTROPY_BYTES = 32; // 256 bits

/**
 * Generate a cryptographically secure 24-word BIP39-style recovery phrase.
 *
 * Algorithm:
 *   1. Generate 32 bytes (256 bits) of secure random entropy
 *   2. Compute SHA-256 checksum of the entropy
 *   3. Append first 8 bits of checksum to entropy → 264 bits total
 *   4. Split 264 bits into 24 groups of 11 bits
 *   5. Each 11-bit group indexes into the 2048-word BIP39 wordlist
 *   6. Join words with spaces
 *
 * This matches the BIP39 specification exactly, ensuring compatibility
 * with hardware wallets and other BIP39-compliant tools if needed.
 *
 * @returns A 24-word recovery phrase as a space-separated string
 */
export async function generateRecoveryPhrase(): Promise<string> {
  // Step 1: Generate 256 bits of cryptographic randomness
  const entropy = webcrypto.getRandomValues(new Uint8Array(ENTROPY_BYTES));

  // Step 2: SHA-256 checksum of entropy
  const hashBuffer = await webcrypto.subtle.digest("SHA-256", entropy);
  const checksum = new Uint8Array(hashBuffer);

  // Step 3: Build a bit array from entropy + first byte of checksum
  // entropy = 256 bits, checksum byte = 8 bits → 264 bits total = 24 × 11
  const bits: number[] = [];

  for (const byte of entropy) {
    for (let bit = 7; bit >= 0; bit--) {
      bits.push((byte >> bit) & 1);
    }
  }

  // Append first 8 bits of checksum
  const checksumByte = checksum[0];
  for (let bit = 7; bit >= 0; bit--) {
    bits.push((checksumByte >> bit) & 1);
  }

  // Step 4 & 5: Group into 11-bit chunks and map to words
  const words: string[] = [];
  for (let i = 0; i < PHRASE_WORD_COUNT; i++) {
    let index = 0;
    for (let j = 0; j < BITS_PER_WORD; j++) {
      index = (index << 1) | bits[i * BITS_PER_WORD + j];
    }
    words.push(BIP39_WORDLIST[index]);
  }

  return words.join(" ");
}

/**
 * Hash a recovery phrase with SHA-256 for server-side verification.
 *
 * The server stores ONLY this hash — never the phrase itself.
 * During recovery, the client hashes the user-entered phrase and sends
 * it to the server to verify it matches before proceeding.
 *
 * Using SHA-256 here (not Argon2id) is intentional:
 * - This hash is for VERIFICATION only (does the phrase match?)
 * - The actual security against brute-force is handled by Argon2id
 *   in deriveRecoveryKEK() — you need the KEK to unwrap the vault key
 * - SHA-256 is fast enough for server verification without being a
 *   bottleneck on every API call
 *
 * @param phrase - The 24-word recovery phrase (space-separated)
 * @returns Lowercase hex string of the SHA-256 digest (64 characters)
 */
export async function hashRecoveryPhrase(phrase: string): Promise<string> {
  if (!phrase || !phrase.trim()) {
    throw new Error("Recovery phrase cannot be empty");
  }

  const encoder = new TextEncoder();
  const data = encoder.encode(phrase.trim().toLowerCase());
  const hashBuffer = await webcrypto.subtle.digest("SHA-256", data);

  return toHex(new Uint8Array(hashBuffer));
}

/**
 * Derive a 32-byte Key Encryption Key (KEK) from the recovery phrase.
 *
 * This is the function that makes recovery possible:
 * - During registration, the same salt used for the master password KEK
 *   is ALSO used to derive a recovery KEK from the phrase
 * - The vault key is wrapped with BOTH the master KEK and this recovery KEK
 *   (stored as two separate wrappedVaultKey values on the server)
 * - During recovery, the user enters the phrase → we derive this KEK →
 *   unwrap the vault key → re-wrap with a new master KEK
 *
 * Uses Argon2id with the same parameters as deriveKEK() to ensure the
 * phrase is equally hard to brute-force as the master password.
 *
 * @param phrase - The 24-word recovery phrase (space-separated)
 * @param salt - 16-byte salt (same salt as used for the master password KEK)
 * @returns 32-byte recovery KEK as Uint8Array
 * @throws Error if Argon2id derivation fails
 */
export async function deriveRecoveryKEK(
  phrase: string,
  salt: Uint8Array
): Promise<Uint8Array> {
  if (!phrase || !phrase.trim()) {
    throw new Error("Recovery phrase cannot be empty");
  }

  // Normalize phrase: trim whitespace and lowercase
  // This allows users to enter words with mixed case or extra spaces
  const normalizedPhrase = phrase.trim().toLowerCase().replace(/\s+/g, " ");

  // Reuse deriveKEK() — the recovery phrase is treated as a "password"
  // for Argon2id. The same memory-hard parameters apply.
  return deriveKEK(normalizedPhrase, salt);
}

/**
 * Validate that a phrase consists of exactly 24 valid BIP39 words.
 *
 * Used to give the user early feedback if they mis-type a word during
 * recovery, before attempting the expensive Argon2id derivation.
 *
 * @param phrase - The phrase to validate (space-separated words)
 * @returns Object with `valid` boolean and optional `error` message
 */
export function validateRecoveryPhrase(phrase: string): {
  valid: boolean;
  error?: string;
} {
  if (!phrase || !phrase.trim()) {
    return { valid: false, error: "Recovery phrase cannot be empty" };
  }

  const words = phrase.trim().toLowerCase().split(/\s+/);

  if (words.length !== PHRASE_WORD_COUNT) {
    return {
      valid: false,
      error: `Recovery phrase must be exactly ${PHRASE_WORD_COUNT} words, got ${words.length}`,
    };
  }

  const wordSet = new Set(BIP39_WORDLIST);
  const invalidWords = words.filter((w) => !wordSet.has(w));

  if (invalidWords.length > 0) {
    return {
      valid: false,
      error: `Unknown word(s) in recovery phrase: ${invalidWords.join(", ")}`,
    };
  }

  return { valid: true };
}
