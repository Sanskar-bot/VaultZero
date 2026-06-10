/**
 * ═══════════════════════════════════════════════════════════════════
 * src/lib/recovery.ts — Recovery Phrase Utilities (Server-Side)
 * ═══════════════════════════════════════════════════════════════════
 *
 * Functions:
 *   generateRecoveryPhrase()  — 24 BIP39 words, crypto-random selection
 *   hashRecoveryPhrase()      — SHA-256 of normalized phrase (stored in DB)
 *   deriveRecoveryKEK()       — Argon2id with static salt → CryptoKey
 *
 * ZERO-KNOWLEDGE NOTES:
 *   - generateRecoveryPhrase() is called client-side in production.
 *     This server-side version exists for testing and CLI tooling.
 *   - The raw phrase is NEVER stored anywhere — only its SHA-256 hash.
 *   - deriveRecoveryKEK uses a STATIC SALT so derivation is deterministic.
 *     Security comes from the phrase entropy (~256 bits for 24 BIP39 words).
 *     The static salt is public knowledge — changing it after deployment
 *     would invalidate ALL existing recovery phrases.
 *
 * TIMING ATTACK NOTE:
 *   Hash comparison in recovery/verify MUST use crypto.timingSafeEqual().
 *   Do not use string === comparison — it leaks timing information.
 * ═══════════════════════════════════════════════════════════════════
 */

import crypto from "crypto";
import argon2 from "argon2";
import { BIP39_WORDLIST } from "@vaultzero/core";

// ── Constants ─────────────────────────────────────────────────────────────────

const PHRASE_WORD_COUNT = 24;

/**
 * Static Argon2id salt for recovery KEK derivation.
 *
 * This MUST be static (not random) so recovery is deterministic:
 * the same phrase always produces the same KEK.
 *
 * Security model: The 24-word BIP39 phrase provides ~256 bits of entropy.
 * The Argon2id parameters make brute-force expensive on both CPU and GPU.
 * The static salt does NOT weaken security for this use case because we
 * are NOT defending against mass rainbow-table attacks on many users
 * (each user's wrapped vault key is different).
 *
 * ⚠️ NEVER change this value after production deployment.
 *    Changing it makes ALL existing recovery phrases permanently invalid.
 */
const RECOVERY_KEK_STATIC_SALT = Buffer.from(
  "5661756c745a65726f526563486578536c74323032340000000000000000", // "VaultZeroRecHexSlt2024" + padding
  "hex"
);

/** Argon2id parameters — identical to core/src/crypto/argon2.ts */
const ARGON2_PARAMS = {
  type: argon2.argon2id,
  memoryCost: 65536,   // 64 MiB
  timeCost: 3,
  parallelism: 1,
  hashLength: 32,      // 256-bit output → AES-256-GCM key
  salt: RECOVERY_KEK_STATIC_SALT,
};

// ── Functions ─────────────────────────────────────────────────────────────────

/**
 * Generate a 24-word BIP39 recovery phrase using CSPRNG.
 *
 * Uses crypto.randomBytes (never Math.random).
 * Rejection sampling ensures uniform distribution across the 2048-word list.
 *
 * @returns Space-separated 24-word string
 */
export function generateRecoveryPhrase(): string {
  const words: string[] = [];

  for (let i = 0; i < PHRASE_WORD_COUNT; i++) {
    let index: number;
    // Rejection sampling: ensure uniform distribution
    // 2048 = 2^11, so values 0–2047 are all valid (no bias needed)
    // but use 2 bytes (0–65535) and reject values ≥ 65536 - (65536 % 2048)
    const LIMIT = 65536 - (65536 % BIP39_WORDLIST.length);
    do {
      const bytes = crypto.randomBytes(2);
      index = (bytes[0] << 8) | bytes[1];
    } while (index >= LIMIT);

    words.push(BIP39_WORDLIST[index % BIP39_WORDLIST.length]);
  }

  return words.join(" ");
}

/**
 * SHA-256 hash a recovery phrase for safe database storage.
 *
 * Normalisation: lowercase + trim before hashing.
 * This makes comparison case-insensitive and whitespace-tolerant.
 *
 * ONLY the hash is ever stored on the server.
 * The raw phrase is never persisted anywhere.
 *
 * @param phrase - Raw recovery phrase (e.g. "abandon ability able ...")
 * @returns 64-character hex SHA-256 digest
 */
export function hashRecoveryPhrase(phrase: string): string {
  const normalised = phrase.trim().toLowerCase();
  return crypto.createHash("sha256").update(normalised, "utf8").digest("hex");
}

/**
 * Derive a recovery Key Encryption Key (KEK) from the recovery phrase.
 *
 * Uses Argon2id with a STATIC salt so derivation is deterministic:
 * the same phrase always produces the same 256-bit key.
 *
 * The returned CryptoKey can be used to unwrapKey() a wrapped vault key.
 *
 * @param phrase - Raw recovery phrase
 * @returns AES-256-GCM CryptoKey (not extractable, for unwrapKey only)
 */
export async function deriveRecoveryKEK(phrase: string): Promise<Awaited<ReturnType<typeof globalThis.crypto.subtle.importKey>>> {
  const normalised = phrase.trim().toLowerCase();

  // Run Argon2id with static salt — expensive on purpose (64 MiB, 3 iterations)
  const rawKeyBytes = await argon2.hash(normalised, {
    ...ARGON2_PARAMS,
    raw: true, // return raw Buffer, not encoded string
  }) as Buffer;

  // Import raw bytes as a Web Crypto AES-256-GCM key
  return globalThis.crypto.subtle.importKey(
    "raw",
    rawKeyBytes,
    { name: "AES-GCM", length: 256 },
    false,               // not extractable — key bytes cannot be read back out
    ["wrapKey", "unwrapKey"]
  );
}
