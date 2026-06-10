/**
 * ═══════════════════════════════════════════════════════════════════
 * Password Generator, Entropy Calculator, Breach Checker
 * ═══════════════════════════════════════════════════════════════════
 *
 * generatePassword():
 *   Uses crypto.getRandomValues() exclusively — NEVER Math.random().
 *   Employs rejection sampling to avoid modulo bias when selecting
 *   characters from the charset.
 *
 * calculateEntropy():
 *   Returns bits of entropy using: length × log2(charset_size).
 *   This measures the theoretical strength assuming the attacker knows
 *   the generation method but not the random seed.
 *
 * checkBreach():
 *   Uses the Have I Been Pwned API with k-anonymity:
 *   - SHA-1 hash the password locally
 *   - Send only the first 5 characters of the hash to the API
 *   - The full hash NEVER leaves the device
 *   - Parse the response to find if the suffix matches
 *   - Returns the count of times the password appeared in breaches
 * ═══════════════════════════════════════════════════════════════════
 */

import { webcrypto } from "crypto";
import { toHex } from "../utils/encoding";

/** Character sets for password generation */
const CHARSETS = {
  uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  lowercase: "abcdefghijklmnopqrstuvwxyz",
  numbers: "0123456789",
  symbols: "!@#$%^&*()_+-=[]{}|;:',.<>?/`~",
} as const;

/** Options for password generation */
export interface PasswordOptions {
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  numbers: boolean;
  symbols: boolean;
}

/**
 * Generate a cryptographically secure random password.
 *
 * Uses crypto.getRandomValues() for all randomness. Employs rejection
 * sampling to avoid modulo bias — we generate random bytes and only
 * use values that fall within a range evenly divisible by the charset
 * length. This ensures every character in the charset has an exactly
 * equal probability of being selected.
 *
 * @param options - Password generation options (length, character types)
 * @returns A random password string of the specified length
 * @throws Error if no character types are selected or length < 1
 */
export function generatePassword(options: PasswordOptions): string {
  const { length, uppercase, lowercase, numbers, symbols } = options;

  if (length < 1) {
    throw new Error("Password length must be at least 1");
  }

  // Build the charset from selected options
  let charset = "";
  if (uppercase) charset += CHARSETS.uppercase;
  if (lowercase) charset += CHARSETS.lowercase;
  if (numbers) charset += CHARSETS.numbers;
  if (symbols) charset += CHARSETS.symbols;

  if (charset.length === 0) {
    throw new Error(
      "At least one character type must be selected (uppercase, lowercase, numbers, or symbols)"
    );
  }

  const password: string[] = [];
  const charsetLength = charset.length;

  // Rejection sampling: find the largest multiple of charsetLength that fits
  // in a byte (256). Any random byte >= this threshold is rejected to avoid
  // modulo bias. For example, if charset has 62 chars, threshold = 256 - (256 % 62) = 248.
  // Values 0-247 map evenly to charset indices, values 248-255 are rejected.
  const threshold = 256 - (256 % charsetLength);

  for (let i = 0; i < length; i++) {
    let randomByte: number;

    // Keep generating random bytes until we get one below the threshold.
    // Expected iterations: ~1.0 per character (rejection rate < 1% for typical charsets).
    do {
      const buf = new Uint8Array(1);
      webcrypto.getRandomValues(buf);
      randomByte = buf[0];
    } while (randomByte >= threshold);

    password.push(charset[randomByte % charsetLength]);
  }

  return password.join("");
}

/**
 * Calculate the entropy (in bits) of a password given its charset.
 *
 * Formula: length × log2(charset_size)
 *
 * This measures the theoretical strength assuming the attacker knows
 * the generation method (which characters are possible) but not the
 * random seed or the specific password.
 *
 * Benchmarks for reference:
 * - 40 bits: trivially crackable
 * - 60 bits: weak, crackable by motivated attacker
 * - 80 bits: reasonable for most uses
 * - 100+ bits: strong
 * - 128+ bits: very strong
 *
 * @param password - The password to evaluate
 * @returns Bits of entropy as a number
 */
export function calculateEntropy(password: string): number {
  if (password.length === 0) return 0;

  // Determine the charset size by checking which character types are present
  let charsetSize = 0;
  if (/[a-z]/.test(password)) charsetSize += 26;
  if (/[A-Z]/.test(password)) charsetSize += 26;
  if (/[0-9]/.test(password)) charsetSize += 10;
  if (/[^a-zA-Z0-9]/.test(password)) charsetSize += 32; // common symbols

  if (charsetSize === 0) return 0;

  return password.length * Math.log2(charsetSize);
}

/**
 * Check if a password has appeared in known data breaches.
 *
 * Uses the Have I Been Pwned (HIBP) Pwned Passwords API v3 with
 * k-anonymity protection:
 *
 * 1. SHA-1 hash the password locally (never sent to the API)
 * 2. Send only the first 5 characters of the hash as a prefix
 * 3. The API returns all hash suffixes that start with that prefix
 * 4. We check if our full hash suffix appears in the results
 *
 * This means the FULL password hash NEVER leaves the device.
 * The API cannot determine which hash we were checking.
 *
 * @param password - The password to check
 * @returns Number of times the password appeared in breaches (0 = clean)
 * @throws Error if the API request fails
 */
export async function checkBreach(password: string): Promise<number> {
  try {
    // SHA-1 hash the password
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await webcrypto.subtle.digest("SHA-1", data);
    const hashHex = toHex(new Uint8Array(hashBuffer)).toUpperCase();

    // Split hash into prefix (first 5 chars) and suffix (remaining 35 chars)
    const prefix = hashHex.slice(0, 5);
    const suffix = hashHex.slice(5);

    // Query the HIBP API with only the prefix (k-anonymity)
    const response = await fetch(
      `https://api.pwnedpasswords.com/range/${prefix}`,
      {
        headers: {
          "User-Agent": "VaultZero-PasswordManager",
        },
      }
    );

    if (!response.ok) {
      throw new Error(`HIBP API returned status ${response.status}`);
    }

    const body = await response.text();

    // Response format: each line is "SUFFIX:COUNT"
    // Find our suffix in the response
    const lines = body.split("\n");
    for (const line of lines) {
      const [hashSuffix, count] = line.trim().split(":");
      if (hashSuffix === suffix) {
        return parseInt(count, 10);
      }
    }

    // Hash suffix not found in response — password is clean
    return 0;
  } catch (error) {
    if (
      error instanceof Error &&
      error.message.includes("HIBP API returned")
    ) {
      throw error;
    }
    throw new Error(
      `Breach check failed: ${error instanceof Error ? error.message : "network error"}`
    );
  }
}
