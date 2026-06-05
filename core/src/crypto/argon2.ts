/**
 * Argon2id Key Derivation
 *
 * Derives a 32-byte Key Encryption Key (KEK) from the user's master password.
 *
 * Algorithm: Argon2id (hybrid of Argon2i and Argon2d)
 * - Resistant to both side-channel and GPU/ASIC attacks
 * - Uses libsodium's crypto_pwhash which implements Argon2id
 *
 * Parameters (OWASP 2024 recommendations):
 * - Memory: 64 MiB (crypto_pwhash_MEMLIMIT_MODERATE)
 * - Iterations: 3 (crypto_pwhash_OPSLIMIT_MODERATE)
 * - Output: 32 bytes (256-bit KEK)
 * - Salt: 16 bytes random (generated per-user, stored server-side)
 *
 * What would break if misused:
 * - Reusing salts across users → rainbow table attacks
 * - Low memory/iterations → brute-force becomes feasible
 * - Outputting < 32 bytes → insufficient key material for AES-256
 *
 * Implementation: Day 2
 */

// TODO: Day 2 — implement deriveKEK(masterPassword, salt) → Uint8Array(32)
// TODO: Day 2 — implement generateSalt() → Uint8Array(16)

export {};
