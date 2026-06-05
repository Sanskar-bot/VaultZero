/**
 * AES-256-GCM Symmetric Encryption
 *
 * Algorithm: AES-256-GCM (Galois/Counter Mode)
 * - Provides both confidentiality AND authenticity (AEAD)
 * - 256-bit key, 96-bit (12-byte) IV/nonce, 128-bit auth tag
 *
 * IV/Nonce approach:
 * - EVERY call to encrypt() generates a FRESH 12-byte random IV
 *   using crypto.getRandomValues() — NEVER Math.random()
 * - IV is PREPENDED to the ciphertext output (first 12 bytes)
 * - Decrypt reads the IV from the first 12 bytes before decrypting
 *
 * What would break if misused:
 * - Reusing an IV with the same key → catastrophic: attacker can
 *   recover plaintext via XOR of ciphertext blocks (GCM nonce reuse attack)
 * - Not checking the auth tag → attacker can modify ciphertext undetected
 * - Using CBC mode instead → no built-in authenticity, padding oracle attacks
 *
 * Implementation: Day 2
 */

// TODO: Day 2 — implement encrypt(plaintext, key) → Uint8Array (IV || ciphertext || tag)
// TODO: Day 2 — implement decrypt(blob, key) → Uint8Array (throws on wrong key / tampered data)

export {};
