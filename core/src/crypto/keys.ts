/**
 * Key Management — Vault Key Generation, Wrapping, Unwrapping
 *
 * Key hierarchy:
 *   Master Password (user's brain, never stored)
 *     └─→ Argon2id → KEK (Key Encryption Key, 32 bytes, ephemeral in memory)
 *           └─→ wraps → Vault Key (random 32 bytes, encrypted at rest)
 *                 └─→ encrypts → each VaultEntry via AES-256-GCM
 *
 * Why a separate Vault Key?
 * - Changing the master password only requires re-wrapping the Vault Key
 *   with the new KEK, not re-encrypting the entire vault
 * - Recovery phrase can derive an alternative KEK to unwrap the same Vault Key
 *
 * Wrapping uses AES-256-GCM (same as vault encryption):
 * - wrap(vaultKey, kek)   → encrypted vault key blob (IV prepended)
 * - unwrap(blob, kek)     → raw vault key (throws on wrong KEK)
 *
 * Implementation: Day 2
 */

// TODO: Day 2 — implement generateVaultKey() → Uint8Array(32)
// TODO: Day 2 — implement wrapVaultKey(vaultKey, kek) → Uint8Array
// TODO: Day 2 — implement unwrapVaultKey(wrappedKey, kek) → Uint8Array

export {};
