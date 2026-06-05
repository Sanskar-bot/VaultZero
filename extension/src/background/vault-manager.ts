/**
 * Vault Manager — manages the decrypted vault lifecycle in the service worker
 *
 * - unlock(masterPassword) → derives KEK, unwraps vault key, decrypts vault
 * - lock() → scrubs all key material and vault data from memory
 * - getCredentials(url) → returns matching entries for a domain
 * - saveEntry(entry) → adds/updates entry, re-encrypts, pushes to server
 *
 * SECURITY: Memory scrubbing overwrites Uint8Arrays with zeros before GC.
 *
 * Implementation: Day 7-8
 */

// TODO: Day 7-8 — implement VaultManager class
