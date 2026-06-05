/**
 * Vault Operations — Encrypt/Decrypt the entire vault as a single blob
 *
 * Flow:
 * 1. Vault (VaultEntry[]) → JSON.stringify → UTF-8 bytes
 * 2. UTF-8 bytes → AES-256-GCM encrypt with Vault Key → ciphertext blob
 * 3. Ciphertext blob → Base64 encode → send to server
 *
 * Decryption is the reverse. If the Vault Key is wrong, AES-GCM will
 * throw an authentication error (never silently return garbage).
 *
 * Implementation: Day 2
 */

// TODO: Day 2 — implement encryptVault(vault, vaultKey) → string (base64 ciphertext)
// TODO: Day 2 — implement decryptVault(ciphertext, vaultKey) → Vault

export {};
