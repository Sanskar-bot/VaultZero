/**
 * @vaultzero/core — Zero-knowledge crypto primitives
 *
 * This package contains ALL encryption logic for VaultZero.
 * It is used by the extension, web UI, and mobile apps.
 * The backend NEVER imports crypto functions from this package
 * (it only stores opaque blobs).
 *
 * Modules:
 * - crypto/argon2    — Argon2id key derivation (master password → KEK)
 * - crypto/aes-gcm   — AES-256-GCM encrypt/decrypt with fresh IV per call
 * - crypto/keys      — Vault key generation, wrapping, unwrapping
 * - vault/vault      — Vault serialization, encryption, decryption
 * - vault/types      — VaultEntry type definitions
 * - recovery/bip39   — BIP39-style recovery phrase generation
 * - utils/encoding   — Base64 / hex / Uint8Array conversion helpers
 */

export * from "./crypto";
export * from "./vault";
export * from "./recovery";
export * from "./utils";
