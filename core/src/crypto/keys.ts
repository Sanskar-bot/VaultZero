/**
 * ═══════════════════════════════════════════════════════════════════
 * Key Management — Vault Key Generation, Wrapping, Unwrapping
 * ═══════════════════════════════════════════════════════════════════
 *
 * Key hierarchy:
 *   Master Password (user's brain, never stored)
 *     └─→ Argon2id → KEK (Key Encryption Key, 32 bytes, ephemeral in memory)
 *           └─→ wraps → Vault Key (random 32 bytes, encrypted at rest)
 *                 └─→ encrypts → each VaultEntry via AES-256-GCM
 *
 * Why a separate Vault Key?
 *   - Changing the master password only requires re-wrapping the Vault Key
 *     with the new KEK, not re-encrypting the entire vault
 *   - Recovery phrase can derive an alternative KEK to unwrap the same Vault Key
 *   - If a device is compromised, the vault key can be rotated independently
 *
 * Wrapping uses AES-256-GCM (same as vault encryption):
 *   - wrapVaultKey(vaultKey, kek)    → base64(IV + encrypted_key + auth_tag)
 *   - unwrapVaultKey(wrappedKey, kek) → raw 32-byte vault key
 *   - unwrap throws explicitly on wrong KEK (GCM auth tag check fails)
 *
 * The vault key is generated ONCE during registration and wrapped with the
 * user's KEK. The wrapped (encrypted) vault key is stored on the server.
 * The raw vault key NEVER leaves the client device in plaintext.
 * ═══════════════════════════════════════════════════════════════════
 */

import { webcrypto } from "crypto";
import { encryptData, decryptData } from "./aes-gcm";
import { toBase64, fromBase64 } from "../utils/encoding";

/** AES-256 key length in bytes */
const VAULT_KEY_LENGTH = 32;

/**
 * Generate a random AES-256-GCM vault key.
 *
 * This key is used to encrypt/decrypt all vault entries. It is generated
 * ONCE during user registration, wrapped (encrypted) with the KEK derived
 * from the user's master password, and the wrapped version is stored on
 * the server.
 *
 * Uses crypto.getRandomValues() for cryptographic randomness — NEVER Math.random().
 *
 * @returns 32-byte random key as Uint8Array
 */
export async function generateVaultKey(): Promise<Uint8Array> {
  return webcrypto.getRandomValues(new Uint8Array(VAULT_KEY_LENGTH));
}

/**
 * Wrap (encrypt) the vault key with the KEK.
 *
 * The vault key (32 bytes) is treated as plaintext and encrypted using
 * AES-256-GCM with the KEK as the encryption key. A fresh IV is generated
 * for each wrap call.
 *
 * The wrapped key is what gets stored on the server — the server cannot
 * decrypt it because it doesn't know the KEK (which is derived from the
 * master password that never leaves the client).
 *
 * @param vaultKey - 32-byte vault key to wrap
 * @param kek - 32-byte Key Encryption Key (from Argon2id)
 * @returns Base64 string of the wrapped (encrypted) vault key
 * @throws Error if wrapping fails
 */
export async function wrapVaultKey(
  vaultKey: Uint8Array,
  kek: Uint8Array
): Promise<string> {
  try {
    if (vaultKey.length !== VAULT_KEY_LENGTH) {
      throw new Error(
        `Vault key must be exactly ${VAULT_KEY_LENGTH} bytes, got ${vaultKey.length}`
      );
    }

    // Convert vault key bytes to a base64 string, then encrypt that string.
    // This reuses the same encryptData() function used for vault contents,
    // ensuring consistent encryption behavior (fresh IV, auth tag, etc.).
    const vaultKeyBase64 = toBase64(vaultKey);
    return await encryptData(vaultKeyBase64, kek);
  } catch (error) {
    if (error instanceof Error && error.message.includes("Vault key must")) {
      throw error;
    }
    throw new Error(
      `Failed to wrap vault key: ${error instanceof Error ? error.message : "unknown error"}`
    );
  }
}

/**
 * Unwrap (decrypt) the vault key using the KEK.
 *
 * Decrypts the wrapped vault key back to the raw 32-byte key. If the KEK
 * is wrong (e.g., wrong master password was used), the AES-GCM auth tag
 * check will fail and this function will throw an explicit error.
 *
 * This NEVER returns garbage data — it either returns the correct key
 * or throws.
 *
 * @param wrappedKey - Base64 string from wrapVaultKey()
 * @param kek - 32-byte Key Encryption Key (from Argon2id)
 * @returns 32-byte vault key as Uint8Array
 * @throws Error if KEK is wrong or wrapped key data is tampered with
 */
export async function unwrapVaultKey(
  wrappedKey: string,
  kek: Uint8Array
): Promise<Uint8Array> {
  try {
    const vaultKeyBase64 = await decryptData(wrappedKey, kek);
    const vaultKey = fromBase64(vaultKeyBase64);

    if (vaultKey.length !== VAULT_KEY_LENGTH) {
      throw new Error(
        `Unwrapped vault key has invalid length: expected ${VAULT_KEY_LENGTH}, got ${vaultKey.length}`
      );
    }

    return vaultKey;
  } catch (error) {
    if (
      error instanceof Error &&
      error.message.includes("Unwrapped vault key")
    ) {
      throw error;
    }
    throw new Error(
      "Failed to unwrap vault key: wrong KEK or wrapped key has been tampered with"
    );
  }
}
