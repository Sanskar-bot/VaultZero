/**
 * ═══════════════════════════════════════════════════════════════════
 * Argon2id Key Derivation — Master Password → Key Encryption Key (KEK)
 * ═══════════════════════════════════════════════════════════════════
 *
 * WHAT IS ARGON2id?
 *   Argon2id is the winner of the Password Hashing Competition (2015).
 *   It is a hybrid of Argon2i (side-channel resistant) and Argon2d
 *   (GPU/ASIC resistant). The "id" variant provides the best of both
 *   worlds, making it the recommended choice for password hashing and
 *   key derivation (RFC 9106, OWASP 2024).
 *
 * WHY THESE PARAMETERS?
 *   - Memory: 64 MiB (65536 KiB)
 *     → Forces attackers to use ~64MB per guess, making GPU/ASIC attacks
 *       prohibitively expensive. This is the OWASP 2024 minimum for
 *       Argon2id. Higher is better if the client device can handle it.
 *
 *   - Iterations (time cost): 3
 *     → Each password guess requires 3 sequential passes over the 64MB
 *       memory region. Combined with the memory cost, this makes each
 *       guess take ~0.5–1 second on modern hardware.
 *
 *   - Parallelism: 1
 *     → Single-threaded derivation. We use 1 to keep behavior consistent
 *       across all client platforms (browser extension, mobile, web).
 *       Attackers don't gain a parallelism advantage.
 *
 *   - Output: 32 bytes (256 bits)
 *     → Exactly the key size needed for AES-256-GCM key wrapping.
 *
 * WHAT BREAKS IF SALT IS REUSED?
 *   If two users share the same salt, an attacker who cracks one user's
 *   password can instantly check whether other users have the same
 *   password (rainbow table / precomputation attack). Each user MUST
 *   have a unique random salt. The salt is stored server-side alongside
 *   the wrapped vault key — it is NOT secret (knowing the salt without
 *   the password is useless).
 *
 * SALT STORAGE:
 *   The salt is generated once during registration, stored on the server,
 *   and returned to the client on every login so any device can re-derive
 *   the KEK from the master password.
 * ═══════════════════════════════════════════════════════════════════
 */

import sodium from "libsodium-wrappers-sumo";

/** Argon2id parameters (OWASP 2024 minimum recommendations) */
const ARGON2_MEMORY_KIB = 65536; // 64 MiB
const ARGON2_ITERATIONS = 3;
const ARGON2_KEY_LENGTH = 32; // 256 bits for AES-256
const SALT_LENGTH = 16; // 128-bit salt

/**
 * Ensure libsodium is initialized before any crypto operations.
 * libsodium-wrappers requires an async `ready` promise to complete
 * before any functions can be called.
 */
async function ensureSodiumReady(): Promise<void> {
  await sodium.ready;
}

/**
 * Derive a 32-byte Key Encryption Key (KEK) from the user's master password.
 *
 * The KEK is used to wrap/unwrap the vault key — it is NEVER stored anywhere.
 * It exists only in memory while the user's vault is unlocked.
 *
 * @param masterPassword - The user's master password (plaintext, from their brain)
 * @param salt - 16-byte random salt (stored server-side, unique per user)
 * @returns 32-byte KEK as Uint8Array, suitable for AES-256-GCM key wrapping
 * @throws Error if libsodium fails or parameters are invalid
 */
export async function deriveKEK(
  masterPassword: string,
  salt: Uint8Array
): Promise<Uint8Array> {
  try {
    await ensureSodiumReady();

    if (!masterPassword) {
      throw new Error("Master password cannot be empty");
    }
    if (salt.length !== SALT_LENGTH) {
      throw new Error(
        `Salt must be exactly ${SALT_LENGTH} bytes, got ${salt.length}`
      );
    }

    // crypto_pwhash with ALG_ARGON2ID13 performs Argon2id key derivation.
    // It internally handles parallelism = 1 (libsodium's default for this API).
    const kek = sodium.crypto_pwhash(
      ARGON2_KEY_LENGTH,
      masterPassword,
      salt,
      ARGON2_ITERATIONS,
      ARGON2_MEMORY_KIB * 1024, // libsodium expects bytes, not KiB
      sodium.crypto_pwhash_ALG_ARGON2ID13
    );

    return kek;
  } catch (error) {
    // Re-throw with context if it's not already our error
    if (error instanceof Error && error.message.startsWith("Master password")) {
      throw error;
    }
    if (error instanceof Error && error.message.startsWith("Salt must")) {
      throw error;
    }
    throw new Error(
      `Argon2id key derivation failed: ${error instanceof Error ? error.message : "unknown error"}`
    );
  }
}

/**
 * Generate a cryptographically secure random salt for Argon2id.
 *
 * Called once during user registration. The salt is sent to the server
 * for storage and returned on login so any device can re-derive the KEK.
 *
 * @returns 16-byte random salt as Uint8Array
 */
export async function generateSalt(): Promise<Uint8Array> {
  await ensureSodiumReady();
  return sodium.randombytes_buf(SALT_LENGTH);
}
