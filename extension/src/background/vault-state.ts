/**
 * src/background/vault-state.ts — In-Memory Vault State
 *
 * This module is the single source of truth for the vault's runtime state.
 * It holds the decrypted vault and vault key IN MEMORY ONLY.
 *
 * ═══════════════════════════════════════════════════════
 * CRITICAL SECURITY INVARIANTS (never violate these):
 * ═══════════════════════════════════════════════════════
 *
 * 1. NEVER persist state to chrome.storage.local, localStorage,
 *    IndexedDB, or any other storage mechanism.
 *    vault and vaultKey must ONLY exist in this module's closure.
 *
 * 2. vaultKey is a Uint8Array of raw key bytes. The caller MUST
 *    ensure it was generated with a CSPRNG (crypto.getRandomValues).
 *    Once setLocked() is called, the reference is set to null —
 *    the GC will eventually zero or reclaim the memory.
 *    ⚠️ NOTE: JavaScript's GC does NOT guarantee immediate zeroing
 *    of ArrayBuffers. In a higher-security context you'd use
 *    SecureMemory (not available in browsers). Setting to null is
 *    the best we can do in a standard browser extension.
 *
 * 3. The vaultKey Uint8Array was derived from the user's master
 *    password and is NOT extractable to an external context.
 *    It is passed as a raw Uint8Array (not a CryptoKey) because
 *    @vaultzero/core's crypto functions use libsodium, which works
 *    with raw Uint8Arrays rather than the Web Crypto CryptoKey API.
 *
 * 4. vault.entries contain PLAINTEXT passwords. Once setLocked() is
 *    called, the vault reference is nulled out. Any code holding a
 *    stale reference to a VaultStore will still have entries in
 *    memory until GC — this is acceptable given the module boundary.
 *
 * 5. Service worker restart resilience:
 *    When Chrome kills the service worker (idle timeout, update, etc.),
 *    ALL module-level variables reset to their initial values.
 *    This means state.locked = true and state.vault = null automatically.
 *    The user must re-enter their master password to unlock.
 *    ✅ THIS IS A FEATURE, NOT A BUG — equivalent to a screen lock.
 */

import type { VaultStore } from "../shared/types";

export interface VaultState {
  locked:       boolean;
  vaultKey:     Uint8Array | null;  // raw 32-byte AES-256 key, never serialised
  vault:        VaultStore | null;  // plaintext entries, memory only
  lastActivity: number;             // Date.now() timestamp for idle detection
}

// Module-level singleton — intentionally not exported (callers use functions)
const state: VaultState = {
  locked:       true,
  vaultKey:     null,
  vault:        null,
  lastActivity: 0,
};

/** Read the entire vault state (for debugging / serialisation-free inspection) */
export function getState(): Readonly<VaultState> {
  return state;
}

/**
 * Transition to UNLOCKED state.
 *
 * Called after successful Argon2id derivation + vault key unwrap + vault decrypt.
 * Stores the vault key and decrypted vault in module memory.
 *
 * ⚠️ SECURITY: vaultKey MUST be a Uint8Array from crypto.getRandomValues or
 *   derived via libsodium — not a hardcoded or user-supplied value.
 *
 * @param vaultKey - 32-byte AES-256 vault key (raw bytes, NOT a CryptoKey)
 * @param vault    - Decrypted vault (plaintext entries)
 */
export function setUnlocked(vaultKey: Uint8Array, vault: VaultStore): void {
  state.locked       = false;
  state.vaultKey     = vaultKey;
  state.vault        = vault;
  state.lastActivity = Date.now();
}

/**
 * Transition to LOCKED state — clears all sensitive data.
 *
 * Sets vaultKey and vault to null. This removes the JS references,
 * allowing GC to eventually reclaim the memory. While JS doesn't
 * guarantee immediate zeroing, this is the best available mechanism.
 *
 * Also called automatically by the auto-lock timer after 5 minutes idle.
 */
export function setLocked(): void {
  state.locked       = true;
  state.vaultKey     = null;
  state.vault        = null;
  state.lastActivity = 0;
}

/**
 * Update the lastActivity timestamp to now.
 * Called on any user-initiated message (click, autofill, etc.)
 * to reset the idle auto-lock countdown.
 */
export function updateActivity(): void {
  state.lastActivity = Date.now();
}

/** Update the in-memory vault (after add/edit/delete — before sync) */
export function setVault(vault: VaultStore): void {
  if (state.locked) {
    throw new Error("Cannot update vault while locked");
  }
  state.vault = vault;
}

/** Check if the vault is currently locked */
export function isLocked(): boolean {
  return state.locked;
}

/** Get the vault key — returns null if locked */
export function getVaultKey(): Uint8Array | null {
  return state.vaultKey;
}

/** Get the decrypted vault — returns null if locked */
export function getVault(): VaultStore | null {
  return state.vault;
}
