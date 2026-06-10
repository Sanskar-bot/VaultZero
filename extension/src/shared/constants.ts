/**
 * src/shared/constants.ts — Extension-Wide Constants
 *
 * STORAGE SECURITY MODEL:
 *
 *   chrome.storage.local (encrypted by OS, persists across restarts):
 *     ✅ JWT token            — needed to call backend; expires in 15 min
 *     ✅ Refresh token        — needed to get new JWTs; single-use
 *     ✅ argon2Salt (base64)  — needed so any device can derive the KEK
 *     ✅ wrappedVaultKey      — AES-256-GCM encrypted vault key; safe to store
 *
 *   Memory ONLY (lost on service worker restart — intentional):
 *     ❌ Decrypted vault entries — plaintext passwords NEVER touch disk
 *     ❌ Vault key (Uint8Array)  — raw key bytes NEVER touch disk
 *     ❌ KEK (Uint8Array)        — ephemeral, exists only during unlock
 *     ❌ Master password         — never stored after UNLOCK completes
 *
 * WHY IS SERVICE WORKER RESTART SAFE?
 *   Chrome can kill service workers at any time (idle timeout, browser restart).
 *   When this happens, vault-state is reset to { locked: true, vault: null }.
 *   The user simply re-enters their master password to unlock again.
 *   This is by design — it is equivalent to a screen lock on a laptop.
 *   The only downside is UX friction; the security properties are maintained.
 */

export const API_URL = (process.env.API_URL as string | undefined) ?? "http://localhost:3000";

// ── Auto-lock timing ──────────────────────────────────────────────────────────
export const LOCK_TIMEOUT_MS    = 5 * 60 * 1000;   // 5 minutes idle → auto-lock
export const CLIPBOARD_CLEAR_MS = 30 * 1000;        // 30 seconds → clear clipboard

// ── chrome.alarms key ─────────────────────────────────────────────────────────
export const ALARM_NAME = "vaultzero-autolock";

// ── chrome.storage.local keys ─────────────────────────────────────────────────
// Keys are kept short to minimise storage footprint.
// None of these keys contain plaintext vault data.
export const STORAGE_KEY_JWT          = "vz_jwt";      // Current JWT access token
export const STORAGE_KEY_REFRESH      = "vz_refresh";  // Refresh token (raw, 128 hex chars)
export const STORAGE_KEY_WRAPPED_KEY  = "vz_wk";       // AES-256-GCM wrapped vault key (base64)
export const STORAGE_KEY_SALT         = "vz_salt";     // Argon2id salt (base64)

// ── Password generator defaults ───────────────────────────────────────────────
export const DEFAULT_PASSWORD_LENGTH  = 20;
export const DEFAULT_PASSWORD_CHARSET =
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";

// ── Phishing detection ────────────────────────────────────────────────────────
export const PHISHING_WARNING_DISMISS_MS = 10_000;   // auto-dismiss after 10s
export const LEVENSHTEIN_SUSPICIOUS_MAX  = 3;        // distance ≤ 3 = suspicious

// ── Content script ────────────────────────────────────────────────────────────
export const FORM_OBSERVER_DEBOUNCE_MS = 300;        // MutationObserver debounce
export const SUBMIT_DEBOUNCE_MS        = 2_000;      // ignore duplicate form submits within 2s
