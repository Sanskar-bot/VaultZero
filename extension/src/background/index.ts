/**
 * src/background/index.ts — Service Worker Entry Point
 *
 * ═══════════════════════════════════════════════════════════════
 * SERVICE WORKER RESTART RESILIENCE
 * ═══════════════════════════════════════════════════════════════
 *
 * Chrome MV3 service workers can be terminated by Chrome at any time:
 *   - After 30 seconds of inactivity (no pending events)
 *   - On browser startup/shutdown
 *   - During extension update
 *   - Under memory pressure
 *
 * When the service worker restarts, ALL module-level variables are reset
 * to their initial values (vault-state.ts initialises to { locked: true }).
 *
 * ✅ THIS IS A SECURITY FEATURE, NOT A BUG:
 *   - A restarted service worker means the vault is automatically locked.
 *   - The user must re-enter their master password to unlock.
 *   - This is equivalent to a screen lock on a laptop after sleep.
 *   - JWT and refresh token survive in chrome.storage.local, so the user
 *     does NOT need to log in again — just re-enter their master password.
 *
 * Pattern used here: Register ALL event listeners synchronously at the
 * TOP LEVEL of the service worker. This is required by Chrome MV3 —
 * event listeners registered asynchronously (inside .then() or async functions)
 * may be missed after service worker restart.
 * ═══════════════════════════════════════════════════════════════
 */

import { handleMessage } from "./message-handler";
import { checkIdleAndLock } from "./auto-lock";
import { ALARM_NAME } from "../shared/constants";

// ── [REQUIRED] Register event listeners synchronously at top level ────────────

/**
 * Message listener — handles all messages from popup and content scripts.
 * Returns true to keep the message channel open for async sendResponse.
 */
chrome.runtime.onMessage.addListener(handleMessage);

/**
 * Alarm listener — fires the idle check every minute.
 * Must be registered synchronously here, not inside an async function.
 */
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === ALARM_NAME) {
    const didLock = checkIdleAndLock();
    if (didLock) {
      console.log("[Background] Vault auto-locked due to inactivity");
    }
  }
});

// ── Lifecycle events ──────────────────────────────────────────────────────────

/**
 * Fired once when the extension is installed or updated.
 * Good place for migration logic or first-run setup.
 */
chrome.runtime.onInstalled.addListener((details) => {
  console.log("[VaultZero] Extension installed/updated:", details.reason);
  // On install: vault starts locked — no action needed
  // On update: if vault was unlocked before update, it is now locked (new SW context)
});

/**
 * Fired when the browser profile starts (user opens Chrome).
 * Service worker is woken up by this event.
 * Vault state starts locked by design (module initialises to locked).
 */
chrome.runtime.onStartup.addListener(() => {
  console.log("[VaultZero] Browser startup — vault starts locked");
  // Vault is already locked by module initialisation.
  // If the user had an active session before, they still have valid
  // tokens in chrome.storage.local — they just need to re-enter their
  // master password to unlock.
});
