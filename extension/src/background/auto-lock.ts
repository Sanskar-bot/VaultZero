/**
 * src/background/auto-lock.ts — Idle Auto-Lock Timer
 *
 * Uses chrome.alarms API rather than setInterval/setTimeout.
 *
 * WHY ALARMS INSTEAD OF setInterval?
 *   Chrome may suspend the service worker after 30 seconds of inactivity.
 *   A suspended service worker's setInterval/setTimeout timers are frozen
 *   and will not fire. chrome.alarms are managed by the browser process
 *   itself and will wake the service worker when they fire, even if it
 *   was suspended.
 *
 * TIMER LOGIC:
 *   - The alarm fires every 1 minute.
 *   - On each alarm tick, we check: Date.now() - lastActivity > LOCK_TIMEOUT_MS
 *   - If the vault has been idle for > 5 minutes: call setLocked()
 *   - If already locked: alarm is a no-op
 *   - resetTimer() does NOT restart the alarm — it just updates the
 *     lastActivity timestamp in vault-state. The alarm keeps running.
 *   - This avoids the overhead of repeatedly creating/clearing alarms.
 */

import { ALARM_NAME, LOCK_TIMEOUT_MS } from "../shared/constants";
import { isLocked, setLocked, updateActivity, getState } from "./vault-state";

/**
 * Start the auto-lock alarm.
 * Creates a repeating alarm that fires every 1 minute.
 * The alarm listener (registered in index.ts) checks idle time and locks if needed.
 *
 * Safe to call multiple times — chrome.alarms.create with the same name
 * overwrites the existing alarm without creating duplicates.
 */
export function startAutoLockTimer(): void {
  chrome.alarms.create(ALARM_NAME, {
    periodInMinutes: 1,  // check idle every minute
  });
  console.log("[AutoLock] Timer started — idle timeout:", LOCK_TIMEOUT_MS / 60_000, "min");
}

/**
 * Reset the idle timer by updating lastActivity.
 * The alarm itself keeps running — only the activity timestamp is reset.
 * Call this on any user-initiated event (message received, autofill, etc.)
 */
export function resetTimer(): void {
  updateActivity();
}

/**
 * Stop the auto-lock alarm entirely.
 * Called on logout so the alarm doesn't fire against a signed-out state.
 */
export function stopTimer(): void {
  chrome.alarms.clear(ALARM_NAME, (wasCleared) => {
    if (wasCleared) {
      console.log("[AutoLock] Timer stopped");
    }
  });
}

/**
 * Check if the vault has been idle too long and lock if so.
 * Called by the alarm listener in index.ts every minute.
 *
 * @returns true if the vault was locked by this call
 */
export function checkIdleAndLock(): boolean {
  if (isLocked()) {
    // Already locked — nothing to do, but keep alarm running
    return false;
  }

  const { lastActivity } = getState();

  const idleMs = Date.now() - lastActivity;
  if (idleMs > LOCK_TIMEOUT_MS) {
    console.log(`[AutoLock] Locking vault after ${Math.round(idleMs / 1000)}s idle`);
    setLocked();

    // Notify all open extension tabs that the vault has been locked
    // so they can update their UI and dismiss credential pickers
    notifyTabsVaultLocked();
    return true;
  }

  return false;
}

/**
 * Broadcast VAULT_LOCKED to all content script contexts.
 * Content scripts use this to remove key buttons and dismiss pickers.
 */
function notifyTabsVaultLocked(): void {
  chrome.tabs.query({}, (tabs) => {
    for (const tab of tabs) {
      if (tab.id != null) {
        chrome.tabs.sendMessage(
          tab.id,
          { type: "VAULT_LOCKED", payload: undefined },
          // Ignore errors — tabs may not have content script loaded
          () => { void chrome.runtime.lastError; }
        );
      }
    }
  });
}
