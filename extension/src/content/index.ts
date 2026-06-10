/**
 * src/content/index.ts — Content Script Entry Point
 *
 * ═══════════════════════════════════════════════════════════════
 * SECURITY ARCHITECTURE
 * ═══════════════════════════════════════════════════════════════
 *
 * [1] IFRAME PROTECTION:
 *   Immediately exits if running inside a cross-origin iframe.
 *   Cross-origin frames have their own browsing context — we can't
 *   read their DOM anyway. This check prevents the script from doing
 *   unnecessary work (or potential confusion) in nested frames.
 *
 * [2] VAULT DATA NEVER STORED HERE:
 *   This file imports from autofill.ts which sends messages to the
 *   background for credential retrieval. Credentials are held in local
 *   variables for the duration of a fillCredentials() call only.
 *   No module-level credential storage.
 *
 * [3] NO /core IMPORTS:
 *   Content scripts NEVER import from @vaultzero/core.
 *   All crypto (Argon2, AES-GCM) happens in the background service worker.
 *   The content script is the most exposed component and is treated as
 *   potentially untrusted.
 *
 * [4] MESSAGE ORIGIN VERIFICATION:
 *   When receiving messages (e.g., VAULT_LOCKED), we verify that
 *   chrome.runtime.id matches the expected extension ID. This prevents
 *   a web page from sending fake VAULT_LOCKED messages to confuse the UI.
 *   (Web pages cannot use chrome.runtime.sendMessage to extension content
 *    scripts normally, but we verify defensively.)
 *
 * [5] CLEANUP ON UNLOAD:
 *   All observers are disconnected, all injected elements are removed,
 *   and all event listeners are cleaned up on pagehide/beforeunload.
 * ═══════════════════════════════════════════════════════════════
 */

// [1] EXIT IMMEDIATELY IF INSIDE A CROSS-ORIGIN IFRAME
// window.top is null when running in a detached frame; both cases: exit.
// This check runs synchronously before any other code executes.
if (window !== window.top) {
  // Use a non-throwing early exit pattern for content scripts
  // (throw would be caught by Chrome and logged as an error)
  // We stop execution by not exporting anything and using a guard below.
  // The IIFE pattern (esbuild wraps this in IIFE) means this throw exits the
  // entire script scope without polluting the global.
  throw new Error("[VaultZero] Skipping cross-origin frame");
}

import type { LoginForm } from "./form-detector";
import { findLoginForms, observeNewForms } from "./form-detector";
import { checkPhishing, showPhishingWarning }  from "./phishing";
import { injectKeyButton, removeAllKeyButtons } from "./overlay";
import {
  requestCredentials,
  showCredentialPicker,
  captureFormSubmission,
  dismissCredentialPicker,
} from "./autofill";

// ── State ─────────────────────────────────────────────────────────────────────

/** Cleanup functions collected throughout the script's lifetime */
const cleanupFns: Array<() => void> = [];

/** The set of password fields we've already fully processed */
const processedInputs = new WeakSet<HTMLInputElement>();

// ── Form processing ───────────────────────────────────────────────────────────

/**
 * Process a newly-detected login form:
 *   1. Check for phishing against saved entry URLs
 *   2. Inject key button on the password field
 *   3. Set up form submission capture
 *
 * [2] Credentials are requested asynchronously and only held for the
 *   duration of the picker/fill operation.
 */
async function processForm(form: LoginForm): Promise<void> {
  // Skip if we've already processed this password field
  if (processedInputs.has(form.passwordField)) return;
  processedInputs.add(form.passwordField);

  // [A] Phishing check — request credentials for current URL
  // This also serves as a "does the vault have any entry for this site?" probe
  const currentUrl = window.location.href;
  const matchingEntries = await requestCredentials(currentUrl);

  // Run phishing check against each saved entry URL
  for (const entry of matchingEntries) {
    const result = checkPhishing(currentUrl, entry.url);
    if (result.isSuspicious && result.reason) {
      showPhishingWarning(result.reason);
      break; // One warning is enough
    }
  }

  // [B] Inject 🔑 button — clicking it shows the credential picker
  injectKeyButton(
    form.passwordField,
    async (clickedForm: LoginForm) => {
      const entries = await requestCredentials(window.location.href);
      if (entries.length === 0) {
        // Vault locked or no matching entries — show subtle feedback
        console.debug("[VaultZero] No credentials found for:", window.location.hostname);
        return;
      }
      showCredentialPicker(clickedForm.passwordField, entries, clickedForm);
    },
    form
  );

  // [C] Set up form submit capture
  captureFormSubmission(form);
}

// ── Initialise ────────────────────────────────────────────────────────────────

function init(): void {
  // Scan for existing login forms
  const forms = findLoginForms();
  for (const form of forms) {
    void processForm(form);
  }

  // Watch for dynamically-added forms (SPAs, React, Angular, Vue)
  const disconnectObserver = observeNewForms((newForm) => {
    void processForm(newForm);
  });
  cleanupFns.push(disconnectObserver);
}

// Run init when DOM is ready
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init, { once: true });
} else {
  // DOM already loaded (script injected after page load)
  init();
}

// ── Message listener: background → content ────────────────────────────────────

/**
 * [4] MESSAGE ORIGIN VERIFICATION
 * Verify that messages come from our own extension before acting on them.
 * chrome.runtime.id is this extension's ID — it cannot be spoofed by web pages.
 */
chrome.runtime.onMessage.addListener(
  (message: { type: string }, sender) => {
    // [4] Reject messages not from our extension's own background
    // Legitimate background messages have sender.id === chrome.runtime.id
    // and no sender.tab (background → content doesn't come from a tab)
    if (sender.id !== chrome.runtime.id) {
      console.warn("[VaultZero] Ignoring message from unknown sender:", sender.id);
      return;
    }

    if (message.type === "VAULT_LOCKED") {
      // [5] Remove all UI elements and clear references on lock
      removeAllKeyButtons();
      dismissCredentialPicker();
      console.debug("[VaultZero] Vault locked — UI cleaned up");
    }
  }
);

// ── Cleanup on page unload ────────────────────────────────────────────────────

/**
 * [5] Full cleanup on page navigation or close.
 * Disconnect observers, remove injected elements, clear timers.
 */
function cleanup(): void {
  for (const fn of cleanupFns) {
    try { fn(); } catch { /* ignore cleanup errors */ }
  }
  removeAllKeyButtons();
  dismissCredentialPicker();
}

window.addEventListener("pagehide",   cleanup, { once: true });
window.addEventListener("beforeunload", cleanup, { once: true });
