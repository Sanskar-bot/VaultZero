/**
 * src/content/autofill.ts — Credential Request, Fill, and Picker
 *
 * ═══════════════════════════════════════════════════════════════
 * SECURITY ARCHITECTURE
 * ═══════════════════════════════════════════════════════════════
 *
 * [1] CREDENTIAL MINIMISATION:
 *   requestCredentials() receives only { id, username, password, url }
 *   from the background worker. The full vault (notes, timestamps) is
 *   never sent to this context.
 *
 * [2] SCOPE MINIMISATION:
 *   After fillCredentials() returns, the CredentialEntry is no longer
 *   referenced. The JS engine can GC it. We do not cache credentials
 *   in any module-level variable.
 *
 * [3] SYNTHETIC EVENTS:
 *   After setting .value on an input, we dispatch synthetic input/change
 *   events. This is required because React, Angular, and Vue use
 *   synthetic event systems that don't fire when .value is set directly.
 *   The events carry NO payload — they only signal "the value changed".
 *   No credential data is embedded in or extractable from these events.
 *
 * [4] DOM INJECTION SAFETY:
 *   The credential picker uses createElement + textContent exclusively.
 *   No innerHTML. Entry URLs and usernames are set via textContent,
 *   which HTML-escapes any special characters automatically.
 *
 * [5] PICKER DISMISSAL ON LOCK:
 *   If the vault locks while the picker is open (VAULT_LOCKED message),
 *   the picker is removed and credentials are discarded.
 *
 * [6] FORM SUBMISSION CAPTURE:
 *   We listen for form submit events to offer "save this password?" prompts.
 *   We do NOT prevent default — the form submits normally.
 *   Debounced to 2 seconds to ignore duplicate submission events.
 * ═══════════════════════════════════════════════════════════════
 */

import type { LoginForm } from "./form-detector";
import type { CredentialEntry, CredentialsResponse, ErrorResponse } from "../shared/types";

// Track the currently open picker so we can close it externally
let activePicker: HTMLElement | null = null;

// ── Credential request ────────────────────────────────────────────────────────

/**
 * Ask the background service worker for credentials matching the current URL.
 *
 * [1] Only { id, username, password, url } are returned — never the full vault.
 * Returns an empty array on any error — content script never throws.
 *
 * @param currentUrl - The URL of the current page (from window.location.href)
 */
export async function requestCredentials(
  currentUrl: string
): Promise<CredentialEntry[]> {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage(
        { type: "GET_CREDENTIALS_FOR_URL", payload: { url: currentUrl } },
        (response: CredentialsResponse | ErrorResponse) => {
          // Check for extension errors (e.g., background worker offline)
          if (chrome.runtime.lastError) {
            console.debug("[VaultZero] Background unavailable:", chrome.runtime.lastError.message);
            resolve([]);
            return;
          }
          if ("error" in response) {
            resolve([]);
            return;
          }
          resolve(response.entries);
        }
      );
    } catch {
      // chrome.runtime.sendMessage can throw if the extension context is invalidated
      resolve([]);
    }
  });
}

// ── Credential fill ───────────────────────────────────────────────────────────

/**
 * Fill a login form with the provided credentials.
 *
 * [3] WHY SYNTHETIC EVENTS?
 *   React, Angular, Vue, and other frameworks override native input behavior.
 *   They attach their own event listeners and maintain internal state (React's
 *   fiber, Angular's NgModel, Vue's v-model) that tracks form values.
 *   When you set .value directly via JS, the internal state doesn't update,
 *   so the framework won't see the new value on submit.
 *   Dispatching input + change events forces the frameworks to re-read .value
 *   and sync their internal state. The events carry no payload — they're just
 *   notifications that say "look at this input again".
 *
 * @param form  - The LoginForm context (passwordField, usernameField)
 * @param entry - The credential to fill (goes out of scope after this returns)
 */
export function fillCredentials(form: LoginForm, entry: CredentialEntry): void {
  const syntheticEvents = [
    new Event("input",  { bubbles: true, cancelable: true }),
    new Event("change", { bubbles: true, cancelable: true }),
    new KeyboardEvent("keydown", { bubbles: true, cancelable: true, key: "a" }),
    new KeyboardEvent("keyup",   { bubbles: true, cancelable: true, key: "a" }),
  ];

  // Fill username field if present
  if (form.usernameField && entry.username) {
    // Use native input value setter to bypass React's property descriptor interception
    const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
      window.HTMLInputElement.prototype,
      "value"
    )?.set;
    if (nativeInputValueSetter) {
      nativeInputValueSetter.call(form.usernameField, entry.username);
    } else {
      form.usernameField.value = entry.username;
    }
    for (const evt of syntheticEvents) {
      form.usernameField.dispatchEvent(evt);
    }
  }

  // Fill password field
  const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
    window.HTMLInputElement.prototype,
    "value"
  )?.set;
  if (nativeInputValueSetter) {
    nativeInputValueSetter.call(form.passwordField, entry.password);
  } else {
    form.passwordField.value = entry.password;
  }
  for (const evt of syntheticEvents) {
    form.passwordField.dispatchEvent(evt);
  }

  // Notify background to reset the idle timer
  try {
    chrome.runtime.sendMessage({ type: "GET_LOCK_STATUS", payload: undefined }, () => {
      void chrome.runtime.lastError; // suppress "no receiver" errors
    });
  } catch { /* extension context may be invalidated */ }

  // [2] entry reference goes out of scope here — eligible for GC
}

// ── Credential picker ─────────────────────────────────────────────────────────

const PICKER_ID = "vaultzero-credential-picker";

/**
 * Show a dropdown picker near the input with matching credentials.
 *
 * [4] All DOM nodes built with createElement + textContent.
 * [5] Dismissed when VAULT_LOCKED message arrives.
 *
 * If exactly 1 entry: fill immediately (no picker shown).
 * If > 1 entries: show dropdown listing { username + masked URL }.
 *
 * @param input   - The input field to position the picker near
 * @param entries - Credential entries returned by requestCredentials()
 * @param form    - The LoginForm to fill on selection
 */
export function showCredentialPicker(
  input: HTMLInputElement,
  entries: CredentialEntry[],
  form: LoginForm
): void {
  if (entries.length === 0) return;

  // Single entry: fill immediately without showing a picker
  if (entries.length === 1) {
    fillCredentials(form, entries[0]!);
    return;
  }

  // Remove any existing picker
  dismissCredentialPicker();

  // ── Build picker with createElement only ──────────────────────────────────

  const picker = document.createElement("div");
  picker.id = PICKER_ID;
  picker.setAttribute("role", "listbox");
  picker.setAttribute("aria-label", "VaultZero credentials");

  // Position near the input field
  const rect     = input.getBoundingClientRect();
  const scrollX  = window.scrollX || document.documentElement.scrollLeft;
  const scrollY  = window.scrollY || document.documentElement.scrollTop;

  Object.assign(picker.style, {
    position:     "absolute",
    top:          `${rect.bottom + scrollY + 4}px`,
    left:         `${rect.left  + scrollX}px`,
    width:        `${Math.max(rect.width, 240)}px`,
    zIndex:       "2147483645",
    background:   "#0f0f1a",
    border:       "1.5px solid #2d2d4e",
    borderRadius: "8px",
    boxShadow:    "0 8px 24px rgba(0,0,0,0.6)",
    overflow:     "hidden",
    fontFamily:   "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
    fontSize:     "13px",
    boxSizing:    "border-box",
  });

  // Header
  const header = document.createElement("div");
  header.textContent = "🔑 VaultZero — Select credential";
  Object.assign(header.style, {
    padding:       "8px 12px",
    color:         "#888aab",
    fontSize:      "11px",
    fontWeight:    "600",
    letterSpacing: "0.05em",
    borderBottom:  "1px solid #1e1e36",
    textTransform: "uppercase",
  });
  picker.appendChild(header);

  // Entry items
  for (const entry of entries) {
    const item = document.createElement("button");
    item.setAttribute("role", "option");
    item.setAttribute("type", "button");

    Object.assign(item.style, {
      display:       "flex",
      flexDirection: "column",
      gap:           "2px",
      width:         "100%",
      padding:       "10px 12px",
      background:    "transparent",
      border:        "none",
      borderBottom:  "1px solid #1a1a2e",
      cursor:        "pointer",
      textAlign:     "left",
      transition:    "background 0.1s",
      boxSizing:     "border-box",
    });

    item.addEventListener("mouseenter", () => {
      item.style.background = "#1a1a2e";
    });
    item.addEventListener("mouseleave", () => {
      item.style.background = "transparent";
    });

    // Username row
    const usernameEl = document.createElement("span");
    usernameEl.textContent = entry.username; // textContent — XSS-safe
    Object.assign(usernameEl.style, { color: "#e0e0f0", fontWeight: "600" });

    // URL row
    const urlEl = document.createElement("span");
    // Extract just the hostname for display — never raw URL (could be long)
    try {
      urlEl.textContent = new URL(entry.url.includes("://") ? entry.url : `https://${entry.url}`).hostname;
    } catch {
      urlEl.textContent = entry.url;
    }
    Object.assign(urlEl.style, { color: "#555770", fontSize: "11px" });

    // Masked password indicator
    const maskEl = document.createElement("span");
    maskEl.textContent = "••••••••";
    Object.assign(maskEl.style, { color: "#3d3d5c", fontSize: "11px" });

    item.appendChild(usernameEl);
    item.appendChild(urlEl);
    item.appendChild(maskEl);

    item.addEventListener("click", () => {
      dismissCredentialPicker();
      fillCredentials(form, entry);
      // [2] entry reference goes out of scope when event handler returns
    });

    picker.appendChild(item);
  }

  document.body.appendChild(picker);
  activePicker = picker;

  // ── Dismiss on outside click ──────────────────────────────────────────────
  const onOutsideClick = (e: MouseEvent) => {
    if (!picker.contains(e.target as Node)) {
      dismissCredentialPicker();
      document.removeEventListener("click", onOutsideClick, true);
    }
  };
  // Use capture phase to intercept clicks before they reach the page
  setTimeout(() => {
    document.addEventListener("click", onOutsideClick, true);
  }, 0);

  // ── Dismiss on Escape ─────────────────────────────────────────────────────
  const onKeydown = (e: KeyboardEvent) => {
    if (e.key === "Escape") {
      dismissCredentialPicker();
      document.removeEventListener("keydown", onKeydown, true);
    }
  };
  document.addEventListener("keydown", onKeydown, true);
}

/**
 * Dismiss and remove the active credential picker.
 * Called when: user clicks outside, presses Escape, vault locks,
 * or an entry is selected.
 */
export function dismissCredentialPicker(): void {
  if (activePicker) {
    activePicker.remove();
    activePicker = null;
  }
  // Remove picker by ID as a fallback
  document.getElementById(PICKER_ID)?.remove();
}

// ── Form submission capture ───────────────────────────────────────────────────

/**
 * Capture form submission to offer "save this password?" functionality.
 *
 * [6] We do NOT prevent default — the form submits normally.
 *   We only observe what was typed and offer to save it.
 *   Debounced to 2 seconds to ignore duplicate submit events from frameworks
 *   that fire submit multiple times (e.g., Angular's ngSubmit + native submit).
 *
 * @param form - The LoginForm to watch for submission
 */
export function captureFormSubmission(form: LoginForm): void {
  let lastSubmitTime = 0;

  const handleSubmit = () => {
    const now = Date.now();
    // Debounce: ignore submissions within 2 seconds of the last one
    if (now - lastSubmitTime < 2_000) return;
    lastSubmitTime = now;

    const username = form.usernameField?.value?.trim() ?? "";
    const password = form.passwordField.value;

    // Only capture if both fields are non-empty
    if (!username || !password) return;

    const url = window.location.href;

    // Send SAVE_ENTRY to background — fire and forget
    // Content script does NOT await this — it just sends and moves on
    // The credential reference (username/password) is read from live DOM
    // and goes out of scope after this call
    try {
      chrome.runtime.sendMessage({
        type: "SAVE_ENTRY",
        payload: {
          entry: { url, username, password },
        },
      }, () => {
        void chrome.runtime.lastError; // suppress errors if background is unavailable
      });
    } catch { /* extension context may be invalidated */ }
  };

  // Prefer listening on the form element; fall back to document
  const target = form.form ?? document;
  target.addEventListener("submit", handleSubmit, { passive: true });
}
