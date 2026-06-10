/**
 * src/content/form-detector.ts — Login Form Detection
 *
 * Finds login forms on the current page and watches for dynamically-added
 * forms in SPAs (React, Angular, Vue, etc.).
 *
 * DETECTION STRATEGY:
 *   The anchor for detection is always a password field (input[type="password"]).
 *   From there, we search for a nearby username field using several heuristics:
 *     1. Sibling inputs inside the same <form> element
 *     2. Inputs within the same container (up to 3 DOM levels up)
 *     3. The closest preceding input before the password field
 *
 * SECURITY NOTES:
 *   - We never cross iframe boundaries (cross-origin frames are a separate
 *     browsing context with their own JS heap — we can't reach them anyway)
 *   - Hidden or disabled fields are ignored to prevent filling invisible inputs
 *     that could be honeypots or anti-CSRF traps
 *   - offsetParent check is the reliable cross-browser way to detect hidden elements
 *     (it returns null for display:none and visibility:hidden)
 */

export interface LoginForm {
  passwordField: HTMLInputElement;
  usernameField: HTMLInputElement | null;
  form: HTMLFormElement | null;
}

// ── Visibility helpers ────────────────────────────────────────────────────────

/**
 * Returns true if the input is visible and interactable.
 * Checks: not disabled, not hidden via display/visibility, not zero-size.
 */
function isVisible(input: HTMLInputElement): boolean {
  if (input.disabled) return false;
  if (input.type === "hidden") return false;
  // offsetParent is null for display:none / visibility:hidden ancestors
  if (input.offsetParent === null) return false;
  const rect = input.getBoundingClientRect();
  // Ignore zero-dimension inputs (common for honeypot fields)
  if (rect.width === 0 || rect.height === 0) return false;
  return true;
}

// ── Username field selectors ──────────────────────────────────────────────────

const USERNAME_SELECTORS = [
  'input[type="email"]',
  'input[type="text"][name*="user"]',
  'input[type="text"][name*="email"]',
  'input[type="text"][name*="login"]',
  'input[type="text"][id*="user"]',
  'input[type="text"][id*="email"]',
  'input[type="text"][id*="login"]',
  'input[type="text"][autocomplete="username"]',
  'input[type="text"][autocomplete="email"]',
  'input[type="tel"]',
  // Generic text input as last resort
  'input[type="text"]',
] as const;

/**
 * Find the best username field within a given container element.
 * Tries each selector in priority order.
 */
function findUsernameInContainer(
  container: Element,
  passwordField: HTMLInputElement
): HTMLInputElement | null {
  for (const selector of USERNAME_SELECTORS) {
    const candidates = Array.from(container.querySelectorAll<HTMLInputElement>(selector));
    // Pick the first visible candidate that appears BEFORE the password field in DOM order
    for (const candidate of candidates) {
      if (candidate === passwordField) continue;
      if (!isVisible(candidate)) continue;
      // Ensure the candidate comes before the password field in the DOM tree
      const position = passwordField.compareDocumentPosition(candidate);
      // Node.DOCUMENT_POSITION_PRECEDING = 2
      if (position & Node.DOCUMENT_POSITION_PRECEDING) {
        return candidate;
      }
    }
  }
  return null;
}

// ── Form detection ────────────────────────────────────────────────────────────

/**
 * Find all login forms on the current page.
 *
 * A "login form" is any page section containing an input[type="password"]
 * that is visible, enabled, and not inside a cross-origin frame.
 *
 * @returns Array of LoginForm objects, one per password field found
 */
export function findLoginForms(): LoginForm[] {
  const passwordFields = Array.from(
    document.querySelectorAll<HTMLInputElement>('input[type="password"]')
  );

  const forms: LoginForm[] = [];

  for (const passwordField of passwordFields) {
    // Skip invisible or disabled password fields
    if (!isVisible(passwordField)) continue;

    let usernameField: HTMLInputElement | null = null;

    // Strategy 1: Search inside the same <form> element
    const formEl = passwordField.closest("form");
    if (formEl) {
      usernameField = findUsernameInContainer(formEl, passwordField);
    }

    // Strategy 2: Walk up to 3 parent levels looking for a container with a username field
    if (!usernameField) {
      let ancestor: Element | null = passwordField.parentElement;
      for (let depth = 0; depth < 3 && ancestor; depth++) {
        usernameField = findUsernameInContainer(ancestor, passwordField);
        if (usernameField) break;
        ancestor = ancestor.parentElement;
      }
    }

    // Strategy 3: Find the closest preceding input anywhere in the document
    // that is not a password field (last-resort heuristic)
    if (!usernameField) {
      const allInputs = Array.from(
        document.querySelectorAll<HTMLInputElement>(
          'input[type="text"], input[type="email"], input[type="tel"]'
        )
      );
      // Find the last one in DOM order that precedes passwordField
      for (let i = allInputs.length - 1; i >= 0; i--) {
        const candidate = allInputs[i]!;
        if (!isVisible(candidate)) continue;
        const position = passwordField.compareDocumentPosition(candidate);
        if (position & Node.DOCUMENT_POSITION_PRECEDING) {
          usernameField = candidate;
          break;
        }
      }
    }

    forms.push({
      passwordField,
      usernameField,
      form: formEl,
    });
  }

  return forms;
}

// ── MutationObserver for SPAs ─────────────────────────────────────────────────

/**
 * Watch for dynamically-added login forms (React, Angular, Vue SPAs).
 *
 * Uses a MutationObserver on the document body to detect when new
 * password inputs are added to the DOM. Debounces the callback to
 * avoid thrashing on rapid DOM updates (e.g., React reconciliation).
 *
 * @param callback - Called with each newly-detected LoginForm
 * @returns Disconnect function — call on page unload to clean up
 */
export function observeNewForms(callback: (form: LoginForm) => void): () => void {
  let debounceTimer: ReturnType<typeof setTimeout> | null = null;

  // Track which password fields we've already processed to avoid duplicates
  const processedFields = new WeakSet<HTMLInputElement>();

  const observer = new MutationObserver(() => {
    // Debounce: wait 300ms after the last DOM mutation before re-scanning
    if (debounceTimer !== null) {
      clearTimeout(debounceTimer);
    }
    debounceTimer = setTimeout(() => {
      const forms = findLoginForms();
      for (const form of forms) {
        if (!processedFields.has(form.passwordField)) {
          processedFields.add(form.passwordField);
          callback(form);
        }
      }
    }, 300); // FORM_OBSERVER_DEBOUNCE_MS
  });

  observer.observe(document.body, {
    childList: true,
    subtree:   true,
  });

  // Return a disconnect function for cleanup on page unload
  return () => {
    if (debounceTimer !== null) clearTimeout(debounceTimer);
    observer.disconnect();
  };
}
