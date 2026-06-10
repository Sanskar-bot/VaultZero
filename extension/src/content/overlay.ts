/**
 * src/content/overlay.ts — Key Button Overlay Injection
 *
 * Injects a small 🔑 button next to each detected password field so the user
 * can trigger credential lookup without opening the popup.
 *
 * POSITIONING STRATEGY:
 *   We use getBoundingClientRect() + scroll offsets to position the button
 *   absolutely relative to the document (not viewport) so it stays in place
 *   as the user scrolls. We use !important on critical styles to prevent
 *   the page's CSS from repositioning or hiding the button.
 *
 * ⚠️ SECURITY:
 *   - All elements created via createElement — no innerHTML
 *   - Styles injected via JS — no relying on external CSS (content scripts
 *     don't load CSS files from the extension by default)
 *   - Button z-index is 2147483646 (one below the phishing banner at max)
 *
 * CLEANUP:
 *   Each injected button is tracked by a WeakMap keyed on the input element.
 *   When the input is removed from the DOM or vault locks, removeKeyButton()
 *   cleans up the associated button.
 */

import type { LoginForm } from "./form-detector";

// WeakMap: input element → its injected key button
// WeakMap allows GC to collect entries when the input is removed from DOM
const buttonMap = new WeakMap<HTMLInputElement, HTMLButtonElement>();

// WeakMap: input element → its ResizeObserver (for cleanup)
const resizeObserverMap = new WeakMap<HTMLInputElement, ResizeObserver>();

const BUTTON_SIZE = 22; // px
const BUTTON_MARGIN = 4; // px from right edge of input

// ── Position calculation ──────────────────────────────────────────────────────

/**
 * Calculate and apply the absolute position for the key button.
 * Positions it at the right edge of the input field, vertically centred.
 *
 * Uses pageX/pageY (viewport rect + scroll offset) so the button doesn't
 * drift when the page is scrolled.
 */
export function positionButton(
  button: HTMLElement,
  input: HTMLInputElement
): void {
  const rect = input.getBoundingClientRect();

  // Convert viewport coordinates to document (page) coordinates
  const scrollX = window.scrollX || document.documentElement.scrollLeft;
  const scrollY = window.scrollY || document.documentElement.scrollTop;

  const top  = rect.top  + scrollY + (rect.height - BUTTON_SIZE) / 2;
  const left = rect.right + scrollX - BUTTON_SIZE - BUTTON_MARGIN;

  // Use !important on positioning to resist page CSS
  button.style.setProperty("position", "absolute", "important");
  button.style.setProperty("top",      `${top}px`,  "important");
  button.style.setProperty("left",     `${left}px`, "important");
  button.style.setProperty("z-index",  "2147483646", "important");
}

// ── Button injection ──────────────────────────────────────────────────────────

/**
 * Inject a 🔑 key button next to the given password input.
 * The button triggers credential lookup when clicked.
 *
 * No-op if the input already has a key button (safe to call multiple times).
 *
 * @param input      - The password input to decorate
 * @param onActivate - Callback to invoke when the button is clicked
 *                     (receives the associated login form)
 * @param form       - The LoginForm context (passed to onActivate)
 */
export function injectKeyButton(
  input: HTMLInputElement,
  onActivate: (form: LoginForm) => void,
  form: LoginForm
): void {
  // Skip if already injected
  if (buttonMap.has(input)) return;

  const button = document.createElement("button");

  // Content: key emoji via textContent (never innerHTML)
  button.textContent = "🔑";
  button.setAttribute("aria-label", "Fill with VaultZero");
  button.setAttribute("type", "button"); // prevent accidental form submission
  button.setAttribute("data-vaultzero", "key-button"); // for identification/cleanup

  // Apply styles via setProperty with !important to resist page CSS override
  const styles: Array<[string, string]> = [
    ["width",            `${BUTTON_SIZE}px`],
    ["height",           `${BUTTON_SIZE}px`],
    ["border",           "1px solid rgba(124, 58, 237, 0.5)"],
    ["border-radius",    "4px"],
    ["background",       "rgba(15, 15, 26, 0.92)"],
    ["cursor",           "pointer"],
    ["font-size",        "13px"],
    ["line-height",      "1"],
    ["display",          "flex"],
    ["align-items",      "center"],
    ["justify-content",  "center"],
    ["padding",          "0"],
    ["transition",       "opacity 0.15s, border-color 0.15s"],
    ["opacity",          "0.8"],
    ["box-shadow",       "0 1px 4px rgba(0,0,0,0.4)"],
    ["box-sizing",       "border-box"],
    ["pointer-events",   "auto"],
  ];

  for (const [prop, value] of styles) {
    button.style.setProperty(prop, value, "important");
  }

  button.addEventListener("mouseenter", () => {
    button.style.setProperty("opacity", "1", "important");
    button.style.setProperty("border-color", "rgba(124, 58, 237, 0.9)", "important");
  });
  button.addEventListener("mouseleave", () => {
    button.style.setProperty("opacity", "0.8", "important");
    button.style.setProperty("border-color", "rgba(124, 58, 237, 0.5)", "important");
  });

  button.addEventListener("click", (e) => {
    e.preventDefault();
    e.stopPropagation();
    onActivate(form);
  });

  // Append to document.body so the button is positioned in page coordinates
  // and not clipped by any overflow:hidden container the input lives in
  document.body.appendChild(button);

  // Initial position calculation
  positionButton(button, input);

  // Track for cleanup
  buttonMap.set(input, button);

  // ── ResizeObserver: reposition when input resizes ─────────────────────────
  if (typeof ResizeObserver !== "undefined") {
    const ro = new ResizeObserver(() => positionButton(button, input));
    ro.observe(input);
    resizeObserverMap.set(input, ro);
  }

  // ── Scroll + resize events: reposition button ─────────────────────────────
  const reposition = () => positionButton(button, input);
  window.addEventListener("scroll",  reposition, { passive: true });
  window.addEventListener("resize",  reposition, { passive: true });
}

// ── Button removal ────────────────────────────────────────────────────────────

/**
 * Remove the key button associated with the given input.
 * Called when:
 *   - The vault locks (VAULT_LOCKED message received)
 *   - The input element is removed from the DOM
 *   - Page is unloading
 */
export function removeKeyButton(input: HTMLInputElement): void {
  const button = buttonMap.get(input);
  if (button) {
    button.remove();
    buttonMap.delete(input);
  }

  // Clean up ResizeObserver
  const ro = resizeObserverMap.get(input);
  if (ro) {
    ro.disconnect();
    resizeObserverMap.delete(input);
  }
}

/**
 * Remove ALL injected key buttons.
 * Called when the vault locks to clean up the entire page.
 */
export function removeAllKeyButtons(): void {
  const buttons = document.querySelectorAll('[data-vaultzero="key-button"]');
  buttons.forEach((b) => b.remove());
}
