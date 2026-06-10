/**
 * src/content/phishing.ts — Domain Comparison + Phishing Warning Banner
 *
 * Detects when the current page looks suspiciously similar to a domain
 * for which the user has saved credentials. Uses:
 *
 *   1. Exact hostname match         → safe (autofill proceeds normally)
 *   2. Levenshtein distance 1–3     → typosquatting (e.g. goggle.com vs google.com)
 *   3. Substring containment        → subdomain impersonation (e.g. paypal.com.evil.net)
 *   4. Same name, different TLD     → TLD swap (e.g. paypal.net vs paypal.com)
 *
 * SECURITY NOTE — Warning injection:
 *   The warning banner is created with createElement + textContent ONLY.
 *   We NEVER use innerHTML, outerHTML, or insertAdjacentHTML.
 *   The `message` string passed to showPhishingWarning() comes from our own
 *   code (templated from saved entry URLs), not from web page content.
 *   However, we still avoid innerHTML as defense-in-depth: if an entry URL
 *   somehow contained a crafted string, innerHTML would be a XSS vector.
 *
 * LEVENSHTEIN NOTE:
 *   We only check against the hostname (not the full URL) to avoid false
 *   positives from path differences. We also normalise by stripping "www."
 *   before comparison.
 */

export interface PhishingResult {
  isSuspicious: boolean;
  reason: string | null;
}

// ── Levenshtein distance ──────────────────────────────────────────────────────

/**
 * Compute the Levenshtein edit distance between two strings.
 *
 * Standard DP implementation — O(|a| × |b|) time, O(min(|a|,|b|)) space.
 * Used to detect typosquatting: distance of 1–3 between hostnames.
 *
 * Examples:
 *   ("paypal.com", "paypa1.com") → 1  (l → 1)
 *   ("github.com", "gıthub.com") → 1  (homoglyph: i → ı)
 *   ("google.com", "googel.com") → 2  (transposition)
 */
export function levenshteinDistance(a: string, b: string): number {
  // Short-circuit for identical strings
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  // Use the shorter string as the "column" to minimise memory usage
  let [shorter, longer] = a.length <= b.length ? [a, b] : [b, a];

  // prev[j] = edit distance between shorter[0..j] and longer[0..i-1]
  let prev = Array.from({ length: shorter.length + 1 }, (_, i) => i);

  for (let i = 1; i <= longer.length; i++) {
    const curr = new Array<number>(shorter.length + 1);
    curr[0] = i;

    for (let j = 1; j <= shorter.length; j++) {
      const cost = longer[i - 1] === shorter[j - 1] ? 0 : 1;
      curr[j] = Math.min(
        prev[j]!  + 1,      // deletion
        curr[j-1]! + 1,     // insertion
        prev[j-1]! + cost   // substitution
      );
    }

    prev = curr;
  }

  return prev[shorter.length]!;
}

// ── URL hostname extraction ───────────────────────────────────────────────────

/**
 * Extract and normalise the hostname from a URL string.
 *
 * Normalisation:
 *   - Lowercased
 *   - "www." prefix stripped
 *   - Port numbers stripped
 *
 * Returns empty string on parse error so callers can treat it as "no match".
 */
export function extractHostname(url: string): string {
  try {
    const normalized = url.includes("://") ? url : `https://${url}`;
    const parsed = new URL(normalized);
    // Strip www. prefix and lowercase
    return parsed.hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return "";
  }
}

/**
 * Extract the registered domain (eTLD+1) from a hostname.
 * Simplified version: extracts the last two parts of the hostname.
 * e.g. "sub.paypal.com" → "paypal.com"
 */
function getRegisteredDomain(hostname: string): string {
  const parts = hostname.split(".");
  if (parts.length <= 2) return hostname;
  return parts.slice(-2).join(".");
}

// ── Phishing check ────────────────────────────────────────────────────────────

/**
 * Compare the current page URL against a saved entry URL to detect phishing.
 *
 * @param currentUrl   - URL of the page the content script is running on
 * @param savedEntryUrl - URL stored in the vault entry we're about to autofill
 * @returns PhishingResult: { isSuspicious, reason }
 */
export function checkPhishing(
  currentUrl: string,
  savedEntryUrl: string
): PhishingResult {
  const currentHost = extractHostname(currentUrl);
  const savedHost   = extractHostname(savedEntryUrl);

  // Can't compare if either hostname fails to parse
  if (!currentHost || !savedHost) {
    return { isSuspicious: false, reason: null };
  }

  // Rule 1: Exact match → safe
  if (currentHost === savedHost) {
    return { isSuspicious: false, reason: null };
  }

  // Rule 2: Typosquatting — Levenshtein distance 1–3 between hostnames
  const dist = levenshteinDistance(currentHost, savedHost);
  if (dist >= 1 && dist <= 3) {
    return {
      isSuspicious: true,
      reason: `This site looks similar to ${savedHost} — verify before filling`,
    };
  }

  // Rule 3: Substring impersonation — "paypal.com.evil.net" contains "paypal.com"
  // Check if one hostname contains the other as a proper substring
  if (
    (currentHost.includes(savedHost) || savedHost.includes(currentHost)) &&
    currentHost !== savedHost
  ) {
    const impersonated = savedHost.length > currentHost.length ? savedHost : currentHost;
    return {
      isSuspicious: true,
      reason: `This site may be impersonating ${impersonated}`,
    };
  }

  // Rule 4: Same registered domain but different TLD
  // e.g. paypal.net vs paypal.com
  const currentDomain = getRegisteredDomain(currentHost);
  const savedDomain   = getRegisteredDomain(savedHost);
  const currentName   = currentDomain.split(".")[0]!;
  const savedName     = savedDomain.split(".")[0]!;
  const currentTLD    = currentDomain.split(".").slice(1).join(".");
  const savedTLD      = savedDomain.split(".").slice(1).join(".");

  if (currentName === savedName && currentTLD !== savedTLD) {
    return {
      isSuspicious: true,
      reason: `Different domain extension from saved entry ${savedHost}`,
    };
  }

  return { isSuspicious: false, reason: null };
}

// ── Warning banner injection ──────────────────────────────────────────────────

const BANNER_ID = "vaultzero-phishing-warning";
const DISMISS_MS = 10_000; // auto-dismiss after 10 seconds

/**
 * Inject a red warning banner at the top of the page.
 *
 * ⚠️ SECURITY: All DOM construction uses createElement + textContent.
 * NEVER innerHTML — even though the message comes from our own template,
 * defense-in-depth prevents any future code path from accidentally passing
 * user-controlled content here.
 *
 * The banner is:
 *   - Fixed position at top of viewport
 *   - z-index 2147483647 (max signed 32-bit int — highest possible stacking)
 *   - Dismissed by click on × button or automatically after 10 seconds
 *   - Only one banner shown at a time (existing banner replaced)
 *
 * @param message - Human-readable warning message (from our own templates)
 */
export function showPhishingWarning(message: string): void {
  // Remove any existing banner to prevent stacking
  const existing = document.getElementById(BANNER_ID);
  if (existing) existing.remove();

  // ── Build banner using createElement only ─────────────────────────────────

  const banner = document.createElement("div");
  banner.id = BANNER_ID;

  // Critical positioning: must be on top of everything on the page
  Object.assign(banner.style, {
    position:        "fixed",
    top:             "0",
    left:            "0",
    right:           "0",
    zIndex:          "2147483647",
    background:      "linear-gradient(135deg, #7f1d1d, #991b1b)",
    color:           "#fef2f2",
    padding:         "10px 16px",
    display:         "flex",
    alignItems:      "center",
    justifyContent:  "space-between",
    gap:             "12px",
    fontFamily:      "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
    fontSize:        "13px",
    fontWeight:      "500",
    lineHeight:      "1.4",
    boxShadow:       "0 2px 12px rgba(0,0,0,0.5)",
    boxSizing:       "border-box",
  });

  // Warning icon + message (textContent — no HTML)
  const textNode = document.createElement("span");
  textNode.textContent = `⚠️ VaultZero: ${message}`;

  // Dismiss button
  const dismissBtn = document.createElement("button");
  dismissBtn.textContent = "×";
  Object.assign(dismissBtn.style, {
    background:    "none",
    border:        "none",
    color:         "#fef2f2",
    fontSize:      "20px",
    lineHeight:    "1",
    cursor:        "pointer",
    padding:       "0 4px",
    flexShrink:    "0",
    fontWeight:    "300",
  });
  dismissBtn.setAttribute("aria-label", "Dismiss phishing warning");

  const dismiss = () => banner.remove();
  dismissBtn.addEventListener("click", dismiss);

  banner.appendChild(textNode);
  banner.appendChild(dismissBtn);
  document.body.insertBefore(banner, document.body.firstChild);

  // Auto-dismiss after 10 seconds
  setTimeout(dismiss, DISMISS_MS);
}
