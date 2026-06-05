/**
 * Content Script — Form Detection and Autofill
 *
 * Runs in an isolated world on every page. Responsibilities:
 * - Detect login forms (input[type=password] + nearby username/email fields)
 * - Inject a VaultZero key icon next to password fields
 * - On icon click: request matching credentials from background, fill fields
 * - Dispatch InputEvent after fill so React/Angular/Vue register the value
 * - On form submit: capture credentials, offer to save via background worker
 * - Phishing check: Levenshtein distance on hostname vs saved URLs
 *
 * SECURITY:
 * - Content script runs in isolated world — page JS cannot access vault data
 * - Content script NEVER holds decrypted vault — it requests single entries
 *   from the background worker as needed
 * - Never uses innerHTML with user content (XSS prevention)
 *
 * Implementation: Day 8-9
 */

// TODO: Day 8-9 — implement form detection, icon injection, autofill
