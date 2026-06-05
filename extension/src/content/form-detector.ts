/**
 * Form Detector — finds login forms on the current page
 *
 * Heuristics:
 * - Look for input[type=password] elements
 * - Walk up the DOM tree to find the containing <form>
 * - Within that form, find username/email fields by type, name, id, autocomplete
 * - Handle edge cases: shadow DOM, iframes (same-origin only), SPA navigation
 *
 * Implementation: Day 8-9
 */

// TODO: Day 8-9 — implement detectLoginForms()
