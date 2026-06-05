/**
 * Phishing Detection — Levenshtein distance check on hostnames
 *
 * Compares the current window.location.hostname against saved entry URLs.
 * If Levenshtein distance <= 3 and hostnames are NOT identical, show a
 * red warning banner: "This site looks similar to [saved-url]. Possible phishing."
 *
 * This catches typosquatting attacks like "g1thub.com" vs "github.com".
 *
 * Implementation: Day 9
 */

// TODO: Day 9 — implement levenshteinDistance() and checkPhishing()
