/**
 * BIP39-style Recovery Phrase Generation
 *
 * On registration, we generate a 24-word recovery phrase from a
 * cryptographically secure random source (crypto.getRandomValues).
 *
 * This phrase is:
 * - Shown ONCE to the user
 * - NEVER stored in plaintext anywhere
 * - Server stores only SHA-256(phrase) for verification during recovery
 *
 * Recovery flow:
 * 1. User enters phrase → client derives recovery KEK (deterministic)
 * 2. Server returns wrapped_vault_key
 * 3. Client unwraps vault key with recovery KEK
 * 4. Client re-wraps vault key with new master password's KEK
 * 5. Client pushes new wrapped_vault_key to server
 *
 * What would break if misused:
 * - Using Math.random() → predictable phrases, attacker can brute-force
 * - Storing the phrase → defeats the entire recovery model
 * - Not using a large enough word list → insufficient entropy
 *
 * Implementation: Day 3
 */

// TODO: Day 3 — implement generateRecoveryPhrase() → string (24 space-separated words)
// TODO: Day 3 — implement hashRecoveryPhrase(phrase) → string (SHA-256 hex)
// TODO: Day 3 — implement deriveRecoveryKEK(phrase, salt) → Uint8Array(32)

export {};
