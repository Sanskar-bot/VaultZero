/**
 * Background Service Worker
 *
 * Responsibilities:
 * - Hold decrypted vault in memory ONLY while unlocked
 * - Auto-lock after 5 minutes of idle (clear vault from memory)
 * - Handle all crypto operations (content script never touches raw vault)
 * - Respond to messages: GET_CREDENTIALS_FOR_URL, SAVE_ENTRY, LOCK, UNLOCK
 *
 * SECURITY: This is the only context that ever sees decrypted passwords.
 *           The content script and popup communicate via chrome.runtime messages.
 *
 * Implementation: Day 7-8
 */

// TODO: Day 7-8 — implement service worker message handler and vault manager
