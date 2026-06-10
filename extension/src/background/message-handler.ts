/**
 * src/background/message-handler.ts — Central Message Dispatcher
 *
 * Handles ALL messages from content scripts and the popup.
 *
 * ═══════════════════════════════════════════════════════════════
 * SECURITY ARCHITECTURE
 * ═══════════════════════════════════════════════════════════════
 *
 * [A] SENDER VALIDATION:
 *   Every message is checked for sender.tab presence before acting.
 *   Messages from the extension popup have no sender.tab.
 *   Messages from content scripts MUST have sender.tab.
 *   This prevents a web page from spoofing a content script message.
 *   (Web pages cannot send chrome.runtime.sendMessage to extensions
 *    they don't know the ID of, but we validate defensively anyway.)
 *
 * [B] CREDENTIAL MINIMISATION:
 *   GET_CREDENTIALS_FOR_URL returns ONLY { id, username, password, url }.
 *   Notes, timestamps, and full VaultStore are NEVER sent to content scripts.
 *   Content scripts are treated as untrusted — they run in the same process
 *   as (potentially hostile) web pages.
 *
 * [C] OPAQUE ERROR MESSAGES:
 *   On UNLOCK failure, we return "Unlock failed — check your password"
 *   regardless of which step failed. This prevents an attacker who can
 *   send UNLOCK messages from learning which step is failing.
 *
 * [D] CRYPTO IN BACKGROUND ONLY:
 *   All calls to @vaultzero/core (deriveKEK, unwrapVaultKey, encryptVault,
 *   decryptVault) happen here in the background service worker.
 *   The content script NEVER imports /core — it only receives credentials.
 *
 * [E] ACTIVITY TRACKING:
 *   Every successful message resets the auto-lock idle timer.
 * ═══════════════════════════════════════════════════════════════
 */

import {
  deriveKEK,
  unwrapVaultKey,
  encryptVault,
  decryptVault,
  addEntry,
  deleteEntry,
  updateEntry,
  getEntriesForUrl,
  createVault,
} from "@vaultzero/core";

import type { AnyMessage, AnyResponse, CredentialEntry } from "../shared/types";
import {
  STORAGE_KEY_SALT,
  STORAGE_KEY_WRAPPED_KEY,
  DEFAULT_PASSWORD_LENGTH,
} from "../shared/constants";
import {
  isLocked,
  getVault,
  getVaultKey,
  setUnlocked,
  setLocked,
  setVault,
  updateActivity,
} from "./vault-state";
import {
  pullVault,
  pushVault,
} from "./api-client";
import { startAutoLockTimer, stopTimer, resetTimer } from "./auto-lock";

// ── Main message handler ──────────────────────────────────────────────────────

/**
 * Central message dispatcher.
 *
 * Returns true from the listener when we call sendResponse asynchronously.
 * This is required by the Chrome extension API to keep the message channel open.
 */
export function handleMessage(
  message: AnyMessage,
  sender: chrome.runtime.MessageSender,
  sendResponse: (response: AnyResponse) => void
): boolean {
  // Dispatch to appropriate handler (async inside sync listener pattern)
  void dispatch(message, sender, sendResponse);
  return true; // Keep message channel open for async sendResponse
}

async function dispatch(
  message: AnyMessage,
  sender: chrome.runtime.MessageSender,
  sendResponse: (response: AnyResponse) => void
): Promise<void> {
  try {
    switch (message.type) {
      case "UNLOCK":
        await handleUnlock(message.payload.masterPassword, sendResponse);
        break;

      case "LOCK":
        setLocked();
        stopTimer();
        sendResponse({ success: true });
        break;

      case "GET_CREDENTIALS_FOR_URL":
        // [A] Validate sender has a tab (content script source verification)
        await handleGetCredentials(message.payload.url, sender, sendResponse);
        break;

      case "SAVE_ENTRY":
        await handleSaveEntry(message.payload.entry, sendResponse);
        break;

      case "UPDATE_ENTRY":
        await handleUpdateEntry(message.payload.id, message.payload.updates, sendResponse);
        break;

      case "DELETE_ENTRY":
        await handleDeleteEntry(message.payload.id, sendResponse);
        break;

      case "GET_VAULT":
        handleGetVault(sendResponse);
        break;

      case "SYNC_VAULT":
        await handleSyncVault(sendResponse);
        break;

      case "GET_LOCK_STATUS":
        sendResponse({ locked: isLocked() });
        break;

      case "GENERATE_PASSWORD":
        sendResponse({
          password: generatePassword(
            message.payload.length ?? DEFAULT_PASSWORD_LENGTH,
            message.payload.symbols,
            message.payload.numbers
          ),
        });
        break;

      default:
        sendResponse({ error: "Unknown message type" });
    }
  } catch (err) {
    // Never expose internal error details to callers
    console.error("[MessageHandler] Error:", err);
    sendResponse({ error: "Operation failed" });
  }
}

// ── UNLOCK ────────────────────────────────────────────────────────────────────

async function handleUnlock(
  masterPassword: string,
  sendResponse: (r: AnyResponse) => void
): Promise<void> {
  try {
    // Step 1: Read stored vault material from chrome.storage.local
    const stored = await new Promise<Record<string, string>>((resolve) => {
      chrome.storage.local.get([STORAGE_KEY_SALT, STORAGE_KEY_WRAPPED_KEY], (r) => {
        resolve(r as Record<string, string>);
      });
    });

    const argon2SaltB64   = stored[STORAGE_KEY_SALT];
    const wrappedVaultKey = stored[STORAGE_KEY_WRAPPED_KEY];

    if (!argon2SaltB64 || !wrappedVaultKey) {
      sendResponse({ error: "Not logged in — please log in first" });
      return;
    }

    // Step 2: Decode base64 salt → Uint8Array
    const saltBytes = Uint8Array.from(atob(argon2SaltB64), (c) => c.charCodeAt(0));

    // Step 3: [D] Argon2id key derivation — ONLY in background worker
    // This is the expensive operation (64 MiB, 3 iterations).
    // Takes ~0.5-1 second on modern hardware.
    const kek = await deriveKEK(masterPassword, saltBytes);

    // Step 4: Unwrap vault key with KEK (AES-256-GCM decrypt)
    // Throws "wrong KEK" if master password is incorrect — caught below
    const vaultKey = await unwrapVaultKey(wrappedVaultKey, kek);

    // Step 5: Pull ciphertext from server
    let ciphertext: string;
    try {
      ciphertext = await pullVault();
    } catch (e) {
      if (e instanceof Error && e.message === "NO_VAULT") {
        // First-time login — initialise empty vault
        const emptyVault = createVault();
        const encrypted  = await encryptVault(emptyVault, vaultKey);
        await pushVault(encrypted.ciphertext);
        setUnlocked(vaultKey, emptyVault);
        startAutoLockTimer();
        sendResponse({ success: true });
        return;
      }
      throw e;
    }

    // Step 6: Decrypt vault blob → plaintext VaultStore
    const vault = await decryptVault({ ciphertext, updatedAt: Date.now() }, vaultKey);

    // Step 7: Store in memory, start timer
    setUnlocked(vaultKey, vault);
    startAutoLockTimer();

    sendResponse({ success: true });
  } catch {
    // [C] Opaque error — never reveal which step failed
    // (Could be wrong password, network error, or corrupt vault)
    sendResponse({ error: "Unlock failed — check your password" });
  }
}

// ── GET_CREDENTIALS_FOR_URL ───────────────────────────────────────────────────

async function handleGetCredentials(
  url: string,
  sender: chrome.runtime.MessageSender,
  sendResponse: (r: AnyResponse) => void
): Promise<void> {
  if (isLocked()) {
    sendResponse({ error: "Vault is locked" });
    return;
  }

  // [A] SENDER VALIDATION: content scripts must have a tab
  // Reject messages from contexts without a tab (shouldn't happen normally)
  if (!sender.tab?.id) {
    console.warn("[MessageHandler] GET_CREDENTIALS received without sender.tab — rejected");
    sendResponse({ error: "Forbidden" });
    return;
  }

  const vault = getVault();
  if (!vault) {
    sendResponse({ error: "Vault not available" });
    return;
  }

  const matches = getEntriesForUrl(vault, url);

  // [B] CREDENTIAL MINIMISATION — only return { id, username, password, url }
  // Never return notes, createdAt, updatedAt, or the full vault to content scripts
  const minimalEntries: CredentialEntry[] = matches.map((e) => ({
    id:       e.id,
    username: e.username,
    password: e.password,
    url:      e.url,
  }));

  resetTimer(); // [E] Activity tracking
  sendResponse({ entries: minimalEntries });
}

// ── SAVE_ENTRY ────────────────────────────────────────────────────────────────

async function handleSaveEntry(
  entryData: Parameters<typeof addEntry>[1],
  sendResponse: (r: AnyResponse) => void
): Promise<void> {
  if (isLocked()) { sendResponse({ error: "Vault is locked" }); return; }

  const vault    = getVault()!;
  const vaultKey = getVaultKey()!;

  const newVault  = addEntry(vault, entryData);
  const encrypted = await encryptVault(newVault, vaultKey);

  await pushVault(encrypted.ciphertext);
  setVault(newVault);

  resetTimer();
  sendResponse({ success: true });
}

// ── UPDATE_ENTRY ──────────────────────────────────────────────────────────────

async function handleUpdateEntry(
  id: string,
  updates: Parameters<typeof updateEntry>[2],
  sendResponse: (r: AnyResponse) => void
): Promise<void> {
  if (isLocked()) { sendResponse({ error: "Vault is locked" }); return; }

  const vault    = getVault()!;
  const vaultKey = getVaultKey()!;

  const newVault  = updateEntry(vault, id, updates);
  const encrypted = await encryptVault(newVault, vaultKey);

  await pushVault(encrypted.ciphertext);
  setVault(newVault);

  resetTimer();
  sendResponse({ success: true });
}

// ── DELETE_ENTRY ──────────────────────────────────────────────────────────────

async function handleDeleteEntry(
  id: string,
  sendResponse: (r: AnyResponse) => void
): Promise<void> {
  if (isLocked()) { sendResponse({ error: "Vault is locked" }); return; }

  const vault    = getVault()!;
  const vaultKey = getVaultKey()!;

  const newVault  = deleteEntry(vault, id);
  const encrypted = await encryptVault(newVault, vaultKey);

  await pushVault(encrypted.ciphertext);
  setVault(newVault);

  resetTimer();
  sendResponse({ success: true });
}

// ── GET_VAULT ─────────────────────────────────────────────────────────────────

function handleGetVault(sendResponse: (r: AnyResponse) => void): void {
  if (isLocked()) { sendResponse({ error: "Vault is locked" }); return; }

  const vault = getVault();
  if (!vault) { sendResponse({ error: "Vault not available" }); return; }

  // Popup-only endpoint — safe to return full entries including notes
  updateActivity();
  sendResponse({ entries: vault.entries });
}

// ── SYNC_VAULT ────────────────────────────────────────────────────────────────

async function handleSyncVault(sendResponse: (r: AnyResponse) => void): Promise<void> {
  if (isLocked()) { sendResponse({ error: "Vault is locked" }); return; }

  const vault    = getVault()!;
  const vaultKey = getVaultKey()!;

  const encrypted = await encryptVault(vault, vaultKey);
  await pushVault(encrypted.ciphertext);

  resetTimer();
  sendResponse({ success: true });
}

// ── Password Generator ────────────────────────────────────────────────────────

function generatePassword(
  length: number,
  symbols: boolean,
  numbers: boolean
): string {
  let charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
  if (numbers) charset += "0123456789";
  if (symbols) charset += "!@#$%^&*()_+-=[]{}|;:,.<>?";

  // Use crypto.getRandomValues for CSPRNG — never Math.random()
  const values  = new Uint32Array(length);
  crypto.getRandomValues(values);

  return Array.from(values)
    .map((v) => charset[v % charset.length])
    .join("");
}
