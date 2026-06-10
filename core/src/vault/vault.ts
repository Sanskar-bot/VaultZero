/**
 * ═══════════════════════════════════════════════════════════════════
 * Vault Operations — In-Memory Vault CRUD, Search, URL Matching
 * ═══════════════════════════════════════════════════════════════════
 *
 * All vault operations are IMMUTABLE — they return a new VaultStore
 * rather than mutating the original. This is critical for React state
 * management (both in the extension and web UI) and makes undo/redo
 * trivially implementable in the future.
 *
 * The vault exists in plaintext ONLY in client memory while unlocked.
 * Before being sent to the server, it is serialized and encrypted
 * via serializer.ts → encryptData() → opaque blob.
 *
 * Entry IDs use crypto.randomUUID() (Web Crypto, not Math.random()).
 * Timestamps use Date.now() (Unix milliseconds).
 * ═══════════════════════════════════════════════════════════════════
 */

import { webcrypto } from "crypto";
import { VaultEntry, VaultStore, EncryptedVault } from "./types";
import { encryptData, decryptData } from "../crypto/aes-gcm";

/**
 * Create a new empty vault.
 *
 * Called once during user registration to initialize the vault.
 * The empty vault is immediately serialized and encrypted before
 * being sent to the server.
 *
 * @returns A new VaultStore with an empty entries array
 */
export function createVault(): VaultStore {
  return { entries: [] };
}

/**
 * Add a new entry to the vault (immutable).
 *
 * Generates a cryptographically random UUID for the entry ID and sets
 * both createdAt and updatedAt to the current time. Returns a new
 * VaultStore with the entry appended — the original is NOT mutated.
 *
 * @param vault - The current vault state
 * @param entry - Entry data without id, createdAt, or updatedAt
 * @returns A new VaultStore with the entry added
 */
export function addEntry(
  vault: VaultStore,
  entry: Omit<VaultEntry, "id" | "createdAt" | "updatedAt">
): VaultStore {
  const now = Date.now();
  const newEntry: VaultEntry = {
    ...entry,
    id: webcrypto.randomUUID(),
    createdAt: now,
    updatedAt: now,
  };

  return {
    entries: [...vault.entries, newEntry],
  };
}

/**
 * Update an existing entry in the vault (immutable).
 *
 * Merges the provided updates into the existing entry and automatically
 * bumps the updatedAt timestamp. Returns a new VaultStore — the
 * original is NOT mutated.
 *
 * @param vault - The current vault state
 * @param id - The UUID of the entry to update
 * @param updates - Partial entry fields to merge (id, createdAt ignored)
 * @returns A new VaultStore with the updated entry
 * @throws Error if no entry with the given id exists
 */
export function updateEntry(
  vault: VaultStore,
  id: string,
  updates: Partial<Omit<VaultEntry, "id" | "createdAt">>
): VaultStore {
  const entryIndex = vault.entries.findIndex((e) => e.id === id);

  if (entryIndex === -1) {
    throw new Error(`Entry not found: no entry with id "${id}" exists in the vault`);
  }

  const existingEntry = vault.entries[entryIndex];
  const updatedEntry: VaultEntry = {
    ...existingEntry,
    ...updates,
    id: existingEntry.id, // never allow overriding id
    createdAt: existingEntry.createdAt, // never allow overriding createdAt
    updatedAt: Date.now(),
  };

  const newEntries = [...vault.entries];
  newEntries[entryIndex] = updatedEntry;

  return { entries: newEntries };
}

/**
 * Delete an entry from the vault (immutable).
 *
 * Removes the entry with the given ID. Returns a new VaultStore —
 * the original is NOT mutated.
 *
 * @param vault - The current vault state
 * @param id - The UUID of the entry to delete
 * @returns A new VaultStore without the deleted entry
 * @throws Error if no entry with the given id exists
 */
export function deleteEntry(vault: VaultStore, id: string): VaultStore {
  const entryIndex = vault.entries.findIndex((e) => e.id === id);

  if (entryIndex === -1) {
    throw new Error(`Entry not found: no entry with id "${id}" exists in the vault`);
  }

  return {
    entries: vault.entries.filter((e) => e.id !== id),
  };
}

/**
 * Search entries by partial match across url and username fields.
 *
 * Case-insensitive search: "git" matches "GitHub", "gitlab.com",
 * "user@github.com", etc. Searches both the url and username fields.
 *
 * @param vault - The current vault state
 * @param query - Search string (case-insensitive)
 * @returns Array of matching VaultEntry objects
 */
export function searchEntries(
  vault: VaultStore,
  query: string
): VaultEntry[] {
  const lowerQuery = query.toLowerCase();

  return vault.entries.filter(
    (entry) =>
      entry.url.toLowerCase().includes(lowerQuery) ||
      entry.username.toLowerCase().includes(lowerQuery)
  );
}

/**
 * Find entries that match a given URL by hostname.
 *
 * Used by the browser extension to auto-fill credentials for the
 * current tab. Extracts the hostname from both the input URL and
 * each saved entry's URL, then compares hostnames (not full URLs).
 *
 * Example:
 *   Input:  "https://github.com/login?redirect=dashboard"
 *   Match:  entry with url "https://github.com"
 *   Match:  entry with url "https://github.com/settings"
 *   No:     entry with url "https://gitlab.com"
 *
 * @param vault - The current vault state
 * @param url - The URL to match against (typically from the browser tab)
 * @returns Array of VaultEntry objects whose hostname matches
 */
export function getEntriesForUrl(
  vault: VaultStore,
  url: string
): VaultEntry[] {
  const inputHostname = extractHostname(url);
  if (!inputHostname) return [];

  return vault.entries.filter((entry) => {
    const entryHostname = extractHostname(entry.url);
    return entryHostname === inputHostname;
  });
}

/**
 * Serialize and encrypt the entire vault into an opaque blob.
 *
 * This is the function that bridges vault CRUD operations and AES-256-GCM
 * encryption. It takes the in-memory VaultStore, JSON-serializes all entries,
 * encrypts the JSON string with the vault key, and returns an EncryptedVault
 * object ready to be pushed to the server.
 *
 * A fresh random IV is generated for every call (via encryptData), so
 * encrypting the same vault twice produces different ciphertext.
 *
 * @param vault - The plaintext vault state (exists only in client memory)
 * @param vaultKey - 32-byte AES-256 vault key
 * @returns EncryptedVault with ciphertext + timestamp, ready for server storage
 * @throws Error if serialization or encryption fails
 */
export async function encryptVault(
  vault: VaultStore,
  vaultKey: Uint8Array
): Promise<EncryptedVault> {
  try {
    // Serialize the vault to a JSON string.
    // This is the plaintext that will be encrypted — it contains ALL
    // passwords, usernames, URLs, and notes in readable form.
    const plaintext = JSON.stringify(vault);

    // Encrypt with AES-256-GCM. A fresh 12-byte IV is generated internally.
    const ciphertext = await encryptData(plaintext, vaultKey);

    return {
      ciphertext,
      updatedAt: Date.now(),
    };
  } catch (error) {
    throw new Error(
      `Failed to encrypt vault: ${error instanceof Error ? error.message : "unknown error"}`
    );
  }
}

/**
 * Decrypt an encrypted vault blob back to the in-memory VaultStore.
 *
 * This reverses encryptVault(): takes the opaque blob from the server,
 * decrypts it with the vault key, parses the JSON, and returns the
 * plaintext VaultStore.
 *
 * If the vault key is wrong or the ciphertext has been tampered with,
 * the AES-GCM authentication check FAILS and this function throws.
 * It will NEVER return corrupted or garbage data.
 *
 * @param encrypted - EncryptedVault blob from the server
 * @param vaultKey - 32-byte AES-256 vault key (must match the key used to encrypt)
 * @returns The decrypted VaultStore with all entries in plaintext
 * @throws Error if decryption fails (wrong key, tampered data, invalid JSON)
 */
export async function decryptVault(
  encrypted: EncryptedVault,
  vaultKey: Uint8Array
): Promise<VaultStore> {
  try {
    // Decrypt the ciphertext back to JSON string
    const plaintext = await decryptData(encrypted.ciphertext, vaultKey);

    // Parse the JSON back into a VaultStore object
    const vault: VaultStore = JSON.parse(plaintext);

    // Validate the parsed structure has the expected shape
    if (!vault || !Array.isArray(vault.entries)) {
      throw new Error("Decrypted vault has invalid structure: missing entries array");
    }

    return vault;
  } catch (error) {
    if (
      error instanceof Error &&
      error.message.includes("invalid structure")
    ) {
      throw error;
    }
    if (
      error instanceof Error &&
      error.message.includes("wrong key")
    ) {
      throw error;
    }
    throw new Error(
      `Failed to decrypt vault: ${error instanceof Error ? error.message : "unknown error"}`
    );
  }
}

/**
 * Extract the hostname from a URL string.
 *
 * Handles URLs with and without protocol prefixes:
 * - "https://github.com/path" → "github.com"
 * - "github.com/path" → "github.com"
 * - "http://sub.domain.com:8080/path" → "sub.domain.com"
 *
 * @param url - A URL string (may or may not include protocol)
 * @returns The hostname, or empty string if parsing fails
 */
function extractHostname(url: string): string {
  try {
    // If the URL doesn't have a protocol, add one for URL parsing
    const urlToParse = url.includes("://") ? url : `https://${url}`;
    const parsed = new URL(urlToParse);
    return parsed.hostname.toLowerCase();
  } catch {
    // URL parsing failed — return empty string (no match possible)
    return "";
  }
}
