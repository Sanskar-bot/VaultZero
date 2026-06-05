/**
 * VaultEntry — the plaintext structure that exists ONLY in client memory.
 *
 * An array of VaultEntry objects is JSON-serialized and then encrypted
 * as a single AES-256-GCM blob before leaving the device.
 *
 * The server NEVER sees this type in plaintext.
 */
export interface VaultEntry {
  /** UUID v4, generated client-side */
  id: string;

  /** The website URL this credential belongs to, e.g. "https://github.com" */
  url: string;

  /** Username or email used for login */
  username: string;

  /** The actual password — exists in memory only while vault is unlocked */
  password: string;

  /** Optional freeform notes (also encrypted in the blob) */
  notes?: string;

  /** Unix timestamp (ms) when this entry was created */
  createdAt: number;

  /** Unix timestamp (ms) when this entry was last modified */
  updatedAt: number;
}

/**
 * The complete vault state held in client memory while unlocked.
 */
export interface Vault {
  entries: VaultEntry[];
  lastSyncedAt: number | null;
}

/**
 * Encrypted vault blob as transmitted to/from the server.
 * The server stores this opaque structure — it cannot read anything inside.
 */
export interface EncryptedVault {
  /** Base64-encoded AES-256-GCM ciphertext (IV prepended) */
  ciphertext: string;

  /** ISO 8601 timestamp of when the server last received a push */
  updatedAt: string;
}
