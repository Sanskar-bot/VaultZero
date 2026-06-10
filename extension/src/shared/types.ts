/**
 * src/shared/types.ts — Message Protocol between Extension Components
 *
 * The extension has three isolated JS contexts that can only communicate
 * via chrome.runtime.sendMessage / chrome.tabs.sendMessage:
 *
 *   Popup    ──sendMessage──► Background (service worker)
 *   Content  ──sendMessage──► Background (service worker)
 *   Background ──sendMessage──► Content (via chrome.tabs.sendMessage)
 *
 * This file defines the full message protocol as discriminated union types.
 * Using this protocol prevents runtime message mismatches between contexts.
 *
 * ⚠️ SECURITY NOTE: Content scripts are the most exposed component.
 *   They run in the same process as the web page (just in an isolated world).
 *   ALL messages from content scripts MUST be treated as untrusted input.
 *   The background worker validates sender.tab before acting on any message
 *   from a content script.
 */

import type { VaultEntry, VaultStore } from "@vaultzero/core";

// Re-export for convenience so importers don't need to know about /core
export type { VaultEntry, VaultStore };

// ── Message Type Discriminant ─────────────────────────────────────────────────

export type MessageType =
  | "UNLOCK"
  | "LOCK"
  | "GET_CREDENTIALS_FOR_URL"
  | "SAVE_ENTRY"
  | "UPDATE_ENTRY"
  | "DELETE_ENTRY"
  | "GET_VAULT"
  | "SYNC_VAULT"
  | "GET_LOCK_STATUS"
  | "GENERATE_PASSWORD"
  | "GET_AUDIT_LOG"
  | "VAULT_LOCKED";   // background → content: vault has been locked externally

// ── Generic Message Wrapper ───────────────────────────────────────────────────

export type Message<T extends MessageType, P = undefined> = {
  type: T;
  payload: P;
};

// ── Outbound Messages (popup/content → background) ────────────────────────────

export type UnlockMessage = Message<
  "UNLOCK",
  { masterPassword: string }
>;

export type LockMessage = Message<"LOCK", undefined>;

export type GetCredentialsMessage = Message<
  "GET_CREDENTIALS_FOR_URL",
  { url: string }
>;

export type SaveEntryMessage = Message<
  "SAVE_ENTRY",
  { entry: Omit<VaultEntry, "id" | "createdAt" | "updatedAt"> }
>;

export type UpdateEntryMessage = Message<
  "UPDATE_ENTRY",
  { id: string; updates: Partial<Omit<VaultEntry, "id" | "createdAt">> }
>;

export type DeleteEntryMessage = Message<
  "DELETE_ENTRY",
  { id: string }
>;

export type GetVaultMessage = Message<"GET_VAULT", undefined>;

export type SyncVaultMessage = Message<"SYNC_VAULT", undefined>;

export type GetLockStatusMessage = Message<"GET_LOCK_STATUS", undefined>;

export type GeneratePasswordMessage = Message<
  "GENERATE_PASSWORD",
  { length: number; symbols: boolean; numbers: boolean }
>;

export type GetAuditLogMessage = Message<"GET_AUDIT_LOG", undefined>;

/** Union of all messages the background can receive */
export type AnyMessage =
  | UnlockMessage
  | LockMessage
  | GetCredentialsMessage
  | SaveEntryMessage
  | UpdateEntryMessage
  | DeleteEntryMessage
  | GetVaultMessage
  | SyncVaultMessage
  | GetLockStatusMessage
  | GeneratePasswordMessage
  | GetAuditLogMessage;

// ── Inbound Messages (background → content) ───────────────────────────────────

export type VaultLockedMessage = Message<"VAULT_LOCKED", undefined>;

// ── Response Shapes ───────────────────────────────────────────────────────────

/**
 * Minimal credential shape returned to content scripts.
 * Content scripts ONLY get these four fields — never notes, dates, or full vault.
 *
 * ⚠️ SECURITY NOTE: Never add 'notes' here. The content script is the most
 *   exposed context — it runs in the same process as potentially hostile web pages.
 *   Minimising what it can receive limits blast radius if a content script
 *   is somehow exploited.
 */
export type CredentialEntry = {
  id:       string;
  username: string;
  password: string;
  url:      string;
};

export type CredentialsResponse = {
  entries: CredentialEntry[];
};

export type VaultResponse = {
  entries: VaultEntry[];
};

export type LockStatusResponse = {
  locked: boolean;
};

export type ErrorResponse = {
  error: string;
};

export type SuccessResponse = {
  success: true;
};

export type GeneratedPasswordResponse = {
  password: string;
};

/** Union of all possible response types */
export type AnyResponse =
  | CredentialsResponse
  | VaultResponse
  | LockStatusResponse
  | ErrorResponse
  | SuccessResponse
  | GeneratedPasswordResponse;

// ── Type Guards ───────────────────────────────────────────────────────────────

export function isErrorResponse(r: AnyResponse): r is ErrorResponse {
  return "error" in r;
}

export function isSuccessResponse(r: AnyResponse): r is SuccessResponse {
  return "success" in r && (r as SuccessResponse).success === true;
}
