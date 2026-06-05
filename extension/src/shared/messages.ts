/**
 * Message Types — shared between background, content, and popup
 *
 * All communication between extension contexts uses chrome.runtime.sendMessage
 * with these typed message envelopes.
 */

export enum MessageType {
  // Content script → Background
  GET_CREDENTIALS_FOR_URL = "GET_CREDENTIALS_FOR_URL",
  SAVE_ENTRY = "SAVE_ENTRY",

  // Popup → Background
  UNLOCK = "UNLOCK",
  LOCK = "LOCK",
  GET_ALL_ENTRIES = "GET_ALL_ENTRIES",
  ADD_ENTRY = "ADD_ENTRY",
  UPDATE_ENTRY = "UPDATE_ENTRY",
  DELETE_ENTRY = "DELETE_ENTRY",
  GENERATE_PASSWORD = "GENERATE_PASSWORD",

  // Background → Content script / Popup
  VAULT_LOCKED = "VAULT_LOCKED",
  VAULT_UNLOCKED = "VAULT_UNLOCKED",
  CREDENTIALS_RESPONSE = "CREDENTIALS_RESPONSE",
  ENTRIES_RESPONSE = "ENTRIES_RESPONSE",
  ERROR = "ERROR",
}

export interface ExtensionMessage {
  type: MessageType;
  payload?: unknown;
}
