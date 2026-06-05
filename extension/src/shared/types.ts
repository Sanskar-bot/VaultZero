/**
 * Shared Types for the extension UI
 */

export interface PopupState {
  isLocked: boolean;
  entries: import("@vaultzero/core").VaultEntry[];
  searchQuery: string;
  currentScreen: "lock" | "vault" | "add" | "edit";
  editingEntryId: string | null;
}
