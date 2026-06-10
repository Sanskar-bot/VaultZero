/**
 * src/popup/App.tsx — Root Popup Component
 *
 * Handles the top-level locked/unlocked state.
 * When locked: shows UnlockScreen
 * When unlocked: shows VaultList
 *
 * Lock status is queried from the background service worker on mount
 * using the GET_LOCK_STATUS message.
 */
import { useState, useEffect } from "react";
import type { LockStatusResponse } from "../shared/types";
import { UnlockScreen } from "./components/UnlockScreen";
import { VaultList } from "./components/VaultList";

type AppState = "loading" | "locked" | "unlocked";

export function App(): JSX.Element {
  const [appState, setAppState] = useState<AppState>("loading");

  useEffect(() => {
    // Query background for current lock status on mount
    chrome.runtime.sendMessage(
      { type: "GET_LOCK_STATUS", payload: undefined },
      (response: LockStatusResponse) => {
        if (chrome.runtime.lastError) {
          setAppState("locked");
          return;
        }
        setAppState(response.locked ? "locked" : "unlocked");
      }
    );

    // Listen for VAULT_LOCKED broadcast from auto-lock timer
    const listener = (msg: { type: string }) => {
      if (msg.type === "VAULT_LOCKED") {
        setAppState("locked");
      }
    };
    chrome.runtime.onMessage.addListener(listener);
    return () => chrome.runtime.onMessage.removeListener(listener);
  }, []);

  if (appState === "loading") {
    return (
      <div style={styles.centered}>
        <div style={styles.spinner} />
      </div>
    );
  }

  if (appState === "locked") {
    return <UnlockScreen onUnlocked={() => setAppState("unlocked")} />;
  }

  return <VaultList onLocked={() => setAppState("locked")} />;
}

const styles = {
  centered: {
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    height: "100%",
    minHeight: "200px",
  },
  spinner: {
    width: "32px",
    height: "32px",
    border: "3px solid #2d2d4e",
    borderTop: "3px solid #7c3aed",
    borderRadius: "50%",
    animation: "spin 0.8s linear infinite",
  },
} as const;
