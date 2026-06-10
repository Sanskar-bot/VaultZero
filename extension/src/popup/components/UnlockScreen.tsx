/**
 * src/popup/components/UnlockScreen.tsx
 * Master password entry form. Sends UNLOCK message to background worker.
 */
import { useState, useRef } from "react";
import type { SuccessResponse, ErrorResponse } from "../../shared/types";

interface Props {
  onUnlocked: () => void;
}

export function UnlockScreen({ onUnlocked }: Props): JSX.Element {
  const [password, setPassword] = useState("");
  const [error, setError]       = useState<string | null>(null);
  const [loading, setLoading]   = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleUnlock = async () => {
    if (!password.trim()) return;
    setLoading(true);
    setError(null);

    chrome.runtime.sendMessage(
      { type: "UNLOCK", payload: { masterPassword: password } },
      (response: SuccessResponse | ErrorResponse) => {
        setLoading(false);
        // Clear password from state immediately after sending
        setPassword("");
        if ("error" in response) {
          setError(response.error);
        } else {
          onUnlocked();
        }
      }
    );
  };

  return (
    <div style={s.container}>
      <div style={s.logo}>🔐</div>
      <h1 style={s.title}>VaultZero</h1>
      <p style={s.subtitle}>Enter your master password</p>

      <input
        ref={inputRef}
        id="master-password"
        type="password"
        autoComplete="current-password"
        placeholder="Master password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        onKeyDown={(e) => { if (e.key === "Enter") void handleUnlock(); }}
        style={s.input}
        autoFocus
        disabled={loading}
      />

      {error && <p style={s.error}>{error}</p>}

      <button
        id="unlock-btn"
        onClick={() => void handleUnlock()}
        disabled={loading || !password.trim()}
        style={{ ...s.button, opacity: loading ? 0.6 : 1 }}
      >
        {loading ? "Unlocking…" : "Unlock Vault"}
      </button>
    </div>
  );
}

const s = {
  container: { padding: "32px 24px", display: "flex", flexDirection: "column" as const, alignItems: "center", gap: "12px" },
  logo:      { fontSize: "48px" },
  title:     { fontSize: "22px", fontWeight: 700, color: "#e0e0f0", letterSpacing: "-0.5px" },
  subtitle:  { fontSize: "13px", color: "#888aab", marginBottom: "8px" },
  input:     { width: "100%", padding: "10px 14px", background: "#1a1a2e", border: "1.5px solid #2d2d4e", borderRadius: "8px", color: "#e0e0f0", fontSize: "14px", outline: "none" },
  error:     { color: "#f87171", fontSize: "12px", alignSelf: "flex-start" as const },
  button:    { width: "100%", padding: "11px", background: "linear-gradient(135deg,#7c3aed,#4f46e5)", border: "none", borderRadius: "8px", color: "#fff", fontWeight: 600, fontSize: "14px", cursor: "pointer" },
} as const;
