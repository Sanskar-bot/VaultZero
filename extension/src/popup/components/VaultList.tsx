/**
 * src/popup/components/VaultList.tsx
 * Main vault view — lists all entries after unlocking.
 */
import { useState, useEffect } from "react";
import type { VaultEntry, VaultResponse, ErrorResponse } from "../../shared/types";

interface Props {
  onLocked: () => void;
}

export function VaultList({ onLocked }: Props): JSX.Element {
  const [entries, setEntries]   = useState<VaultEntry[]>([]);
  const [query, setQuery]       = useState("");
  const [loading, setLoading]   = useState(true);
  const [copied, setCopied]     = useState<string | null>(null);

  useEffect(() => {
    chrome.runtime.sendMessage(
      { type: "GET_VAULT", payload: undefined },
      (response: VaultResponse | ErrorResponse) => {
        setLoading(false);
        if ("entries" in response) setEntries(response.entries);
      }
    );
  }, []);

  const lock = () => {
    chrome.runtime.sendMessage({ type: "LOCK", payload: undefined }, () => onLocked());
  };

  const copyPassword = (entry: VaultEntry) => {
    void navigator.clipboard.writeText(entry.password).then(() => {
      setCopied(entry.id);
      // Auto-clear clipboard after 30 seconds (security)
      setTimeout(() => {
        void navigator.clipboard.writeText("");
        setCopied(null);
      }, 30_000);
    });
  };

  const filtered = entries.filter(
    (e) =>
      e.url.toLowerCase().includes(query.toLowerCase()) ||
      e.username.toLowerCase().includes(query.toLowerCase())
  );

  return (
    <div style={s.container}>
      <div style={s.header}>
        <span style={s.logo}>🔐 VaultZero</span>
        <button id="lock-btn" onClick={lock} style={s.lockBtn} title="Lock vault">🔒</button>
      </div>

      <input
        id="vault-search"
        type="search"
        placeholder="Search entries…"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        style={s.search}
      />

      {loading ? (
        <p style={s.muted}>Loading…</p>
      ) : filtered.length === 0 ? (
        <p style={s.muted}>{query ? "No results" : "No saved passwords yet"}</p>
      ) : (
        <div style={s.list}>
          {filtered.map((entry) => (
            <div key={entry.id} style={s.card}>
              <div style={s.cardUrl}>{entry.url}</div>
              <div style={s.cardUser}>{entry.username}</div>
              <button
                id={`copy-${entry.id}`}
                onClick={() => copyPassword(entry)}
                style={{ ...s.copyBtn, background: copied === entry.id ? "#22c55e22" : "#7c3aed22" }}
              >
                {copied === entry.id ? "✓ Copied" : "Copy password"}
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

const s = {
  container: { display: "flex", flexDirection: "column" as const, height: "100%", padding: "16px" },
  header:    { display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" },
  logo:      { fontWeight: 700, fontSize: "15px", color: "#a78bfa" },
  lockBtn:   { background: "none", border: "none", cursor: "pointer", fontSize: "16px" },
  search:    { width: "100%", padding: "8px 12px", background: "#1a1a2e", border: "1.5px solid #2d2d4e", borderRadius: "8px", color: "#e0e0f0", fontSize: "13px", marginBottom: "12px", outline: "none" },
  list:      { overflowY: "auto" as const, display: "flex", flexDirection: "column" as const, gap: "8px" },
  card:      { background: "#1a1a2e", borderRadius: "8px", padding: "12px", border: "1px solid #2d2d4e" },
  cardUrl:   { fontSize: "12px", color: "#888aab", marginBottom: "2px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" as const },
  cardUser:  { fontSize: "14px", fontWeight: 600, color: "#e0e0f0", marginBottom: "8px" },
  copyBtn:   { padding: "5px 12px", border: "1px solid #7c3aed44", borderRadius: "6px", color: "#a78bfa", fontSize: "12px", cursor: "pointer", transition: "background 0.2s" },
  muted:     { color: "#555770", fontSize: "13px", textAlign: "center" as const, marginTop: "32px" },
} as const;
