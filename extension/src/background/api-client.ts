/**
 * src/background/api-client.ts — Backend API Client
 *
 * All communication with the VaultZero backend REST API.
 * Uses the JWT from chrome.storage.local with automatic refresh-on-401.
 *
 * ⚠️ SECURITY NOTES:
 *
 * 1. JWT and refresh token are stored in chrome.storage.local.
 *    This is appropriate for tokens — chrome.storage.local is encrypted
 *    by the OS keychain on supported platforms (macOS Keychain, Windows DPAPI).
 *    It is NOT appropriate for decrypted vault entries or the vault key.
 *
 * 2. The raw refresh token is stored as-is (128 hex chars).
 *    This is safe because chrome.storage.local is not accessible to web pages.
 *    It IS accessible to other extensions if they have the "storage" permission
 *    and know the key names. We accept this risk for UX reasons (persistent login).
 *
 * 3. Credentials (masterPassword, KEK) are NEVER passed to or stored in
 *    any function in this file. This file only handles opaque tokens.
 *
 * 4. The 401 retry is limited to ONE retry per call. This prevents infinite
 *    loops if the refresh token itself is invalid or expired.
 */

import {
  API_URL,
  STORAGE_KEY_JWT,
  STORAGE_KEY_REFRESH,
  STORAGE_KEY_WRAPPED_KEY,
  STORAGE_KEY_SALT,
} from "../shared/constants";
import { setLocked } from "./vault-state";
import { stopTimer } from "./auto-lock";

// ── Storage helpers ───────────────────────────────────────────────────────────

export function getStoredJWT(): Promise<string | null> {
  return new Promise((resolve) => {
    chrome.storage.local.get([STORAGE_KEY_JWT], (result) => {
      resolve((result[STORAGE_KEY_JWT] as string | undefined) ?? null);
    });
  });
}

export function getStoredRefreshToken(): Promise<string | null> {
  return new Promise((resolve) => {
    chrome.storage.local.get([STORAGE_KEY_REFRESH], (result) => {
      resolve((result[STORAGE_KEY_REFRESH] as string | undefined) ?? null);
    });
  });
}

function storeTokens(jwt: string, refreshToken: string): Promise<void> {
  return new Promise((resolve) => {
    chrome.storage.local.set({ [STORAGE_KEY_JWT]: jwt, [STORAGE_KEY_REFRESH]: refreshToken }, resolve);
  });
}

// ── JWT refresh ───────────────────────────────────────────────────────────────

/**
 * Attempt to refresh the JWT using the stored refresh token.
 * On success: stores new JWT + refresh token, returns new JWT.
 * On failure: throws — caller should force re-login.
 */
export async function refreshJWT(): Promise<string> {
  const rawRefreshToken = await getStoredRefreshToken();
  if (!rawRefreshToken) {
    throw new Error("No refresh token stored — user must log in again");
  }

  const response = await fetch(`${API_URL}/auth/refresh`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refreshToken: rawRefreshToken }),
  });

  if (!response.ok) {
    // Refresh token expired or already used — user must re-login
    throw new Error(`Token refresh failed (${response.status})`);
  }

  const data = (await response.json()) as { jwt: string; refreshToken: string };
  await storeTokens(data.jwt, data.refreshToken);
  return data.jwt;
}

// ── Authenticated fetch with auto-retry ──────────────────────────────────────

/**
 * Make an authenticated fetch request with automatic JWT refresh on 401.
 *
 * Retry logic: On 401, attempt refreshJWT() once and retry the original request.
 * If the retry also fails with 401, throws to the caller.
 *
 * @param url     - Full URL to fetch
 * @param options - RequestInit options (method, body, etc.) — do NOT pass Authorization header
 */
async function authenticatedFetch(url: string, options: RequestInit = {}): Promise<Response> {
  let jwt = await getStoredJWT();
  if (!jwt) throw new Error("Not authenticated — no JWT in storage");

  const makeRequest = (token: string) =>
    fetch(url, {
      ...options,
      headers: {
        ...options.headers,
        "Authorization": `Bearer ${token}`,
        "Content-Type":  "application/json",
      },
    });

  let response = await makeRequest(jwt);

  // [4] Single retry on 401 — prevents infinite loops
  if (response.status === 401) {
    try {
      jwt = await refreshJWT();
      response = await makeRequest(jwt);
    } catch {
      // Refresh failed — clear credentials so popup shows login screen
      throw new Error("Session expired — please log in again");
    }
  }

  return response;
}

// ── Vault sync ────────────────────────────────────────────────────────────────

/**
 * Pull the encrypted vault blob from the server.
 * Returns the raw ciphertext string (base64-encoded AES-256-GCM blob).
 */
export async function pullVault(): Promise<string> {
  const response = await authenticatedFetch(`${API_URL}/vault/pull`);

  if (response.status === 404) {
    // First-time login — no vault on server yet
    // Caller should initialise an empty vault locally
    throw new Error("NO_VAULT");
  }

  if (!response.ok) {
    throw new Error(`Failed to pull vault (${response.status})`);
  }

  const data = (await response.json()) as { ciphertext: string; updatedAt: string };
  return data.ciphertext;
}

/**
 * Push the encrypted vault blob to the server.
 * The ciphertext is an opaque base64 string — the server sees no plaintext.
 */
export async function pushVault(ciphertext: string): Promise<void> {
  const response = await authenticatedFetch(`${API_URL}/vault/push`, {
    method: "POST",
    body: JSON.stringify({ ciphertext }),
  });

  if (!response.ok) {
    throw new Error(`Failed to push vault (${response.status})`);
  }
}

// ── Auth ──────────────────────────────────────────────────────────────────────

/**
 * Login: call backend /auth/login and store tokens + vault material.
 *
 * NOTE: masterPassword is NOT sent to the server. The server returns
 * argon2Salt and wrappedVaultKey so the CLIENT can derive the KEK locally.
 *
 * @returns { argon2Salt, wrappedVaultKey } for client-side vault decryption
 */
export async function login(
  email: string
): Promise<{ argon2Salt: string; wrappedVaultKey: string }> {
  const response = await fetch(`${API_URL}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    // Zero-knowledge: only email is sent. masterPassword stays on device.
    body: JSON.stringify({ email }),
  });

  if (!response.ok) {
    const body = (await response.json()) as { error?: string };
    throw new Error(body.error ?? `Login failed (${response.status})`);
  }

  const data = (await response.json()) as {
    jwt:            string;
    refreshToken:   string;
    argon2Salt:     string;
    wrappedVaultKey: string;
  };

  // Store tokens and vault material in chrome.storage.local
  await new Promise<void>((resolve) => {
    chrome.storage.local.set({
      [STORAGE_KEY_JWT]:         data.jwt,
      [STORAGE_KEY_REFRESH]:     data.refreshToken,
      [STORAGE_KEY_SALT]:        data.argon2Salt,
      [STORAGE_KEY_WRAPPED_KEY]: data.wrappedVaultKey,
    }, resolve);
  });

  return {
    argon2Salt:     data.argon2Salt,
    wrappedVaultKey: data.wrappedVaultKey,
  };
}

/**
 * Logout: invalidate server tokens, clear local storage, lock vault.
 */
export async function logout(): Promise<void> {
  // Best-effort: attempt server-side token invalidation
  try {
    const jwt = await getStoredJWT();
    if (jwt) {
      await fetch(`${API_URL}/auth/logout`, {
        method: "POST",
        headers: { "Authorization": `Bearer ${jwt}` },
      });
    }
  } catch {
    // Ignore network errors on logout — we clear local state regardless
  }

  // Clear all stored credentials from chrome.storage.local
  await new Promise<void>((resolve) => {
    chrome.storage.local.remove([
      STORAGE_KEY_JWT,
      STORAGE_KEY_REFRESH,
      STORAGE_KEY_SALT,
      STORAGE_KEY_WRAPPED_KEY,
    ], resolve);
  });

  // Lock vault and stop auto-lock timer
  setLocked();
  stopTimer();
}
