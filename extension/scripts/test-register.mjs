/**
 * scripts/test-register.mjs
 *
 * End-to-end helper script for local development testing.
 * Runs outside the extension — directly in Node.js.
 *
 * What it does:
 *   1. Generates an Argon2id salt
 *   2. Derives a KEK from your master password
 *   3. Generates a vault key
 *   4. Wraps the vault key with the KEK
 *   5. Calls POST /auth/register → creates your account
 *   6. Calls POST /auth/login   → gets JWT + refresh token
 *   7. Prints chrome.storage.local values to inject via DevTools
 *
 * Usage:
 *   node scripts/test-register.mjs <email> <masterPassword>
 *
 * Example:
 *   node scripts/test-register.mjs alice@test.dev MySecretPass123!
 */

import { createRequire } from "module";
import { webcrypto }     from "crypto";

const require = createRequire(import.meta.url);
// Use the workspace-level libsodium install
const sodium  = require("libsodium-wrappers-sumo");

const [email, masterPassword] = process.argv.slice(2);

if (!email || !masterPassword) {
  console.error("Usage: node scripts/test-register.mjs <email> <masterPassword>");
  process.exit(1);
}

const API_URL = process.env.API_URL || "http://localhost:3000";

// ── Crypto helpers (matches @vaultzero/core exactly) ─────────────────────────

const ARGON2_MEMORY  = 65536 * 1024; // 64 MiB in bytes
const ARGON2_ITERS   = 3;
const SALT_LENGTH    = 16;
const KEY_LENGTH     = 32;

function toBase64(bytes) {
  return Buffer.from(bytes).toString("base64");
}
function fromBase64(str) {
  return new Uint8Array(Buffer.from(str, "base64"));
}

await sodium.ready;
console.log("✓ libsodium ready");

// 1. Generate Argon2id salt (16 bytes)
const salt = sodium.randombytes_buf(SALT_LENGTH);
const saltB64 = toBase64(salt);
console.log("✓ Salt generated:", saltB64);

// 2. Derive KEK via Argon2id
console.log("⏳ Deriving KEK via Argon2id (64 MiB × 3 iterations — takes ~1 second)…");
const kek = sodium.crypto_pwhash(
  KEY_LENGTH, masterPassword, salt,
  ARGON2_ITERS, ARGON2_MEMORY,
  sodium.crypto_pwhash_ALG_ARGON2ID13
);
console.log("✓ KEK derived (32 bytes)");

// 3. Generate vault key (random 32 bytes)
const vaultKey = webcrypto.getRandomValues(new Uint8Array(KEY_LENGTH));
console.log("✓ Vault key generated");

// 4. Wrap vault key with KEK using AES-256-GCM
const iv = webcrypto.getRandomValues(new Uint8Array(12));
const kekCryptoKey = await webcrypto.subtle.importKey(
  "raw", kek, { name: "AES-GCM" }, false, ["encrypt"]
);
const vaultKeyB64  = toBase64(vaultKey);
const enc          = new TextEncoder();
const cipherBytes  = await webcrypto.subtle.encrypt(
  { name: "AES-GCM", iv },
  kekCryptoKey,
  enc.encode(vaultKeyB64)
);

// Packed format: base64(IV + ciphertext)
const packed = new Uint8Array(iv.byteLength + cipherBytes.byteLength);
packed.set(iv, 0);
packed.set(new Uint8Array(cipherBytes), iv.byteLength);
const wrappedVaultKey = toBase64(packed);
console.log("✓ Vault key wrapped with KEK");

// 5. Register
console.log(`\n📡 Registering ${email} at ${API_URL}…`);
const regRes = await fetch(`${API_URL}/auth/register`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ email, wrappedVaultKey, argon2Salt: saltB64 }),
});

if (!regRes.ok) {
  const body = await regRes.json();
  if (regRes.status === 409) {
    console.log("⚠️  Email already registered — skipping registration, proceeding to login…");
  } else {
    console.error("❌ Registration failed:", body);
    process.exit(1);
  }
} else {
  const { userId } = await regRes.json();
  console.log("✓ Registered! userId:", userId);
}

// 6. Login
console.log(`\n📡 Logging in…`);
const loginRes = await fetch(`${API_URL}/auth/login`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ email }),
});

if (!loginRes.ok) {
  console.error("❌ Login failed:", await loginRes.json());
  process.exit(1);
}

const loginData = await loginRes.json();
console.log("✓ Logged in! JWT expires in 15 minutes.");

// 7. Print chrome.storage.local values
console.log(`
${"═".repeat(65)}
STEP: Inject these values into the extension via DevTools
${"═".repeat(65)}

1. Go to chrome://extensions
2. Click "Service worker" link next to VaultZero → Opens DevTools
3. Paste this into the Console:

chrome.storage.local.set({
  "vz_jwt":     "${loginData.jwt}",
  "vz_refresh": "${loginData.refreshToken}",
  "vz_salt":    "${loginData.argon2Salt}",
  "vz_wk":      "${loginData.wrappedVaultKey}"
}, () => console.log("✅ Storage set! Now open the popup and unlock with: ${masterPassword}"));

${"═".repeat(65)}
After injecting: open the VaultZero popup and type your master password.
Master password: ${masterPassword}
${"═".repeat(65)}
`);
