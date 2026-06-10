# VaultZero — Days 2, 3 & 4 Summary

**Date**: June 10, 2026
**Goal**: Implement the complete crypto core, vault operations, and backend API.

---

## What Was Done

### Day 2 — Crypto Core (`/core/src/crypto/`)

| File | Purpose |
|------|---------|
| `crypto/argon2.ts` | `deriveKEK()` — Argon2id (64 MiB, 3 iter) master password → KEK |
| `crypto/aes-gcm.ts` | `encryptData()` / `decryptData()` — AES-256-GCM with fresh IV per call |
| `crypto/keys.ts` | `generateVaultKey()`, `wrapVaultKey()`, `unwrapVaultKey()` |
| `crypto/generator.ts` | `generatePassword()`, `calculateEntropy()`, `checkBreach()` (HIBP k-anonymity) |

### Day 3 — Vault Model + Recovery (`/core/src/`)

| File | Purpose |
|------|---------|
| `vault/types.ts` | `VaultEntry`, `VaultStore`, `EncryptedVault` interfaces |
| `vault/vault.ts` | `createVault`, `addEntry`, `updateEntry`, `deleteEntry`, `searchEntries`, `getEntriesForUrl`, `encryptVault`, `decryptVault` |
| `recovery/bip39.ts` | `generateRecoveryPhrase()`, `hashRecoveryPhrase()`, `deriveRecoveryKEK()`, `validateRecoveryPhrase()` |
| `recovery/wordlist.ts` | Full 2048-word BIP39 English wordlist with integrity check |

**Bug fixed**: Wordlist was truncated to 1923 words — replaced with complete canonical BIP39 list downloaded from `bitcoin/bips`.

### Day 4 — Backend API (`/backend/src/`)

| File | Purpose |
|------|---------|
| `config/index.ts` | `PrismaClient` singleton + `requireEnv()` / `optionalEnv()` helpers |
| `middleware/auth.ts` | `verifyJWT` — reads `Authorization: Bearer`, attaches `req.user` |
| `middleware/rate-limit.ts` | `authLimiter` (5/15min on login) + `standardLimiter` (100/15min global) |
| `services/auth.service.ts` | `register`, `login`, `refresh`, `logout` — refresh tokens stored as SHA-256 hashes |
| `services/vault.service.ts` | `pullVault`, `pushVault` — server treats ciphertext as opaque blob |
| `services/audit.service.ts` | `logAuditEvent` (fire-and-forget), `getAuditLog` |
| `routes/auth.ts` | POST `/auth/register`, `/auth/login`, `/auth/refresh`, `/auth/logout` |
| `routes/vault.ts` | GET `/vault/pull`, POST `/vault/push` |
| `routes/audit.ts` | GET `/audit/log` |
| `app.ts` | Express factory — helmet, CORS, JSON body parsing, rate limiting, routes, global error handler |
| `src/index.ts` | Server entry — dotenv, env validation, Prisma connect, graceful shutdown |

---

## Test Results

```
PASS src/__tests__/crypto.test.ts
  AES-256-GCM Encryption         ✓ 3 tests
  Vault Key Wrapping              ✓ 2 tests
  Password Generator              ✓ 2 tests
  Entropy Calculator              ✓ 1 test
  Vault Serialization             ✓ 4 tests
  Recovery Phrase Generation      ✓ 3 tests
  Recovery Phrase Hashing         ✓ 3 tests
  Recovery KEK Derivation         ✓ 3 tests
  Recovery Phrase Validation      ✓ 4 tests

Tests: 25 passed, 25 total ✅
TypeScript (core):    0 errors ✅
TypeScript (backend): 0 errors ✅
```

---

## Commands

### Install & Generate

```bash
# From repo root — install all workspace dependencies
npm install

# Generate Prisma client (must run after any schema change)
cd backend && npx prisma generate
```

### Database Migration

```bash
# Copy and fill in backend/.env first!
cp backend/.env.example backend/.env
# Edit backend/.env — set DATABASE_URL, JWT_SECRET

# Run migrations (creates tables in your PostgreSQL database)
cd backend && npx prisma migrate dev --name init

# Inspect database via Prisma Studio (visual UI)
cd backend && npx prisma studio
```

### Start the Backend

```bash
# Dev server with hot reload (tsx watch)
cd backend && npm run dev

# Or from root
npm run backend:dev
```

### Run Tests

```bash
# Core crypto tests (25 tests)
cd core && npm test

# Or from root
npm run core:test
```

---

## API Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/health` | None | Server health check |
| POST | `/auth/register` | None | Register with email + wrapped vault key + salt |
| POST | `/auth/login` | None | Login → JWT + refresh token + vault material |
| POST | `/auth/refresh` | None | Rotate refresh token |
| POST | `/auth/logout` | JWT | Invalidate all refresh tokens |
| GET | `/vault/pull` | JWT | Get encrypted vault blob |
| POST | `/vault/push` | JWT | Store encrypted vault blob |
| GET | `/audit/log` | JWT | Last 50 security events |

---

## Verifying Zero Plaintext Passwords in the Database

After registering a user, run these queries in Prisma Studio or psql to confirm no plaintext data is stored:

```sql
-- 1. View the users table — confirm NO password column exists
SELECT column_name, data_type
FROM information_schema.columns
WHERE table_name = 'users';
-- Expected columns: id, email, argon2_salt, wrapped_vault_key, recovery_phrase_hash, created_at
-- ✅ No 'password', 'master_password', or 'kek' column

-- 2. Inspect a registered user's data
SELECT id, email, argon2_salt, wrapped_vault_key FROM users LIMIT 1;
-- argon2_salt:      should be a base64 string (e.g. "dGVzdC1zYWx0...")
-- wrapped_vault_key: should be a base64 string (AES-256-GCM ciphertext)
-- ✅ Neither field is a human-readable password

-- 3. Inspect refresh tokens — confirm only hashes are stored
SELECT id, token_hash, expires_at, used FROM refresh_tokens LIMIT 5;
-- token_hash: 64-char hex (SHA-256) — not the raw token
-- ✅ Raw refresh tokens are never persisted

-- 4. Inspect vault blobs — confirm ciphertext is opaque
SELECT id, user_id, LENGTH(ciphertext) AS ciphertext_bytes, updated_at FROM vault_blobs LIMIT 5;
-- ciphertext: base64-encoded AES-256-GCM blob — not JSON, not readable
-- ✅ Server cannot decrypt this without the vault key
```

---

## Security Notes

> **⚠️ SECURITY NOTE**: `POST /auth/login` returns a 404 when the email is not registered.
> In production, this should return a generic 401 "Invalid credentials" to prevent email enumeration.
> The dev-friendly 404 is intentional here for easier debugging.

> **⚠️ SECURITY NOTE**: Rate limiter uses in-memory store (default express-rate-limit).
> For multi-instance deployments (Railway with 2+ replicas), upgrade to `rate-limit-redis`
> to share the rate limit state across instances.

---

## Postman / Bruno Collection

Import `backend/vaultzero.postman_collection.json` into Postman.

**Run order**: Register → Login → Push Vault → Pull Vault → Audit Log → Refresh → Logout

Collection variables `jwt` and `refreshToken` are automatically captured from the Login response and used in subsequent requests.

---

## 14-Day Roadmap

| Day | Milestone | Status |
|-----|-----------|--------|
| **1** | Monorepo scaffold, configs, Prisma schema, README | ✅ DONE |
| **2** | Crypto core: Argon2id, AES-256-GCM, key management | ✅ DONE |
| **3** | Vault operations, recovery phrase, encoding utils | ✅ DONE |
| **4** | Backend: Express app, auth routes, JWT, rate limiting | ✅ DONE |
| 5 | Backend: integration tests, vault conflict resolution | ⬜ |
| 6 | Web UI: login, register, vault dashboard | ⬜ |
| 7 | Extension: popup UI, lock screen, vault list | ⬜ |
| 8 | Extension: service worker, vault manager, autofill | ⬜ |
| 9 | Extension: content script, form detection, phishing | ⬜ |
| 10 | Android: Kotlin app, Keystore, BiometricPrompt | ⬜ |
| 11 | Android: AutofillService integration | ⬜ |
| 12 | iOS: Swift app, Keychain, Face ID | ⬜ |
| 13 | iOS: CredentialProvider extension | ⬜ |
| 14 | Integration testing, security audit, deployment | ⬜ |
