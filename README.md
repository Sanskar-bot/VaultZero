# 🔐 VaultZero

**Zero-knowledge password manager** — your passwords never leave your device unencrypted. VaultZero encrypts everything client-side using Argon2id key derivation and AES-256-GCM before anything touches the network. The server stores only opaque encrypted blobs and can never read, infer, or recover your passwords — even if fully compromised. Available as a Chrome/Firefox extension, Android app (with native Autofill), iOS app (with CredentialProvider), and a web dashboard.

---

## Architecture

```
Master Password (your brain — never stored anywhere)
  └─→ Argon2id(salt) → KEK (Key Encryption Key, 32 bytes)
        └─→ wraps → Vault Key (random 32 bytes, encrypted at rest on server)
              └─→ AES-256-GCM → encrypts each vault entry
                    └─→ encrypted blob sent to server (server sees only this)
```

The server **never** receives, processes, or stores:
- Your master password
- Your KEK (key encryption key)
- Your vault key in usable form
- Any plaintext credentials

## Monorepo Structure

```
VaultZero/
├── core/               # Crypto primitives (Argon2id, AES-256-GCM, key management)
│   └── src/
│       ├── crypto/     # argon2.ts, aes-gcm.ts, keys.ts
│       ├── vault/      # vault types and encrypt/decrypt operations
│       ├── recovery/   # BIP39-style recovery phrase generation
│       └── utils/      # base64/hex/UTF-8 encoding helpers
│
├── backend/            # Node.js + Express + Prisma API server
│   ├── prisma/         # PostgreSQL schema
│   └── src/
│       ├── config/     # environment validation (zod)
│       ├── middleware/  # JWT auth, rate limiting
│       ├── routes/     # /auth, /vault, /audit endpoints
│       ├── services/   # business logic layer
│       └── utils/      # JWT signing/verification
│
├── extension/          # Chrome/Firefox Manifest V3 extension
│   ├── manifest.json
│   └── src/
│       ├── background/ # service worker + vault manager
│       ├── content/    # form detection, autofill, phishing check
│       ├── popup/      # React UI (lock screen, vault list, entry form)
│       └── shared/     # message types, shared interfaces
│
├── web/                # React SPA (Vite) — web vault dashboard
│   └── src/
│       ├── pages/      # login, register, vault, settings, recovery
│       ├── components/ # shared UI components
│       └── styles/     # global CSS
│
└── mobile/
    ├── android/        # Kotlin native — AutofillService + BiometricPrompt
    │   └── app/src/main/kotlin/com/vaultzero/
    │       ├── autofill/   # Android AutofillService
    │       ├── crypto/     # Android Keystore integration
    │       ├── data/       # vault repository
    │       └── ui/         # Jetpack Compose screens
    │
    └── ios/            # Swift native — CredentialProvider + Face ID
        └── VaultZero/VaultZero/
            ├── Crypto/             # Keychain + CryptoKit
            ├── Data/               # vault repository
            └── CredentialProvider/ # iOS AutoFill extension
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Crypto | libsodium-wrappers-sumo + Web Crypto API |
| Backend | Node.js, Express, TypeScript, Prisma, PostgreSQL |
| Extension | React, TypeScript, Manifest V3, esbuild |
| Web UI | React, TypeScript, Vite, React Router |
| Android | Kotlin, Jetpack Compose, Android Keystore |
| iOS | Swift, SwiftUI, CryptoKit, Keychain |
| Hosting | Railway (free tier) |
| Tests | Jest (unit), Postman/Bruno (API) |

## Getting Started

### Prerequisites

- **Node.js** 18+ and npm 9+
- **PostgreSQL** 14+ (local or Railway)
- **Git**

### 1. Clone and install dependencies

```bash
git clone https://github.com/your-username/VaultZero.git
cd VaultZero
npm install
```

This installs dependencies for all workspaces (`core`, `backend`, `extension`, `web`).

### 2. Set up the backend

```bash
# Copy the environment template
cp backend/.env.example backend/.env

# Edit backend/.env — set your DATABASE_URL and generate a JWT_SECRET:
#   node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"

# Generate Prisma client
npm run prisma:generate

# Run database migrations
npm run prisma:migrate
```

### 3. Run each package

```bash
# Core (build the crypto library)
npm run core:build

# Backend (Express API on port 3001)
npm run backend:dev

# Extension (esbuild watch mode — load dist/ as unpacked extension)
npm run extension:dev

# Web UI (Vite dev server on port 5173)
npm run web:dev
```

### 4. Load the browser extension

1. Open Chrome → `chrome://extensions`
2. Enable "Developer mode"
3. Click "Load unpacked" → select the `extension/` directory
4. The VaultZero icon appears in your toolbar

### 5. Run tests

```bash
# All packages
npm test

# Core only
npm run core:test
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/register` | Register (email, wrapped vault key, salt) |
| POST | `/auth/login` | Login → JWT + refresh token + salt + wrapped key |
| POST | `/auth/refresh` | Rotate refresh token |
| POST | `/auth/logout` | Invalidate refresh token |
| GET | `/vault/pull` | Get encrypted vault blob |
| POST | `/vault/push` | Push new encrypted vault blob |
| GET | `/audit/log` | Last 50 audit events |

## Security Model

- 🔒 **Zero-knowledge**: server stores only encrypted blobs
- 🔑 **Argon2id**: memory-hard KDF resistant to GPU/ASIC attacks
- 🛡️ **AES-256-GCM**: authenticated encryption (confidentiality + integrity)
- 🎲 **Fresh IV per encryption**: prevents nonce-reuse attacks
- 🔄 **Key separation**: changing master password only re-wraps the vault key
- 📋 **Recovery phrase**: 24-word BIP39-style, shown once, never stored
- ⏱️ **Auto-lock**: extension clears decrypted vault after 5 min idle
- 🧹 **Memory scrubbing**: overwrites sensitive buffers before GC

## 14-Day Build Plan

| Day | Milestone |
|-----|-----------|
| 1 | ✅ Monorepo scaffold, package configs, Prisma schema |
| 2 | Crypto core: Argon2id, AES-256-GCM, key management |
| 3 | Vault operations, recovery phrase, encoding utils |
| 4 | Backend: Express app, auth routes, JWT, rate limiting |
| 5 | Backend: vault/audit routes, API tests |
| 6 | Web UI: login, register, vault dashboard |
| 7 | Extension: popup UI, lock screen, vault list |
| 8 | Extension: service worker, vault manager, autofill |
| 9 | Extension: content script, form detection, phishing check |
| 10 | Android: Kotlin app, Keystore, BiometricPrompt |
| 11 | Android: AutofillService integration |
| 12 | iOS: Swift app, Keychain, Face ID |
| 13 | iOS: CredentialProvider extension |
| 14 | Integration testing, security audit, deployment |

## License

MIT
