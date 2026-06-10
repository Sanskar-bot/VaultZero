# VaultZero Security Policy

## Zero-Knowledge Architecture

VaultZero is a zero-knowledge password manager. The server operates under the following strict guarantee:

> **The server never has access to plaintext vault contents, master passwords, or vault keys.**

### What the server stores

| Field | Description | Can server decrypt? |
|-------|-------------|-------------------|
| `email` | Plaintext (needed for login lookup) | N/A |
| `argon2Salt` | Random salt for client-side KEK derivation | No — useless without master password |
| `wrappedVaultKey` | Vault key encrypted with KEK (AES-256-GCM) | No — KEK never reaches server |
| `wrappedVaultKeyForRecovery` | Vault key encrypted with recovery KEK | No — recovery phrase never stored |
| `recoveryHash` | SHA-256 of recovery phrase | No — hash is one-way |
| `VaultBlob.ciphertext` | AES-256-GCM encrypted vault blob | No — vault key never on server |
| `RefreshToken.tokenHash` | SHA-256 of raw refresh token | No — raw token shown once only |

### What the server cannot do even if fully compromised

- Decrypt any vault blob (no vault key)
- Recover a master password (never transmitted)
- Forge a refresh token (hash only; 64 bytes of entropy in raw token)
- Recover a BIP39 recovery phrase (SHA-256 is one-way)
- Impersonate a user without their refresh token or JWT (short-lived: 15 min)

---

## Security Controls

### Authentication
- JWT: HS256, 15-minute expiry, secret ≥ 32 characters (server refuses to start otherwise)
- Refresh tokens: 64 bytes CSPRNG, stored as SHA-256 hash only, single-use with rotation
- Rate limiting: 5 attempts/15 min on login/register; 3 attempts/hour on recovery verify

### Attack Mitigations

| Attack | Mitigation |
|--------|-----------|
| Email enumeration via timing | Dummy SHA-256 work when user not found in `POST /auth/login` |
| Brute-force login | `authLimiter`: 5 req/15 min per IP |
| Recovery phrase brute-force | `recoveryLimiter`: 3 req/hr per IP + constant-time compare |
| Session fixation | Refresh token rotation on every use; `used = true` on logout |
| Stolen refresh token detection | Single-use tokens: second use of rotated-away token → 401 |
| Storage exhaustion | Vault capped at 2MB; body parser capped at 2.5MB |
| Information leakage | Global error handler never sends `error.message` or stack traces |
| Clickjacking | `X-Frame-Options: DENY` via Helmet |
| MIME sniffing | `X-Content-Type-Options: nosniff` via Helmet |
| Cross-site request forgery | CORS locked to `ALLOWED_ORIGIN` env var; never wildcard `*` |
| Audit trail bypass | All security events logged; failures logged same as successes |

### Transport Security
- HTTPS enforced via Railway (TLS termination at proxy)
- `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` (2 years)
- `Content-Security-Policy: default-src 'none'` (API serves no HTML)

---

## Responsible Disclosure

If you discover a security vulnerability in VaultZero, please report it privately:

1. **Do not** open a public GitHub issue for security vulnerabilities
2. Email: `security@vaultzero.dev` (or open a private GitHub Security Advisory)
3. Include: description, reproduction steps, potential impact, and suggested fix
4. We will acknowledge within 48 hours and aim to patch within 14 days
5. We will credit you in the release notes (unless you prefer anonymity)

### Scope

**In scope:**
- Authentication bypass
- Zero-knowledge violations (server gaining access to plaintext data)
- Privilege escalation (user A accessing user B's vault)
- Cryptographic implementation flaws
- Rate limit bypass
- Audit log tampering

**Out of scope:**
- Attacks requiring physical access to the user's device
- Social engineering attacks against users
- Denial-of-service via legitimate traffic volume
- Issues in third-party dependencies (report to them directly)

---

## Known Limitations

1. **Single-instance rate limiting**: The in-memory rate limiter is per-process. Multi-replica Railway deployments require a Redis-backed store (e.g. `rate-limit-redis`).
2. **Last-write-wins sync**: Vault conflict resolution is not automatic. Clients should check `updatedAt` timestamps before pushing.
3. **No E2E device sync**: Device public keys are stored but device-to-device encryption is not yet implemented.
4. **IP address storage**: Audit logs store raw IP addresses (PII). In GDPR-regulated deployments, consider hashing IPs with a daily rotating key or storing only the `/24` subnet.
