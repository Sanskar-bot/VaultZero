/**
 * Auth Routes
 *
 * POST /auth/register  → { email, wrapped_vault_key, argon2_salt }
 * POST /auth/login     → { jwt, refresh_token, argon2_salt, wrapped_vault_key }
 * POST /auth/refresh   → rotate refresh token, return new jwt
 * POST /auth/logout    → invalidate refresh token
 *
 * SECURITY: The server NEVER receives the master password or KEK.
 * Registration only stores the pre-encrypted wrapped_vault_key and salt.
 *
 * Implementation: Day 4-5
 */

// TODO: Day 4-5 — implement auth routes
