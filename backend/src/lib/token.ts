/**
 * ═══════════════════════════════════════════════════════════════════
 * src/lib/token.ts — JWT + Refresh Token Utilities
 * ═══════════════════════════════════════════════════════════════════
 *
 * JWT design:
 *   - Algorithm: HS256 (HMAC-SHA256)
 *   - Expiry: 15 minutes — short to limit damage if stolen
 *   - Secret: JWT_SECRET env var, validated at startup to be ≥ 32 chars
 *   - Payload: { userId, deviceId? } — no sensitive data embedded
 *
 * Refresh token design:
 *   - 64 random bytes → 128-char hex string (512 bits of entropy)
 *   - Raw token returned to client once, then NEVER stored
 *   - Only SHA-256 hash stored in DB (tokenHash column)
 *   - Single-use: each rotation marks old token as used
 *
 * NEVER log JWT tokens or refresh tokens — they are bearer credentials.
 * ═══════════════════════════════════════════════════════════════════
 */

import crypto from "crypto";
import jwt, { TokenExpiredError, JsonWebTokenError } from "jsonwebtoken";

export interface JWTPayload {
  userId: string;
  deviceId?: string;
}

// Re-export error types so callers can import them from one place
export { TokenExpiredError, JsonWebTokenError };

/**
 * Sign a JWT access token.
 *
 * @param payload - { userId, deviceId? }
 * @returns Signed JWT string (15-minute expiry)
 * @throws Error if JWT_SECRET is not set
 */
export function signJWT(payload: JWTPayload): string {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    throw new Error("JWT_SECRET environment variable is not configured");
  }
  return jwt.sign(payload, secret, {
    algorithm: "HS256",
    expiresIn: "15m",
  });
}

/**
 * Verify a JWT access token.
 *
 * Does NOT catch errors — callers must handle:
 *   - TokenExpiredError: token is valid but expired
 *   - JsonWebTokenError: invalid signature, malformed, etc.
 *
 * @param token - Raw JWT string from Authorization header
 * @returns Decoded payload { userId, deviceId? }
 * @throws TokenExpiredError | JsonWebTokenError
 */
export function verifyJWT(token: string): JWTPayload {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    throw new Error("JWT_SECRET environment variable is not configured");
  }
  const decoded = jwt.verify(token, secret, { algorithms: ["HS256"] });
  return decoded as JWTPayload;
}

/**
 * Generate a cryptographically secure refresh token.
 *
 * Uses crypto.randomBytes (CSPRNG) — never Math.random().
 * Returns 128-char hex string (64 bytes × 2).
 * This raw token is shown to the client ONCE and never stored.
 *
 * @returns 128-character hex string
 */
export function generateRefreshToken(): string {
  return crypto.randomBytes(64).toString("hex");
}

/**
 * SHA-256 hash a token for safe database storage.
 *
 * Only the hash is ever written to the DB.
 * Comparison: hash the incoming token and compare to stored hash.
 * Even a full DB dump cannot be used to forge sessions.
 *
 * @param token - Raw token string
 * @returns 64-char hex SHA-256 digest
 */
export function hashToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}
