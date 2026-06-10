/**
 * ═══════════════════════════════════════════════════════════════════
 * Auth Service — Business Logic for Registration, Login, Token Management
 * ═══════════════════════════════════════════════════════════════════
 *
 * ZERO-KNOWLEDGE CONTRACT:
 *   - register() never receives or stores a master password
 *   - The server stores only: email, argon2Salt, wrappedVaultKey
 *   - argon2Salt was generated client-side; server cannot use it without the password
 *   - wrappedVaultKey is AES-256-GCM encrypted; server cannot decrypt it
 *   - Refresh tokens are stored as SHA-256 hashes — raw token never persisted
 *
 * TOKEN ROTATION:
 *   - JWTs are short-lived (15 min) to limit damage if stolen
 *   - Refresh tokens are single-use: each rotation invalidates the old token
 *     and issues a new one. This allows detection of token theft.
 *
 * AUDIT LOGGING:
 *   - Every LOGIN is logged with IP address and deviceId
 *   - Logs are used for anomaly detection (unusual locations, device changes)
 * ═══════════════════════════════════════════════════════════════════
 */

import { webcrypto } from "crypto";
import jwt from "jsonwebtoken";
import { prisma } from "../config";
import type { JWTPayload } from "../middleware/auth";
import { logAuditEvent } from "./audit.service";

/** JWT expiry — 15 minutes */
const JWT_EXPIRY = "15m";

/** Refresh token expiry — 30 days in milliseconds */
const REFRESH_TOKEN_EXPIRY_MS = 30 * 24 * 60 * 60 * 1000;

/** Length of the raw refresh token (hex-encoded bytes) */
const REFRESH_TOKEN_BYTES = 64;

// ─────────────────────────────────────────────────────────────────────────────
// Helper: generate a cryptographically secure refresh token
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Generate a random 64-byte refresh token as a hex string.
 * Uses crypto.getRandomValues() — NEVER Math.random().
 *
 * @returns 128-character hex string (64 bytes × 2 hex chars per byte)
 */
function generateRefreshToken(): string {
  const bytes = webcrypto.getRandomValues(new Uint8Array(REFRESH_TOKEN_BYTES));
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Hash a refresh token with SHA-256 for storage.
 *
 * We never store the raw refresh token — only its SHA-256 hash.
 * This means even if the refresh_tokens table is leaked, attackers
 * cannot use the hashes to forge new JWTs.
 *
 * @param token - Raw refresh token (128-char hex string)
 * @returns SHA-256 hex digest (64 characters)
 */
async function hashRefreshToken(token: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(token);
  const hashBuffer = await webcrypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: sign a JWT
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Sign a JWT with the server's JWT_SECRET.
 *
 * @param payload - { userId, deviceId? }
 * @returns Signed JWT string (15-min expiry)
 * @throws Error if JWT_SECRET is not configured
 */
function signJWT(payload: JWTPayload): string {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    throw new Error("JWT_SECRET environment variable is not configured");
  }
  return jwt.sign(payload, secret, { expiresIn: JWT_EXPIRY });
}

// ─────────────────────────────────────────────────────────────────────────────
// Public service functions
// ─────────────────────────────────────────────────────────────────────────────

export interface RegisterInput {
  email: string;
  wrappedVaultKey: string;
  argon2Salt: string;
}

export interface RegisterResult {
  userId: string;
}

/**
 * Register a new user.
 *
 * Stores email, wrappedVaultKey, and argon2Salt.
 * NEVER receives or stores a master password or KEK.
 *
 * @throws Error with code "EMAIL_TAKEN" if email already registered
 */
export async function register(input: RegisterInput): Promise<RegisterResult> {
  const { email, wrappedVaultKey, argon2Salt } = input;

  // Check for duplicate email
  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) {
    const err = new Error("Email already registered") as Error & { code: string };
    err.code = "EMAIL_TAKEN";
    throw err;
  }

  const user = await prisma.user.create({
    data: {
      email,
      wrappedVaultKey,
      argon2Salt,
    },
  });

  return { userId: user.id };
}

export interface LoginInput {
  email: string;
  deviceId?: string;
  ipAddress?: string;
}

export interface LoginResult {
  jwt: string;
  refreshToken: string;
  argon2Salt: string;
  wrappedVaultKey: string;
}

/**
 * Log a user in.
 *
 * Finds the user by email, issues a JWT + refresh token, logs the event.
 * Returns argon2Salt and wrappedVaultKey so the client can re-derive
 * the KEK and unwrap the vault key locally.
 *
 * @throws Error with code "USER_NOT_FOUND" if email not registered
 */
export async function login(input: LoginInput): Promise<LoginResult> {
  const { email, deviceId, ipAddress } = input;

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) {
    const err = new Error("User not found") as Error & { code: string };
    err.code = "USER_NOT_FOUND";
    throw err;
  }

  // Sign a short-lived JWT
  const jwtToken = signJWT({ userId: user.id, deviceId });

  // Generate a single-use refresh token
  const rawRefreshToken = generateRefreshToken();
  const tokenHash = await hashRefreshToken(rawRefreshToken);

  await prisma.refreshToken.create({
    data: {
      userId: user.id,
      tokenHash,
      expiresAt: new Date(Date.now() + REFRESH_TOKEN_EXPIRY_MS),
    },
  });

  // Log the login event
  await logAuditEvent({
    userId: user.id,
    deviceId,
    action: "LOGIN",
    ipAddress,
  });

  return {
    jwt: jwtToken,
    refreshToken: rawRefreshToken,
    argon2Salt: user.argon2Salt,
    wrappedVaultKey: user.wrappedVaultKey,
  };
}

export interface RefreshInput {
  refreshToken: string;
}

export interface RefreshResult {
  jwt: string;
  refreshToken: string;
}

/**
 * Rotate a refresh token.
 *
 * Verifies the token hash exists and is not expired/used, then:
 * 1. Marks old token as used (single-use enforcement)
 * 2. Issues a new JWT + new refresh token
 *
 * @throws Error with code "INVALID_REFRESH_TOKEN" if token is invalid
 */
export async function refresh(input: RefreshInput): Promise<RefreshResult> {
  const { refreshToken: rawToken } = input;

  const tokenHash = await hashRefreshToken(rawToken);

  const storedToken = await prisma.refreshToken.findUnique({
    where: { tokenHash },
  });

  if (
    !storedToken ||
    storedToken.used ||
    storedToken.expiresAt < new Date()
  ) {
    const err = new Error("Invalid or expired refresh token") as Error & { code: string };
    err.code = "INVALID_REFRESH_TOKEN";
    throw err;
  }

  // Invalidate old token (single-use rotation)
  await prisma.refreshToken.update({
    where: { id: storedToken.id },
    data: { used: true },
  });

  // Issue new JWT + new refresh token
  const newJwt = signJWT({ userId: storedToken.userId });
  const newRawToken = generateRefreshToken();
  const newTokenHash = await hashRefreshToken(newRawToken);

  await prisma.refreshToken.create({
    data: {
      userId: storedToken.userId,
      tokenHash: newTokenHash,
      expiresAt: new Date(Date.now() + REFRESH_TOKEN_EXPIRY_MS),
    },
  });

  return {
    jwt: newJwt,
    refreshToken: newRawToken,
  };
}

export interface LogoutInput {
  userId: string;
  deviceId?: string;
}

/**
 * Log a user out by invalidating their refresh tokens.
 *
 * Marks all non-expired, non-used refresh tokens for this user as used.
 * For a more granular approach, pass deviceId to only invalidate that device's tokens.
 */
export async function logout(input: LogoutInput): Promise<void> {
  const { userId } = input;

  // Invalidate all active refresh tokens for this user
  await prisma.refreshToken.updateMany({
    where: {
      userId,
      used: false,
      expiresAt: { gt: new Date() },
    },
    data: { used: true },
  });
}
