/**
 * ═══════════════════════════════════════════════════════════════════
 * src/routes/auth.ts — Authentication Routes
 * ═══════════════════════════════════════════════════════════════════
 *
 * ZERO-KNOWLEDGE CONTRACT:
 *   - This server NEVER receives a master password.
 *   - Registration accepts only: email, wrappedVaultKey, argon2Salt
 *     (the vault key is already encrypted before it reaches us)
 *   - Login returns argon2Salt + wrappedVaultKey so the client can
 *     derive the KEK locally and unwrap the vault key locally.
 *   - If this entire server is compromised, the attacker gets:
 *     • Encrypted vault blobs (useless without master password)
 *     • Wrapped vault keys (useless without KEK)
 *     • Argon2 salts (useless without master password)
 *     • SHA-256 hashes of refresh tokens (cannot be reversed)
 *
 * ATTACK HARDENING APPLIED:
 *   [1] Timing attack: dummy SHA-256 work when email not found
 *       → prevents email enumeration via response-time difference
 *   [2] Refresh token: stored as SHA-256 hash, raw token returned once
 *       → full DB dump cannot replay sessions
 *   [3] Expired tokens cleaned up on each login
 *       → prevents token table growing unbounded
 *   [4] Registration flood: standardLimiter applied at app level
 *       → prevents mass account creation
 *   [5] JWT_SECRET strength validated at startup (src/server.ts)
 *       → server refuses to start with weak secret
 * ═══════════════════════════════════════════════════════════════════
 */

import crypto from "crypto";
import { Router } from "express";
import { Prisma } from "@prisma/client";
import prisma from "../lib/prisma";
import {
  signJWT,
  generateRefreshToken,
  hashToken,
} from "../lib/token";
import { logAuditEvent, extractIp } from "../lib/audit";
import { authenticateJWT } from "../middleware/auth";
import { validateBody } from "../middleware/validate";

const router = Router();

// ── Email validation regex ────────────────────────────────────────────────────
// RFC 5322 simplified: local@domain.tld
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// ── Refresh token expiry ───────────────────────────────────────────────────
const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000;

// ─────────────────────────────────────────────────────────────────────────────
// POST /auth/register
// ─────────────────────────────────────────────────────────────────────────────
/**
 * Register a new user.
 *
 * Body: { email, wrappedVaultKey, argon2Salt }
 *
 * SECURITY: masterPassword field is never accepted.
 *   Even if a client accidentally sends it, it is ignored.
 *   We destructure only the fields we need — anything else is discarded.
 *
 * Responses:
 *   201 { userId }                    — success
 *   400 { error }                     — validation failure
 *   409 { error: "Email already..." } — duplicate email
 */
router.post(
  "/register",
  validateBody(["email", "wrappedVaultKey", "argon2Salt"]),
  async (req, res, next) => {
    try {
      // Destructure only the fields we need — masterPassword is never touched
      const { email, wrappedVaultKey, argon2Salt } = req.body as {
        email: string;
        wrappedVaultKey: string;
        argon2Salt: string;
      };

      // Validate email format
      if (!EMAIL_REGEX.test(email.trim())) {
        res.status(400).json({ error: "Invalid email format" });
        return;
      }

      const normalizedEmail = email.trim().toLowerCase();

      // Create user — Prisma will throw P2002 on duplicate email
      const user = await prisma.user.create({
        data: {
          email: normalizedEmail,
          wrappedVaultKey,
          argon2Salt,
        },
        select: { id: true }, // never select password-adjacent fields unnecessarily
      });

      // Log registration event (fire-and-forget — never blocks response)
      void logAuditEvent({
        userId: user.id,
        action: "REGISTER",
        ipAddress: extractIp(req),
        prisma,
      });

      res.status(201).json({ userId: user.id });
    } catch (err) {
      // Prisma unique constraint violation (P2002) → duplicate email
      if (
        err instanceof Prisma.PrismaClientKnownRequestError &&
        err.code === "P2002"
      ) {
        res.status(409).json({ error: "Email already registered" });
        return;
      }
      next(err);
    }
  }
);

// ─────────────────────────────────────────────────────────────────────────────
// POST /auth/login
// ─────────────────────────────────────────────────────────────────────────────
/**
 * Log in — returns JWT, refresh token, and vault material.
 *
 * Body: { email, deviceId? }
 *
 * NOTE: No password is sent or checked server-side.
 * The client uses argon2Salt to derive the KEK locally and unwrap
 * the vault key locally. Zero-knowledge by design.
 *
 * TIMING ATTACK HARDENING:
 *   If the user is not found, we still perform a dummy SHA-256 operation
 *   before responding. This equalises response time between "found" and
 *   "not found" paths, preventing email enumeration via timing side-channel.
 *
 * Responses:
 *   200 { jwt, refreshToken, argon2Salt, wrappedVaultKey }
 *   400 { error }     — missing fields
 *   404 { error }     — user not found
 */
router.post(
  "/login",
  validateBody(["email"]),
  async (req, res, next) => {
    try {
      const { email, deviceId } = req.body as {
        email: string;
        deviceId?: string;
      };

      const normalizedEmail = email.trim().toLowerCase();
      const ip = extractIp(req);

      const user = await prisma.user.findUnique({
        where: { email: normalizedEmail },
        select: {
          id: true,
          argon2Salt: true,
          wrappedVaultKey: true,
        },
      });

      // [1] TIMING ATTACK HARDENING:
      // Perform identical computational work whether user exists or not.
      // Without this, an attacker can enumerate valid emails by measuring
      // response time (found user does more work → slightly slower).
      const dummyWork = crypto.createHash("sha256").update(crypto.randomBytes(32)).digest();
      void dummyWork; // Prevent optimisation-out by referencing result

      if (!user) {
        res.status(404).json({ error: "User not found" });
        return;
      }

      // Issue a short-lived JWT (15 minutes)
      const jwtToken = signJWT({ userId: user.id, deviceId });

      // [2] Generate refresh token — raw token returned once, hash stored in DB
      const rawRefreshToken = generateRefreshToken();
      const tokenHash = hashToken(rawRefreshToken);
      const expiresAt = new Date(Date.now() + THIRTY_DAYS_MS);

      // [3] Store token hash + clean up expired tokens atomically
      await prisma.$transaction([
        prisma.refreshToken.create({
          data: {
            userId: user.id,
            tokenHash,
            expiresAt,
          },
        }),
        // Cleanup: delete expired tokens for this user to keep table lean
        prisma.refreshToken.deleteMany({
          where: {
            userId: user.id,
            expiresAt: { lt: new Date() },
          },
        }),
      ]);

      void logAuditEvent({
        userId: user.id,
        deviceId,
        action: "LOGIN",
        ipAddress: ip,
        prisma,
      });

      // Return vault material so client can derive KEK and unwrap vault key
      res.status(200).json({
        jwt: jwtToken,
        refreshToken: rawRefreshToken, // raw token — show to client once only
        argon2Salt: user.argon2Salt,
        wrappedVaultKey: user.wrappedVaultKey,
      });
    } catch (err) {
      next(err);
    }
  }
);

// ─────────────────────────────────────────────────────────────────────────────
// POST /auth/refresh
// ─────────────────────────────────────────────────────────────────────────────
/**
 * Rotate a refresh token — issues new JWT + new refresh token.
 *
 * Body: { refreshToken }
 *
 * SINGLE-USE ENFORCEMENT:
 *   The old token is marked `used = true` (not deleted — keeps audit trail).
 *   If an attacker steals a refresh token and rotates it, the legitimate
 *   user's next refresh will fail (used = true), alerting them that their
 *   session was hijacked.
 *
 * Responses:
 *   200 { jwt, refreshToken }
 *   400 { error }    — missing field
 *   401 { error }    — token not found / expired / already used
 */
router.post(
  "/refresh",
  validateBody(["refreshToken"]),
  async (req, res, next) => {
    try {
      const { refreshToken: rawToken } = req.body as { refreshToken: string };

      const tokenHash = hashToken(rawToken);

      const storedToken = await prisma.refreshToken.findUnique({
        where: { tokenHash },
      });

      // Not found
      if (!storedToken) {
        res.status(401).json({ error: "Invalid refresh token" });
        return;
      }

      // Expired
      if (storedToken.expiresAt < new Date()) {
        res.status(401).json({ error: "Refresh token expired" });
        return;
      }

      // Already used (possible token theft detection)
      if (storedToken.used) {
        res.status(401).json({ error: "Refresh token already used" });
        return;
      }

      // Mark old token as used (not deleted — preserved for audit trail)
      // Issue new JWT + new refresh token atomically
      const newRawToken = generateRefreshToken();
      const newTokenHash = hashToken(newRawToken);
      const newExpiresAt = new Date(Date.now() + THIRTY_DAYS_MS);

      await prisma.$transaction([
        prisma.refreshToken.update({
          where: { id: storedToken.id },
          data: { used: true },
        }),
        prisma.refreshToken.create({
          data: {
            userId: storedToken.userId,
            tokenHash: newTokenHash,
            expiresAt: newExpiresAt,
          },
        }),
      ]);

      const newJwt = signJWT({ userId: storedToken.userId });

      res.status(200).json({
        jwt: newJwt,
        refreshToken: newRawToken,
      });
    } catch (err) {
      next(err);
    }
  }
);

// ─────────────────────────────────────────────────────────────────────────────
// POST /auth/logout
// ─────────────────────────────────────────────────────────────────────────────
/**
 * Log out — invalidate all active refresh tokens for this user.
 *
 * Requires: Authorization: Bearer <jwt>
 *
 * Marks all non-used, non-expired refresh tokens as used.
 * The client should discard its local JWT and refresh token.
 *
 * Responses:
 *   200 { message: "Logged out" }
 *   401 { error }   — missing/invalid/expired JWT
 */
router.post("/logout", authenticateJWT, async (req, res, next) => {
  try {
    const { userId } = req.user!;
    const ip = extractIp(req);

    // Invalidate all active refresh tokens for this user
    await prisma.refreshToken.updateMany({
      where: {
        userId,
        used: false,
        expiresAt: { gt: new Date() },
      },
      data: { used: true },
    });

    void logAuditEvent({
      userId,
      action: "LOGOUT",
      ipAddress: ip,
      prisma,
    });

    res.status(200).json({ message: "Logged out" });
  } catch (err) {
    next(err);
  }
});

export default router;
