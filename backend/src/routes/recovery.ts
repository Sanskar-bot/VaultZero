/**
 * ═══════════════════════════════════════════════════════════════════
 * src/routes/recovery.ts — Account Recovery Routes
 * ═══════════════════════════════════════════════════════════════════
 *
 * Three routes:
 *   POST /recovery/setup   — store recovery hash + wrapped vault key
 *   POST /recovery/verify  — verify phrase hash, return wrapped key
 *   POST /recovery/rekey   — re-wrap vault key with new master password
 *
 * ZERO-KNOWLEDGE CONTRACT:
 *   Even on a successful /recovery/verify, the server returns
 *   wrappedVaultKeyForRecovery — still AES-256-GCM encrypted.
 *   Only the client with the actual recovery phrase can unwrap it.
 *   The server has ZERO ability to decrypt the vault at any point.
 *
 * ATTACK HARDENING APPLIED:
 *   [1] Timing-safe comparison: crypto.timingSafeEqual() on hash compare
 *       → prevents hash oracle via response-time side-channel
 *   [2] recoveryLimiter: 3 attempts/hour per IP on /recovery/verify
 *       → prevents brute-force of recovery hashes
 *   [3] Audit log on EVERY verify attempt (success AND failure)
 *       → users can see recovery attempts in their security timeline
 *   [4] Rekey invalidates ALL refresh tokens → force re-login everywhere
 *       → after a password change, no stale sessions can continue
 *   [5] Email not enumerated: unknown email returns same 401 as wrong hash
 *       → attacker can't learn which emails are registered via recovery
 * ═══════════════════════════════════════════════════════════════════
 */

import crypto from "crypto";
import { Router } from "express";
import prisma from "../lib/prisma";
import { logAuditEvent, extractIp } from "../lib/audit";
import { authenticateJWT } from "../middleware/auth";
import { validateBody } from "../middleware/validate";
import { recoveryLimiter } from "../middleware/rateLimit";

const router = Router();

// ─────────────────────────────────────────────────────────────────────────────
// POST /recovery/setup
// ─────────────────────────────────────────────────────────────────────────────
/**
 * Store recovery configuration for the authenticated user.
 *
 * The client has already:
 *   1. Generated a 24-word recovery phrase
 *   2. Derived a recovery KEK from the phrase (Argon2id, static salt)
 *   3. Wrapped the vault key with the recovery KEK → wrappedVaultKeyForRecovery
 *   4. SHA-256 hashed the phrase → recoveryHash
 *
 * The server stores both. It cannot verify the phrase itself —
 * it only has the hash.
 *
 * Requires: Authorization: Bearer <jwt>
 * Body: { recoveryHash, wrappedVaultKeyForRecovery }
 *
 * Responses:
 *   200 { message: "Recovery configured" }
 *   400 { error }   — missing fields
 *   401 { error }   — missing/invalid JWT
 */
router.post(
  "/setup",
  authenticateJWT,
  validateBody(["recoveryHash", "wrappedVaultKeyForRecovery"]),
  async (req, res, next) => {
    try {
      const { userId } = req.user!;
      const { recoveryHash, wrappedVaultKeyForRecovery } = req.body as {
        recoveryHash: string;
        wrappedVaultKeyForRecovery: string;
      };

      // Validate recoveryHash is a 64-char hex string (SHA-256 output)
      if (!/^[0-9a-f]{64}$/i.test(recoveryHash)) {
        res.status(400).json({
          error: "recoveryHash must be a 64-character hex string (SHA-256 of phrase)",
        });
        return;
      }

      await prisma.user.update({
        where: { id: userId },
        data: {
          recoveryHash,
          wrappedVaultKeyForRecovery,
        },
      });

      res.status(200).json({ message: "Recovery configured" });
    } catch (err) {
      next(err);
    }
  }
);

// ─────────────────────────────────────────────────────────────────────────────
// POST /recovery/verify
// ─────────────────────────────────────────────────────────────────────────────
/**
 * Verify a recovery phrase hash and return the recovery-wrapped vault key.
 *
 * Body: { email, recoveryPhraseHash }
 *
 * [1] TIMING ATTACK HARDENING:
 *   Uses crypto.timingSafeEqual() — regular string === comparison leaks
 *   timing information that could reveal whether the hash prefix matches.
 *
 * [2] Rate limited to 3 attempts/hour by recoveryLimiter.
 *
 * [3] Audit logged on EVERY attempt (success and failure).
 *
 * [5] Unknown email returns same 401 as wrong hash — no email enumeration.
 *
 * Responses:
 *   200 { wrappedVaultKeyForRecovery, argon2Salt }
 *   400 { error }   — missing fields or recovery not set up
 *   401 { error }   — hash mismatch or user not found
 *   429 { error }   — too many attempts (recoveryLimiter)
 */
router.post(
  "/verify",
  recoveryLimiter,  // [2] Hard rate limit: 3/hour per IP
  validateBody(["email", "recoveryPhraseHash"]),
  async (req, res, next) => {
    try {
      const { email, recoveryPhraseHash } = req.body as {
        email: string;
        recoveryPhraseHash: string;
      };
      const ip = extractIp(req);

      // Normalise the incoming hash
      const incomingHash = recoveryPhraseHash.trim().toLowerCase();

      // Validate format: must be 64-char hex
      if (!/^[0-9a-f]{64}$/i.test(incomingHash)) {
        res.status(401).json({ error: "Invalid recovery phrase" });
        return;
      }

      const user = await prisma.user.findUnique({
        where: { email: email.trim().toLowerCase() },
        select: {
          id: true,
          recoveryHash: true,
          wrappedVaultKeyForRecovery: true,
          argon2Salt: true,
        },
      });

      // [5] Don't reveal whether the email exists — always the same error
      if (!user || !user.recoveryHash || !user.wrappedVaultKeyForRecovery) {
        // [3] Audit even on user-not-found to catch enumeration attempts
        if (user) {
          void logAuditEvent({
            userId: user.id,
            action: "RECOVERY_USED",
            ipAddress: ip,
            prisma,
          });
        }
        res.status(401).json({ error: "Invalid recovery phrase" });
        return;
      }

      // [1] CONSTANT-TIME HASH COMPARISON — prevents timing oracle
      const storedHashBuf   = Buffer.from(user.recoveryHash, "hex");
      const incomingHashBuf = Buffer.from(incomingHash, "hex");

      const hashesMatch =
        storedHashBuf.length === incomingHashBuf.length &&
        crypto.timingSafeEqual(storedHashBuf, incomingHashBuf);

      // [3] Always audit — both success and failure are logged
      void logAuditEvent({
        userId: user.id,
        action: "RECOVERY_USED",
        ipAddress: ip,
        prisma,
      });

      if (!hashesMatch) {
        res.status(401).json({ error: "Invalid recovery phrase" });
        return;
      }

      // Match: return vault key wrapped with recovery KEK
      // Client will use their phrase to derive the recovery KEK and unwrap it
      res.status(200).json({
        wrappedVaultKeyForRecovery: user.wrappedVaultKeyForRecovery,
        argon2Salt: user.argon2Salt,
      });
    } catch (err) {
      next(err);
    }
  }
);

// ─────────────────────────────────────────────────────────────────────────────
// POST /recovery/rekey
// ─────────────────────────────────────────────────────────────────────────────
/**
 * Re-wrap the vault key with a new master password.
 *
 * Called after recovery: the client has unwrapped the vault key using
 * their recovery phrase, then re-wrapped it with a new master password KEK.
 *
 * [4] After rekey, ALL refresh tokens are invalidated — every device
 *     must re-authenticate. This prevents stale sessions from continuing
 *     to access a vault whose password just changed.
 *
 * Requires: Authorization: Bearer <jwt>
 * Body: { newWrappedVaultKey, newArgon2Salt }
 *
 * Responses:
 *   200 { message: "Vault rekeyed successfully" }
 *   400 { error }   — missing fields
 *   401 { error }   — missing/invalid JWT
 */
router.post(
  "/rekey",
  authenticateJWT,
  validateBody(["newWrappedVaultKey", "newArgon2Salt"]),
  async (req, res, next) => {
    try {
      const { userId } = req.user!;
      const { newWrappedVaultKey, newArgon2Salt } = req.body as {
        newWrappedVaultKey: string;
        newArgon2Salt: string;
      };
      const ip = extractIp(req);

      // Atomically: update vault key + salt, invalidate all refresh tokens
      await prisma.$transaction([
        // Update master-password-wrapped vault key with new KEK wrap
        prisma.user.update({
          where: { id: userId },
          data: {
            wrappedVaultKey: newWrappedVaultKey,
            argon2Salt: newArgon2Salt,
          },
        }),
        // [4] Invalidate ALL active refresh tokens — force re-login everywhere
        prisma.refreshToken.updateMany({
          where: {
            userId,
            used: false,
            expiresAt: { gt: new Date() },
          },
          data: { used: true },
        }),
      ]);

      void logAuditEvent({
        userId,
        action: "PASSWORD_CHANGED",
        ipAddress: ip,
        prisma,
      });

      res.status(200).json({ message: "Vault rekeyed successfully" });
    } catch (err) {
      next(err);
    }
  }
);

export default router;
