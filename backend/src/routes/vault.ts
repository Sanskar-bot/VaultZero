/**
 * ═══════════════════════════════════════════════════════════════════
 * src/routes/vault.ts — Encrypted Vault Blob Sync
 * ═══════════════════════════════════════════════════════════════════
 *
 * ZERO-KNOWLEDGE CONTRACT:
 *   The server stores and returns `ciphertext` as an OPAQUE BLOB.
 *   It never attempts to parse, decrypt, or inspect the contents.
 *   Only the authenticated client can decrypt it using their vault key.
 *
 * CONFLICT MODEL (last-write-wins):
 *   No merge logic exists server-side. If two devices push simultaneously,
 *   whoever arrives last wins. Clients detect conflicts by comparing
 *   their local updatedAt timestamp with the server's returned updatedAt.
 *   If server.updatedAt > client.lastKnownUpdatedAt → pull before push.
 *
 * ATTACK HARDENING APPLIED:
 *   [1] Vault size limit: 413 if ciphertext > 2MB (storage exhaustion)
 *   [2] Minimum ciphertext length: at least 10 chars (rejects empty/stub pushes)
 *   [3] JWT required on both routes (authenticateJWT middleware)
 *   [4] Every pull and push is audit-logged with real client IP
 *   [5] Prisma P2002 (unique constraint) handled cleanly
 * ═══════════════════════════════════════════════════════════════════
 */

import { Router } from "express";
import { Prisma } from "@prisma/client";
import prisma from "../lib/prisma";
import { logAuditEvent, extractIp } from "../lib/audit";
import { authenticateJWT } from "../middleware/auth";
import { validateBody } from "../middleware/validate";

const router = Router();

// [3] All vault routes require a valid JWT
router.use(authenticateJWT);

// ── Vault size constants ──────────────────────────────────────────────────────
const MAX_CIPHERTEXT_BYTES = 2 * 1024 * 1024; // 2MB
const MIN_CIPHERTEXT_LENGTH = 10;              // sanity check

// ─────────────────────────────────────────────────────────────────────────────
// GET /vault/pull
// ─────────────────────────────────────────────────────────────────────────────
/**
 * Pull the encrypted vault blob for the authenticated user.
 *
 * Returns 404 if the user has never pushed a vault (first-time login).
 * The client should initialise a new empty vault locally in this case.
 *
 * Responses:
 *   200 { ciphertext: string, updatedAt: string (ISO 8601) }
 *   404 { error: "No vault found" }
 */
router.get("/pull", async (req, res, next) => {
  try {
    const { userId, deviceId } = req.user!;
    const ip = extractIp(req);

    const vaultBlob = await prisma.vaultBlob.findUnique({
      where: { userId },
      select: { ciphertext: true, updatedAt: true },
    });

    // [4] Log pull even on 404 — helps detect stolen JWTs being used to probe
    void logAuditEvent({
      userId,
      deviceId,
      action: "VAULT_PULL",
      ipAddress: ip,
      prisma,
    });

    if (!vaultBlob) {
      res.status(404).json({ error: "No vault found" });
      return;
    }

    res.status(200).json({
      ciphertext: vaultBlob.ciphertext,
      updatedAt: vaultBlob.updatedAt.toISOString(),
    });
  } catch (err) {
    next(err);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /vault/push
// ─────────────────────────────────────────────────────────────────────────────
/**
 * Push (upsert) the encrypted vault blob for the authenticated user.
 *
 * Body: { ciphertext: string }
 *
 * The server does NOT inspect or validate ciphertext contents.
 * Only structural checks are applied:
 *   - Must be a non-empty string (validateBody)
 *   - Must be at least 10 characters (stub rejection)
 *   - Must be under 2MB (storage exhaustion protection)
 *
 * Responses:
 *   200 { updatedAt: string (ISO 8601) }   — stored successfully
 *   400 { error }                           — too short
 *   413 { error: "Vault too large" }        — exceeds 2MB limit
 */
router.post("/push", validateBody(["ciphertext"]), async (req, res, next) => {
  try {
    const { userId, deviceId } = req.user!;
    const ip = extractIp(req);
    const { ciphertext } = req.body as { ciphertext: string };

    // [2] Minimum length sanity check
    if (ciphertext.length < MIN_CIPHERTEXT_LENGTH) {
      res.status(400).json({
        error: `Ciphertext too short (minimum ${MIN_CIPHERTEXT_LENGTH} characters)`,
      });
      return;
    }

    // [1] VAULT SIZE LIMIT — prevent storage exhaustion attacks
    // Check byte length (not char length) because base64 can contain multi-byte sequences
    const byteLength = Buffer.byteLength(ciphertext, "utf8");
    if (byteLength > MAX_CIPHERTEXT_BYTES) {
      res.status(413).json({ error: "Vault too large. Maximum size is 2MB." });
      return;
    }

    // Upsert: create on first push, update on subsequent pushes
    const vaultBlob = await prisma.vaultBlob.upsert({
      where: { userId },
      create: { userId, ciphertext },
      update: { ciphertext },
      select: { updatedAt: true },
    });

    // [4] Log every push
    void logAuditEvent({
      userId,
      deviceId,
      action: "VAULT_PUSH",
      ipAddress: ip,
      prisma,
    });

    res.status(200).json({
      updatedAt: vaultBlob.updatedAt.toISOString(),
    });
  } catch (err) {
    // [5] Handle Prisma unique constraint (shouldn't happen with upsert but be safe)
    if (
      err instanceof Prisma.PrismaClientKnownRequestError &&
      err.code === "P2002"
    ) {
      res.status(409).json({ error: "Vault conflict — try pulling first" });
      return;
    }
    next(err);
  }
});

export default router;
