/**
 * ═══════════════════════════════════════════════════════════════════
 * src/routes/audit.ts — Security Audit Log
 * ═══════════════════════════════════════════════════════════════════
 *
 * Returns the last 50 audit events for the authenticated user.
 *
 * ISOLATION GUARANTEE:
 *   The query is always scoped to req.user.userId — a user can never
 *   see another user's events. This is enforced at the Prisma query
 *   level (WHERE userId = ?), not just by filtering the response.
 *
 * USE CASES:
 *   - User detects login from an unknown IP → revokes sessions
 *   - User sees vault pulls from an unexpected device → rekeys vault
 *   - Security audit trail for compliance (SOC2, GDPR)
 * ═══════════════════════════════════════════════════════════════════
 */

import { Router } from "express";
import prisma from "../lib/prisma";
import { authenticateJWT } from "../middleware/auth";

const router = Router();

// All audit routes require authentication
router.use(authenticateJWT);

// ─────────────────────────────────────────────────────────────────────────────
// GET /audit/log
// ─────────────────────────────────────────────────────────────────────────────
/**
 * Return the last 50 security events for the authenticated user.
 *
 * Events are ordered newest-first so the client renders a
 * chronological security timeline starting with the most recent.
 *
 * Responses:
 *   200 { events: AuditLog[] }
 *
 * Each event:
 *   { id, action, ipAddress, createdAt, deviceId }
 */
router.get("/log", async (req, res, next) => {
  try {
    const { userId } = req.user!;

    const events = await prisma.auditLog.findMany({
      where: { userId }, // ALWAYS scoped to requesting user
      orderBy: { createdAt: "desc" },
      take: 50,
      select: {
        id: true,
        action: true,
        ipAddress: true,
        createdAt: true,
        deviceId: true,
      },
    });

    res.status(200).json({ events });
  } catch (err) {
    next(err);
  }
});

export default router;
