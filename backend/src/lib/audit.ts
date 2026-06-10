/**
 * ═══════════════════════════════════════════════════════════════════
 * src/lib/audit.ts — Security Event Logging
 * ═══════════════════════════════════════════════════════════════════
 *
 * DESIGN PRINCIPLE: Audit failures must NEVER break the main request.
 *
 * logAuditEvent() wraps the DB insert in try/catch and only writes
 * to console.error on failure. The calling route handler receives
 * no error — it proceeds normally.
 *
 * This prevents an audit DB issue from causing 500s on login/vault
 * operations. Audit logs are important, but not more important than
 * availability of the core service.
 *
 * WHAT TO LOG:
 *   - IP address: from X-Forwarded-For (Railway proxy) or req.socket
 *   - deviceId: optional, for per-device session tracking
 *   - action: always use the AuditAction enum — no free-form strings
 *
 * NEVER log: tokens, passwords, KEKs, or vault contents.
 * ═══════════════════════════════════════════════════════════════════
 */

import { AuditAction, PrismaClient } from "@prisma/client";

export interface LogAuditParams {
  userId: string;
  deviceId?: string | null;
  action: AuditAction;
  ipAddress: string;
  prisma: PrismaClient;
}

/**
 * Write a security event to the audit log.
 *
 * Fire-and-forget: errors are swallowed and logged to stderr only.
 * Never throws. Never rejects. Calling code never needs to await
 * this if you don't want to block the response.
 *
 * @param params - Audit event details including the prisma client
 */
export async function logAuditEvent(params: LogAuditParams): Promise<void> {
  const { userId, deviceId, action, ipAddress, prisma } = params;

  try {
    await prisma.auditLog.create({
      data: {
        userId,
        deviceId: deviceId ?? null,
        action,
        ipAddress,
      },
    });
  } catch (err) {
    // Audit logging failure is never surfaced to the client.
    // Log to stderr so ops can monitor but don't break the request.
    console.error(
      `[AuditLog] FAILED to write ${action} event for user ${userId}:`,
      err instanceof Error ? err.message : "unknown error"
    );
  }
}

/**
 * Extract the real client IP from an Express request.
 *
 * Railway (and most cloud hosts) sit behind a proxy that sets
 * X-Forwarded-For. Trust the first entry (leftmost = client IP).
 * Fall back to req.socket.remoteAddress if header is absent.
 *
 * @param req - Express request object (typed loosely to avoid circular import)
 */
export function extractIp(req: {
  headers: Record<string, string | string[] | undefined>;
  socket: { remoteAddress?: string };
  ip?: string;
}): string {
  const forwarded = req.headers["x-forwarded-for"];
  if (forwarded) {
    const first = Array.isArray(forwarded) ? forwarded[0] : forwarded.split(",")[0];
    return first.trim();
  }
  return req.socket.remoteAddress ?? req.ip ?? "unknown";
}
