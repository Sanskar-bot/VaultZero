/**
 * ═══════════════════════════════════════════════════════════════════
 * Audit Service — Business Logic for Security Event Logging
 * ═══════════════════════════════════════════════════════════════════
 *
 * Every security-relevant event is written to the audit_log table.
 * Users can see their own audit log via GET /audit/log.
 *
 * Why audit logging matters for a password manager:
 *   - Users can detect unauthorized access (unknown IPs, devices)
 *   - Abnormal patterns (vault pull every 10 seconds) can indicate compromise
 *   - Required for SOC2/GDPR compliance in a production deployment
 *
 * PRIVACY NOTE:
 *   IP addresses are PII. In a production deployment, consider:
 *   - Hashing IPs with a daily rotating key
 *   - Storing only the /24 subnet for geolocation without exact IP
 *   - Auto-deleting audit logs older than 90 days
 * ═══════════════════════════════════════════════════════════════════
 */

import { AuditAction } from "@prisma/client";
import { prisma } from "../config";

export interface LogAuditEventInput {
  userId: string;
  deviceId?: string;
  action: AuditAction;
  ipAddress?: string;
}

/**
 * Write a security event to the audit log.
 *
 * This is a fire-and-forget write — errors are caught and logged to
 * stderr but never propagated to the caller. Audit logging failures
 * must NOT prevent the main operation from completing.
 *
 * @param input - Audit event details
 */
export async function logAuditEvent(input: LogAuditEventInput): Promise<void> {
  const { userId, deviceId, action, ipAddress } = input;

  try {
    await prisma.auditLog.create({
      data: {
        userId,
        deviceId: deviceId ?? null,
        action,
        ipAddress: ipAddress ?? "unknown",
      },
    });
  } catch (error) {
    // Audit log failures must not block the main operation
    // Log to stderr for ops visibility but don't throw
    console.error(
      `[AuditService] Failed to write audit event ${action} for user ${userId}:`,
      error instanceof Error ? error.message : "unknown error"
    );
  }
}

export interface GetAuditLogInput {
  userId: string;
  limit?: number;
}

/**
 * Retrieve the most recent audit events for a user.
 *
 * Returns up to `limit` events (default 50), ordered newest first.
 *
 * @param input - { userId, limit? }
 * @returns Array of audit log entries
 */
export async function getAuditLog(input: GetAuditLogInput) {
  const { userId, limit = 50 } = input;

  return prisma.auditLog.findMany({
    where: { userId },
    orderBy: { createdAt: "desc" },
    take: limit,
  });
}
