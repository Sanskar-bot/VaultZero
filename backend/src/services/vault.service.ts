/**
 * ═══════════════════════════════════════════════════════════════════
 * Vault Service — Business Logic for Encrypted Vault Blob Storage
 * ═══════════════════════════════════════════════════════════════════
 *
 * The server treats vault ciphertext as an OPAQUE BLOB.
 * It stores bytes, not data. It cannot decrypt or inspect content.
 *
 * CONFLICT RESOLUTION:
 *   The server uses "last write wins" — whichever client pushes last
 *   overwrites the stored blob. Clients can use updatedAt to detect
 *   conflicts (if their local updatedAt is older than the server's,
 *   they should pull first before pushing).
 *
 * AUDIT LOGGING:
 *   Every pull and push is logged with userId, deviceId, and IP.
 *   This allows users to see which devices accessed their vault.
 * ═══════════════════════════════════════════════════════════════════
 */

import { prisma } from "../config";
import { logAuditEvent } from "./audit.service";

export interface PullVaultInput {
  userId: string;
  deviceId?: string;
  ipAddress?: string;
}

export interface PullVaultResult {
  ciphertext: string;
  updatedAt: number; // Unix timestamp in milliseconds
}

/**
 * Pull the encrypted vault blob for a user.
 *
 * Returns null if the user has never pushed a vault (first login).
 * The ciphertext is an opaque base64 blob — the server never inspects it.
 *
 * @returns PullVaultResult or null if no vault exists yet
 */
export async function pullVault(
  input: PullVaultInput
): Promise<PullVaultResult | null> {
  const { userId, deviceId, ipAddress } = input;

  const vaultBlob = await prisma.vaultBlob.findFirst({
    where: { userId },
  });

  // Log even on 404 — helps detect if someone is polling with stolen JWTs
  await logAuditEvent({
    userId,
    deviceId,
    action: "VAULT_PULL",
    ipAddress,
  });

  if (!vaultBlob) {
    return null;
  }

  return {
    ciphertext: vaultBlob.ciphertext,
    updatedAt: vaultBlob.updatedAt.getTime(),
  };
}

export interface PushVaultInput {
  userId: string;
  ciphertext: string;
  deviceId?: string;
  ipAddress?: string;
}

export interface PushVaultResult {
  updatedAt: number; // Unix timestamp in milliseconds
}

/**
 * Push (upsert) the encrypted vault blob for a user.
 *
 * Creates the blob on first push, updates it on subsequent pushes.
 * Uses Prisma's upsert to handle the create/update atomically.
 *
 * @returns PushVaultResult with the server-side updatedAt timestamp
 */
export async function pushVault(
  input: PushVaultInput
): Promise<PushVaultResult> {
  const { userId, ciphertext, deviceId, ipAddress } = input;

  // Find existing vault blob for this user
  const existing = await prisma.vaultBlob.findFirst({
    where: { userId },
  });

  let vaultBlob;
  if (existing) {
    // Update existing blob
    vaultBlob = await prisma.vaultBlob.update({
      where: { id: existing.id },
      data: { ciphertext },
    });
  } else {
    // Create new blob for first push
    vaultBlob = await prisma.vaultBlob.create({
      data: { userId, ciphertext },
    });
  }

  await logAuditEvent({
    userId,
    deviceId,
    action: "VAULT_PUSH",
    ipAddress,
  });

  return {
    updatedAt: vaultBlob.updatedAt.getTime(),
  };
}
