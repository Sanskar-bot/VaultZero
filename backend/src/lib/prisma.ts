/**
 * ═══════════════════════════════════════════════════════════════════
 * src/lib/prisma.ts — Singleton PrismaClient
 * ═══════════════════════════════════════════════════════════════════
 *
 * WHY A SINGLETON?
 *   PrismaClient opens a connection pool when first instantiated.
 *   Creating multiple instances (common with hot-reload in dev)
 *   exhausts the PostgreSQL connection limit quickly.
 *
 * HOT-RELOAD GUARD:
 *   In development, tsx/ts-node re-imports modules on every change.
 *   We stash the client on the global object so the same instance
 *   is reused across hot-reloads. In production, the module is only
 *   loaded once so this guard is a no-op.
 *
 * NEVER import PrismaClient directly anywhere else in this codebase.
 * Always: import prisma from '../lib/prisma'
 * ═══════════════════════════════════════════════════════════════════
 */

import { PrismaClient } from "@prisma/client";

// Declare the global augmentation so TypeScript doesn't complain
declare global {
  // eslint-disable-next-line no-var
  var __prisma: PrismaClient | undefined;
}

const prisma: PrismaClient =
  global.__prisma ??
  new PrismaClient({
    log:
      process.env.NODE_ENV === "development"
        ? ["warn", "error"]
        : ["error"],
  });

// In development, attach to global to survive hot-reloads
if (process.env.NODE_ENV !== "production") {
  global.__prisma = prisma;
}

export default prisma;
