/**
 * ═══════════════════════════════════════════════════════════════════
 * Backend Configuration & Prisma Singleton
 * ═══════════════════════════════════════════════════════════════════
 *
 * Centralises all environment variable access and exports a single
 * PrismaClient instance shared across the entire process.
 *
 * WHY A SINGLETON?
 *   Prisma opens a connection pool when the client is first instantiated.
 *   Creating multiple PrismaClient instances causes connection exhaustion.
 *   Using a module-level singleton guarantees exactly one pool per process.
 *
 * STARTUP VALIDATION:
 *   requireEnv() throws immediately if a critical variable is missing,
 *   so the server crashes at startup (fast-fail) rather than silently
 *   misbehaving at runtime.
 * ═══════════════════════════════════════════════════════════════════
 */

import { PrismaClient } from "@prisma/client";

// ─── Prisma singleton ────────────────────────────────────────────────────────

/**
 * Singleton PrismaClient instance.
 *
 * Import this wherever you need database access:
 *   import { prisma } from "../config";
 */
export const prisma = new PrismaClient();

// ─── Environment helpers ─────────────────────────────────────────────────────

/**
 * Read a required environment variable, throwing immediately if absent.
 *
 * @param name - The environment variable name (e.g. "JWT_SECRET")
 * @returns The variable's string value
 * @throws Error if the variable is not set or is empty
 */
export function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(
      `Missing required environment variable: ${name}. ` +
        `Copy backend/.env.example to backend/.env and fill in all values.`
    );
  }
  return value;
}

/**
 * Read an optional environment variable with a default fallback.
 *
 * @param name    - The environment variable name
 * @param fallback - Default value if the variable is absent
 */
export function optionalEnv(name: string, fallback: string): string {
  return process.env[name] ?? fallback;
}
