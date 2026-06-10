/**
 * ═══════════════════════════════════════════════════════════════════
 * src/server.ts — VaultZero API Server Entry Point
 * ═══════════════════════════════════════════════════════════════════
 *
 * Responsibilities (in order):
 *   1. Load .env (dotenv)
 *   2. Validate critical environment variables — FAIL FAST if missing/weak
 *   3. Connect Prisma + verify DB is reachable (SELECT 1)
 *   4. Create Express app
 *   5. Start listening
 *   6. Register graceful shutdown handlers (SIGTERM, SIGINT)
 *
 * STARTUP SECURITY CHECKS:
 *   - JWT_SECRET must exist and be at least 32 characters.
 *     A short secret makes HMAC-SHA256 brute-forceable offline.
 *     Recommended: 64 random bytes = 128 hex chars.
 *   - DATABASE_URL must exist (no DB = no point starting).
 *   - DB must respond to SELECT 1 before accepting traffic.
 *     This prevents the server from starting in a broken state
 *     and silently failing on the first real request.
 *
 * GRACEFUL SHUTDOWN:
 *   On SIGTERM (Railway stopping the container) or SIGINT (Ctrl+C):
 *   - Stop accepting new connections (server.close)
 *   - Disconnect Prisma (flushes connection pool cleanly)
 *   - Exit 0
 *
 * ⚠️ SECURITY NOTE: DATABASE_URL is NEVER logged — it contains credentials.
 * ═══════════════════════════════════════════════════════════════════
 */

import dotenv from "dotenv";
dotenv.config(); // Must run before any process.env access

import prisma from "./lib/prisma";
import { createApp } from "./app";

// ── Startup validation ─────────────────────────────────────────────────────

/**
 * Validate that all required environment variables are present and strong.
 * Throws an Error with a descriptive message on any failure.
 * Caller catches and calls process.exit(1).
 *
 * ⚠️ NEVER log the value of JWT_SECRET or DATABASE_URL.
 */
function validateEnvironment(): void {
  // JWT_SECRET must exist and be at least 32 characters
  const jwtSecret = process.env.JWT_SECRET;
  if (!jwtSecret) {
    throw new Error(
      "JWT_SECRET is not set. Generate one with:\n" +
        "  node -e \"console.log(require('crypto').randomBytes(64).toString('hex'))\""
    );
  }
  if (jwtSecret.length < 32) {
    throw new Error(
      `JWT_SECRET is too short (${jwtSecret.length} chars). ` +
        "Must be at least 32 characters. " +
        "A short secret makes HMAC-SHA256 brute-forceable. " +
        "Generate a secure one with:\n" +
        "  node -e \"console.log(require('crypto').randomBytes(64).toString('hex'))\""
    );
  }

  // DATABASE_URL must exist (value is never logged)
  if (!process.env.DATABASE_URL) {
    throw new Error(
      "DATABASE_URL is not set. " +
        "Add it to your .env file (see .env.example)."
    );
  }
}

// ── Bootstrap ──────────────────────────────────────────────────────────────

const PORT = parseInt(process.env.PORT ?? "3000", 10);

async function bootstrap(): Promise<void> {
  // Step 1: Validate environment variables
  try {
    validateEnvironment();
  } catch (err) {
    console.error("[Startup] Environment validation failed:");
    console.error(" ", err instanceof Error ? err.message : err);
    process.exit(1);
  }

  // Step 2: Connect Prisma and verify DB is reachable
  try {
    await prisma.$connect();
    // Run a real query to confirm connectivity (not just TCP handshake)
    await prisma.$queryRaw`SELECT 1`;
    console.log("[Prisma] Database connection verified");
  } catch (err) {
    console.error("[Startup] Database connection failed:");
    // Sanitise error message — PostgreSQL driver errors can embed the DATABASE_URL.
    // Strip it before logging so credentials never appear in log aggregators.
    // NEVER log process.env.DATABASE_URL directly.
    const rawMsg = err instanceof Error ? err.message : String(err);
    const safeMsg = rawMsg.replace(/postgresql:\/\/[^\s]*/gi, "[DATABASE_URL_REDACTED]");
    console.error(" ", safeMsg);
    process.exit(1);
  }

  // Step 3: Create and start the Express app
  const app = createApp();

  const server = app.listen(PORT, () => {
    console.log(`\n✓ VaultZero API running on port ${PORT} — zero-knowledge mode active`);
    console.log(`  Environment : ${process.env.NODE_ENV ?? "development"}`);
    console.log(`  Health check: http://localhost:${PORT}/health`);
    console.log(`  JWT expiry  : 15 minutes`);
    // Never log JWT_SECRET or DATABASE_URL here
  });

  // Step 4: Graceful shutdown
  const shutdown = async (signal: string): Promise<void> => {
    console.log(`\n[Shutdown] Received ${signal} — shutting down gracefully...`);

    // Stop accepting new connections, finish in-flight requests
    server.close(async () => {
      await prisma.$disconnect();
      console.log("[Shutdown] Prisma disconnected. Goodbye.");
      process.exit(0);
    });

    // Force exit if graceful shutdown takes too long (Railway timeout is 10s)
    setTimeout(() => {
      console.error("[Shutdown] Forced exit after timeout.");
      process.exit(1);
    }, 9000);
  };

  process.on("SIGTERM", () => { void shutdown("SIGTERM"); });
  process.on("SIGINT",  () => { void shutdown("SIGINT"); });

  // Catch unhandled promise rejections — log but don't crash
  process.on("unhandledRejection", (reason) => {
    console.error("[UnhandledRejection]", reason);
  });
}

void bootstrap();
