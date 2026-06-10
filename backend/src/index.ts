/**
 * ═══════════════════════════════════════════════════════════════════
 * VaultZero Backend — Server Entry Point
 * ═══════════════════════════════════════════════════════════════════
 *
 * Responsibilities:
 *   1. Load environment variables from .env (via dotenv)
 *   2. Validate critical env vars (fail fast at startup)
 *   3. Connect Prisma to the database
 *   4. Create the Express app
 *   5. Start listening on PORT
 *   6. Register graceful shutdown handlers (SIGTERM, SIGINT)
 *
 * GRACEFUL SHUTDOWN:
 *   On SIGTERM (e.g. Railway/Kubernetes stopping the container):
 *     - Stop accepting new connections
 *     - Disconnect Prisma (flushes connection pool)
 *     - Exit cleanly
 *   This prevents "connection reset" errors for in-flight requests.
 * ═══════════════════════════════════════════════════════════════════
 */

import dotenv from "dotenv";
dotenv.config(); // Must run before any process.env access

import { createApp } from "./app";
import { prisma, requireEnv } from "./config";

// ── Validate critical environment variables ────────────────────────────────
// requireEnv() throws immediately if the variable is missing or empty,
// so we catch and report it before doing anything else.
try {
  requireEnv("JWT_SECRET");
  requireEnv("DATABASE_URL");
} catch (error) {
  console.error("[Startup] Configuration error:", error instanceof Error ? error.message : error);
  process.exit(1);
}

// ── Resolve port ───────────────────────────────────────────────────────────
const PORT = parseInt(process.env.PORT ?? "3000", 10);

// ── Bootstrap ─────────────────────────────────────────────────────────────
async function bootstrap(): Promise<void> {
  // Connect Prisma — verifies DATABASE_URL is reachable before accepting traffic
  try {
    await prisma.$connect();
    console.log("[Prisma] Connected to database");
  } catch (error) {
    console.error(
      "[Startup] Failed to connect to database:",
      error instanceof Error ? error.message : error
    );
    process.exit(1);
  }

  const app = createApp();

  const server = app.listen(PORT, () => {
    console.log(`VaultZero API running on port ${PORT}`);
    console.log(`  Environment : ${process.env.NODE_ENV ?? "development"}`);
    console.log(`  Health check: http://localhost:${PORT}/health`);
  });

  // ── Graceful shutdown ───────────────────────────────────────────────────
  const shutdown = async (signal: string) => {
    console.log(`\n[Shutdown] Received ${signal} — shutting down gracefully...`);
    server.close(async () => {
      await prisma.$disconnect();
      console.log("[Shutdown] Prisma disconnected. Bye!");
      process.exit(0);
    });
  };

  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}

bootstrap().catch((error) => {
  console.error("[Startup] Unexpected error:", error);
  process.exit(1);
});
