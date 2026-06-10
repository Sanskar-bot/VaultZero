/**
 * ═══════════════════════════════════════════════════════════════════
 * src/app.ts — Express Application Factory
 * ═══════════════════════════════════════════════════════════════════
 *
 * Creates and fully configures the Express app. Exported as a factory
 * function so it can be instantiated cleanly in tests without starting
 * a real server or connecting to a real database.
 *
 * MIDDLEWARE ORDER (matters — do not reorder):
 *   1. helmet()         — security headers, must be first
 *   2. cors()           — CORS headers, before routes
 *   3. express.json()   — body parsing, before routes
 *   4. standardLimiter  — global rate limit, before routes
 *   5. authLimiter      — applied only to specific auth paths
 *   6. Routes           — business logic
 *   7. 404 handler      — after all routes
 *   8. Error handler    — must be last, must have 4 params
 *
 * ATTACK HARDENING APPLIED:
 *   [1] Helmet: sets HSTS, nosniff, X-Frame-Options DENY, removes X-Powered-By
 *   [2] CORS: locked to ALLOWED_ORIGIN env var — never wildcard *
 *   [3] Body limit: 2.5MB (slightly above vault 2MB limit, protects parse layer)
 *   [4] standardLimiter: 100 req/15min globally
 *   [5] authLimiter: 5 req/15min on login + register
 *   [6] Global error handler: NEVER sends error.message or stack to client
 * ═══════════════════════════════════════════════════════════════════
 */

import express, { Request, Response, NextFunction } from "express";
import helmet from "helmet";
import cors from "cors";
import { standardLimiter, authLimiter } from "./middleware/rateLimit";
import authRouter from "./routes/auth";
import vaultRouter from "./routes/vault";
import auditRouter from "./routes/audit";
import recoveryRouter from "./routes/recovery";

export function createApp() {
  const app = express();

  // [1] HELMET — security headers (must be applied before any route)
  // Sets: Strict-Transport-Security, X-Content-Type-Options: nosniff,
  //       X-Frame-Options: SAMEORIGIN, removes X-Powered-By, Content-Security-Policy
  app.use(
    helmet({
      hsts: {
        maxAge: 63_072_000, // 2 years in seconds
        includeSubDomains: true,
        preload: true,
      },
      frameguard: { action: "deny" },        // X-Frame-Options: DENY
      noSniff: true,                          // X-Content-Type-Options: nosniff
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'none'"],             // API server serves no HTML — lock it down
          frameAncestors: ["'none'"],
        },
      },
    })
  );

  // [2] CORS — only allow the configured frontend origin
  // NEVER use origin: '*' — that would allow any site to make credentialed requests
  const allowedOrigin = process.env.ALLOWED_ORIGIN;
  app.use(
    cors({
      origin: (origin, callback) => {
        // Allow requests with no origin (curl, Postman, server-to-server)
        if (!origin) {
          callback(null, true);
          return;
        }
        if (allowedOrigin && origin === allowedOrigin) {
          callback(null, true);
        } else {
          callback(new Error(`CORS: origin '${origin}' not allowed`));
        }
      },
      methods: ["GET", "POST", "OPTIONS"],
      allowedHeaders: ["Content-Type", "Authorization"],
      credentials: true,                     // needed for cookie-based auth if added later
    })
  );

  // [3] BODY PARSING — 2.5MB limit (slightly above vault 2MB limit)
  // Requests above this are rejected at the parse layer before route handlers run.
  // express.json() automatically returns 413 for oversized payloads.
  app.use(express.json({ limit: "2.5mb" }));

  // [4] GLOBAL RATE LIMITING — 100 req/15min per IP
  app.use(standardLimiter);

  // [5] STRICTER AUTH RATE LIMITING — 5 req/15min per IP on sensitive endpoints
  // Applied before routes mount so the limit fires even if the route handler throws.
  app.use("/auth/login", authLimiter);
  app.use("/auth/register", authLimiter);

  // ── Routes ────────────────────────────────────────────────────────────────
  app.use("/auth", authRouter);
  app.use("/vault", vaultRouter);
  app.use("/audit", auditRouter);
  app.use("/recovery", recoveryRouter);

  // ── Health check ──────────────────────────────────────────────────────────
  // Required by Railway for deployment health probes.
  app.get("/health", (_req: Request, res: Response) => {
    res.status(200).json({ status: "ok" });
  });

  // ── 404 handler ───────────────────────────────────────────────────────────
  app.use((_req: Request, res: Response) => {
    res.status(404).json({ error: "Route not found" });
  });

  // [6] GLOBAL ERROR HANDLER
  // MUST have exactly 4 parameters for Express to treat it as an error handler.
  // NEVER send error.message or stack — they may contain internal details.
  // Log the full error server-side for debugging, return generic message to client.
  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    // Log full error server-side for ops visibility
    console.error("[GlobalErrorHandler]", err);

    // CORS errors (from CORS middleware above)
    if (err instanceof Error && err.message.startsWith("CORS:")) {
      res.status(403).json({ error: "Forbidden" });
      return;
    }

    // Never expose error.message or stack to the client
    res.status(500).json({ error: "Internal server error" });
  });

  return app;
}
