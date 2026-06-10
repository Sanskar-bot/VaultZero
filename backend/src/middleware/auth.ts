/**
 * ═══════════════════════════════════════════════════════════════════
 * src/middleware/auth.ts — JWT Verification Middleware
 * ═══════════════════════════════════════════════════════════════════
 *
 * Reads the Authorization: Bearer <token> header, verifies the JWT,
 * and attaches { userId, deviceId } to req.user for downstream handlers.
 *
 * Error responses:
 *   401 { error: "Authorization header required" }  — missing header
 *   401 { error: "Token expired" }                   — valid but expired
 *   401 { error: "Invalid token" }                   — bad signature/malformed
 *
 * NEVER leak jwt.verify() error messages to the client — they can
 * reveal internal details about token structure or secret length.
 * ═══════════════════════════════════════════════════════════════════
 */

import { Request, Response, NextFunction } from "express";
// Import under aliases to avoid name collision with the exported `verifyJWT` alias below
import {
  verifyJWT as verifyJWTToken,
  TokenExpiredError,
  JsonWebTokenError,
} from "../lib/token";

// Re-export JWTPayload type for convenience
export type { JWTPayload } from "../lib/token";

// ── Extend Express Request type ──────────────────────────────────────────────
declare global {
  namespace Express {
    interface Request {
      user?: {
        userId: string;
        deviceId?: string;
      };
    }
  }
}

/**
 * Express middleware: authenticate via JWT Bearer token.
 *
 * On success: sets req.user = { userId, deviceId? } and calls next().
 * On failure: responds 401 immediately, does NOT call next().
 */
export function authenticateJWT(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    res.status(401).json({ error: "Authorization header required" });
    return;
  }

  const token = authHeader.slice(7); // strip "Bearer " prefix

  try {
    const payload = verifyJWTToken(token);
    req.user = {
      userId: payload.userId,
      deviceId: payload.deviceId,
    };
    next();
  } catch (err) {
    if (err instanceof TokenExpiredError) {
      res.status(401).json({ error: "Token expired" });
      return;
    }
    if (err instanceof JsonWebTokenError) {
      res.status(401).json({ error: "Invalid token" });
      return;
    }
    // Unexpected error (e.g. JWT_SECRET not set) — let global handler catch it
    next(err);
  }
}

// Alias for any older files still importing `verifyJWT` by that name
export const verifyJWT = authenticateJWT;
