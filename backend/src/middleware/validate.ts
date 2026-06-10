/**
 * ═══════════════════════════════════════════════════════════════════
 * src/middleware/validate.ts — Request Body Validation
 * ═══════════════════════════════════════════════════════════════════
 *
 * Lightweight field-presence validator. Returns 400 with a clear
 * error message if any required field is missing or empty.
 *
 * This is intentionally simple — it only checks presence, not format.
 * Format validation (email regex, base64 check, etc.) lives in the
 * route handler itself where context-specific rules apply.
 *
 * Usage:
 *   router.post('/auth/register',
 *     validateBody(['email', 'wrappedVaultKey', 'argon2Salt']),
 *     handler
 *   );
 * ═══════════════════════════════════════════════════════════════════
 */

import { Request, Response, NextFunction } from "express";

/**
 * Middleware factory: validate that all listed fields are present
 * and non-empty strings in req.body.
 *
 * @param fields - Array of required field names
 * @returns Express middleware that returns 400 on missing fields
 */
export function validateBody(fields: string[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const body = req.body as Record<string, unknown>;
    const missing: string[] = [];

    for (const field of fields) {
      const value = body[field];
      // Must be present, a string, and non-empty after trimming
      if (value === undefined || value === null || typeof value !== "string" || value.trim() === "") {
        missing.push(field);
      }
    }

    if (missing.length > 0) {
      res.status(400).json({
        error: `Missing required fields: ${missing.join(", ")}`,
      });
      return;
    }

    next();
  };
}
