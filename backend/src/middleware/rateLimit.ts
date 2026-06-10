/**
 * ═══════════════════════════════════════════════════════════════════
 * src/middleware/rateLimit.ts — Rate Limiting
 * ═══════════════════════════════════════════════════════════════════
 *
 * Two limiters:
 *
 * authLimiter — applied to /auth/login and /auth/register
 *   5 requests per 15 minutes per IP.
 *   Prevents brute-force password guessing and registration spam.
 *   Combined with Argon2id (64 MiB/guess on client), makes attacks
 *   impractical even if the rate limit is hit.
 *
 * standardLimiter — applied globally to all routes
 *   100 requests per 15 minutes per IP.
 *   Prevents general API abuse, scraping, and DoS.
 *
 * recoveryLimiter — applied to /recovery/verify
 *   3 requests per hour per IP.
 *   Recovery is a high-value target; much stricter than login.
 *
 * NOTE: In-memory store (single process). For multi-instance Railway
 * deployments with >1 replica, upgrade to rate-limit-redis to share
 * state across instances. For free tier (single instance), this is fine.
 * ═══════════════════════════════════════════════════════════════════
 */

import rateLimit from "express-rate-limit";

const FIFTEEN_MINUTES = 15 * 60 * 1000;
const ONE_HOUR = 60 * 60 * 1000;

/**
 * Auth limiter: 5 requests per 15 minutes per IP.
 * Applied to: POST /auth/login, POST /auth/register
 */
export const authLimiter = rateLimit({
  windowMs: FIFTEEN_MINUTES,
  max: 5,
  standardHeaders: true,   // Emit RateLimit-* headers (RFC 6585)
  legacyHeaders: false,     // Disable X-RateLimit-* headers
  message: { error: "Too many attempts. Try again in 15 minutes." },
  // Don't count successful requests against the limit —
  // only failed/suspicious requests burn through quota
  skipSuccessfulRequests: false,
});

/**
 * Standard limiter: 100 requests per 15 minutes per IP.
 * Applied globally via app.use().
 */
export const standardLimiter = rateLimit({
  windowMs: FIFTEEN_MINUTES,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Rate limit exceeded." },
});

/**
 * Recovery limiter: 3 requests per hour per IP.
 * Applied to: POST /recovery/verify
 * Recovery phrase brute-force is high-value — much stricter limit.
 */
export const recoveryLimiter = rateLimit({
  windowMs: ONE_HOUR,
  max: 3,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many recovery attempts. Try again in 1 hour." },
});
