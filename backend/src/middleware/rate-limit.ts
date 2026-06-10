/**
 * ═══════════════════════════════════════════════════════════════════
 * Rate Limiting Middleware
 * ═══════════════════════════════════════════════════════════════════
 *
 * Two limiters:
 *
 * 1. authLimiter — applied to POST /auth/login only
 *    → 5 requests per 15 minutes per IP
 *    → Prevents brute-force password guessing (combined with Argon2id slowness)
 *
 * 2. standardLimiter — applied to ALL routes
 *    → 100 requests per 15 minutes per IP
 *    → Prevents general API abuse and scraping
 *
 * Both return a consistent JSON error body (never HTML) so clients can
 * parse the error programmatically.
 *
 * NOTE: In-memory store. For multi-instance deployments, upgrade to
 * rate-limit-redis or rate-limit-mongo to share state across instances.
 * ═══════════════════════════════════════════════════════════════════
 */

import rateLimit from "express-rate-limit";

const WINDOW_MS = 15 * 60 * 1000; // 15 minutes in milliseconds

/**
 * Auth limiter: 5 requests per 15 minutes per IP.
 *
 * Applied only to POST /auth/login. This is intentionally very strict:
 * legitimate users who forgot their password will be rate-limited, but
 * that's an acceptable trade-off vs allowing brute-force attacks.
 *
 * The Argon2id KDF (64 MiB, 3 iterations) already makes each guess
 * expensive client-side, but the server can't verify that — so we
 * rate-limit at the HTTP layer too.
 */
export const authLimiter = rateLimit({
  windowMs: WINDOW_MS,
  max: 5,
  standardHeaders: true,  // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false,   // Disable the `X-RateLimit-*` headers
  message: {
    error: "Too many attempts. Try again in 15 minutes.",
  },
  // Skip successful requests — only count failed ones
  // (rate limit only applies when someone is hammering the endpoint)
  skipSuccessfulRequests: false,
});

/**
 * Standard limiter: 100 requests per 15 minutes per IP.
 *
 * Applied globally to all routes. Prevents API scraping and general abuse.
 * 100 requests / 15 minutes is generous enough for legitimate use (including
 * the extension checking autofill credentials) but blocks automated tools.
 */
export const standardLimiter = rateLimit({
  windowMs: WINDOW_MS,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "Too many attempts. Try again in 15 minutes.",
  },
});
