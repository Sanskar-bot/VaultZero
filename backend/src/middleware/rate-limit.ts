/**
 * Rate Limiting Middleware
 *
 * Protects against brute-force attacks:
 * - 5 failed login attempts → 15-minute lockout per IP
 * - General API rate limit: 100 requests per 15 minutes per IP
 *
 * Uses express-rate-limit with in-memory store (upgrade to Redis for multi-instance).
 *
 * Implementation: Day 4
 */

// TODO: Day 4 — implement loginRateLimiter and generalRateLimiter
