/**
 * JWT Utility — sign, verify, and decode tokens
 *
 * Token structure:
 * - Access token: { userId, type: "access" }, expires in 15 minutes
 * - Refresh token: random 64 bytes, stored as SHA-256 hash in DB
 *
 * Implementation: Day 4
 */

// TODO: Day 4 — implement signAccessToken, verifyAccessToken, generateRefreshToken
