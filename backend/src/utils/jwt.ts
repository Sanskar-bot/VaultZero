/**
 * JWT Utility — thin wrappers around jsonwebtoken
 *
 * The actual signing/verifying logic lives in auth.service.ts.
 * This file re-exports helpers for any future code that needs
 * standalone JWT operations (e.g. socket auth, CLI tools).
 */

export { verifyJWT } from "../middleware/auth";
export type { JWTPayload } from "../middleware/auth";
