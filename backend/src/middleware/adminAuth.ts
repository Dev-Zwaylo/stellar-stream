import { timingSafeEqual } from "node:crypto";
import { Request, Response, NextFunction } from "express";

/**
 * Validates a presented admin key against the configured ADMIN_API_KEY.
 *
 * The configured key is read exactly once per call, so a key rotation that
 * happens concurrently can never produce a mixed/partial comparison: a request
 * is judged entirely against either the old or the new key. Missing, empty,
 * non-string (e.g. repeated header / object body) and wrong-length keys are
 * all rejected without throwing. A rejected request has no side effects, so
 * clients can safely retry with the rotated key.
 */
export function isValidAdminKey(presented: unknown): boolean {
  const configured = process.env.ADMIN_API_KEY;
  if (typeof presented !== "string" || presented.length === 0) return false;
  if (typeof configured !== "string" || configured.length === 0) return false;
  const a = Buffer.from(presented);
  const b = Buffer.from(configured);
  return a.length === b.length && timingSafeEqual(a, b);
}

export function adminAuth(req: Request, res: Response, next: NextFunction) {
  if (!isValidAdminKey(req.header("X-Admin-Key"))) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  next();
}