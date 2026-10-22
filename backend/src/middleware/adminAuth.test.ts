import { afterEach, describe, expect, it, vi } from "vitest";
import { adminAuth, isValidAdminKey } from "./adminAuth";

const original = process.env.ADMIN_API_KEY;
afterEach(() => {
  if (original === undefined) delete process.env.ADMIN_API_KEY;
  else process.env.ADMIN_API_KEY = original;
});

function run(key: unknown) {
  const req: any = { header: () => key };
  const res: any = { status: vi.fn().mockReturnThis(), json: vi.fn() };
  const next = vi.fn();
  adminAuth(req, res, next);
  return { res, next };
}

describe("admin key validation", () => {
  it("rejects missing, empty and malformed keys without throwing", () => {
    process.env.ADMIN_API_KEY = "secret";
    for (const bad of [undefined, "", "short", "secret-longer", ["secret"], { a: 1 }, 123]) {
      expect(isValidAdminKey(bad)).toBe(false);
    }
  });

  it("rejects everything when no key is configured", () => {
    delete process.env.ADMIN_API_KEY;
    expect(isValidAdminKey(undefined)).toBe(false);
    expect(isValidAdminKey("anything")).toBe(false);
    process.env.ADMIN_API_KEY = "";
    expect(isValidAdminKey("")).toBe(false);
  });

  it("accepts the current key and rejects the old one after rotation", () => {
    process.env.ADMIN_API_KEY = "old-key";
    expect(run("old-key").next).toHaveBeenCalledTimes(1);
    process.env.ADMIN_API_KEY = "new-key";
    const stale = run("old-key");
    expect(stale.next).not.toHaveBeenCalled();
    expect(stale.res.status).toHaveBeenCalledWith(401);
    expect(run("new-key").next).toHaveBeenCalledTimes(1);
  });

  it("interleaved requests across rotation are each judged consistently and retry is side-effect free", () => {
    process.env.ADMIN_API_KEY = "old-key";
    const first = run("old-key");
    process.env.ADMIN_API_KEY = "new-key";
    const second = run("old-key"); // rejected: nothing executed
    const retry = run("new-key"); // client retries with rotated key
    expect(first.next).toHaveBeenCalledTimes(1);
    expect(second.next).not.toHaveBeenCalled();
    expect(retry.next).toHaveBeenCalledTimes(1); // handler runs exactly once
  });
});
