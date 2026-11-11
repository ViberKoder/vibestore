/**
 * Fixed-window rate limiter, in memory (per process). Good enough for a single
 * instance; state lives on globalThis so separately bundled route handlers share it.
 */
interface Bucket {
  count: number;
  resetAt: number;
}

const g = globalThis as typeof globalThis & { __vibeRate?: Map<string, Bucket> };
const buckets = (g.__vibeRate ??= new Map<string, Bucket>());

export function clientIp(req: Request): string {
  // Behind Railway/Cloudflare the first X-Forwarded-For entry is the client.
  const fwd = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  return fwd || req.headers.get("x-real-ip") || "unknown";
}

/** Returns null when allowed, or the seconds to wait. */
export function rateLimit(key: string, limit: number, windowMs: number): number | null {
  const now = Date.now();
  if (buckets.size > 10_000) {
    for (const [k, b] of buckets) if (b.resetAt <= now) buckets.delete(k);
  }
  const b = buckets.get(key);
  if (!b || b.resetAt <= now) {
    buckets.set(key, { count: 1, resetAt: now + windowMs });
    return null;
  }
  if (b.count >= limit) return Math.ceil((b.resetAt - now) / 1000);
  b.count += 1;
  return null;
}

export const LIMITS = {
  publish: { limit: 20, windowMs: 60 * 60_000 },
  scan: { limit: 60, windowMs: 60 * 60_000 },
  checkUrl: { limit: 30, windowMs: 60 * 60_000 },
  importRepo: { limit: 15, windowMs: 60 * 60_000 },
} as const;

export function limitRequest(req: Request, name: keyof typeof LIMITS): Response | null {
  const { limit, windowMs } = LIMITS[name];
  const wait = rateLimit(`${name}:${clientIp(req)}`, limit, windowMs);
  if (wait === null) return null;
  return new Response(
    JSON.stringify({ error: `Too many requests. Try again in ${Math.ceil(wait / 60)} min.` }),
    {
      status: 429,
      headers: { "Content-Type": "application/json", "Retry-After": String(wait) },
    },
  );
}
