import { lookup as dnsLookup, type LookupAddress } from "dns";
import { isIP } from "net";
import http from "http";
import https from "https";

/**
 * Outbound HTTP for user-supplied URLs (website checks, GitHub archives).
 *
 * SSRF defence: every connection resolves its host through `safeLookup`, which
 * refuses non-public addresses at connect time. Checking the URL once before the
 * request would miss DNS rebinding, so the check lives in the socket layer.
 */

export function isPublicAddress(ip: string): boolean {
  const v = ip.toLowerCase();
  const mapped = v.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isPublicAddress(mapped[1]);

  if (/^\d+\.\d+\.\d+\.\d+$/.test(v)) {
    const [a, b, c] = v.split(".").map(Number);
    if (a === 0 || a === 10 || a === 127) return false;
    if (a === 100 && b >= 64 && b <= 127) return false; // CGNAT
    if (a === 169 && b === 254) return false; // link-local / metadata
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 0 && c === 0) return false;
    if (a === 192 && b === 168) return false;
    if (a === 198 && (b === 18 || b === 19)) return false;
    if (a >= 224) return false; // multicast + reserved
    return true;
  }

  // IPv6
  if (v === "::" || v === "::1") return false;
  if (/^f[cd]/.test(v)) return false; // fc00::/7 unique local
  if (/^fe[89ab]/.test(v)) return false; // fe80::/10 link-local
  if (v.startsWith("ff")) return false; // multicast
  if (v.startsWith("2001:db8")) return false; // documentation
  return true;
}

export function safeLookup(
  hostname: string,
  options: { all?: boolean; family?: number } | number | undefined,
  callback: (err: NodeJS.ErrnoException | null, address?: unknown, family?: number) => void,
) {
  const opts = typeof options === "number" ? { family: options } : options ?? {};
  dnsLookup(hostname, { all: true, family: opts.family }, (err, addresses: LookupAddress[]) => {
    if (err) return callback(err);
    const ok = addresses.filter((a) => isPublicAddress(a.address));
    if (!ok.length) {
      const e = new Error(`Blocked: ${hostname} resolves only to non-public addresses`) as NodeJS.ErrnoException;
      e.code = "EBLOCKED";
      return callback(e);
    }
    if (opts.all) return callback(null, ok);
    return callback(null, ok[0].address, ok[0].family);
  });
}

export interface PublicFetchOptions {
  method?: "GET" | "HEAD";
  headers?: Record<string, string>;
  maxBytes: number;
  timeoutMs: number;
  maxRedirects?: number;
  allowHosts?: (host: string) => boolean;
}

export interface PublicFetchResult {
  status: number;
  headers: http.IncomingHttpHeaders;
  body: Buffer;
  finalUrl: string;
  redirects: string[];
  truncated: boolean;
}

const ALLOWED_PORTS = new Set(["", "80", "443"]);

export function parsePublicUrl(raw: string): URL {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new Error("Not a valid URL");
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") throw new Error("Only http and https URLs are supported");
  if (u.username || u.password) throw new Error("URLs with credentials are not allowed");
  if (!ALLOWED_PORTS.has(u.port)) throw new Error("Only ports 80 and 443 are allowed");
  // Node skips the lookup hook for IP literals, so they must never reach the socket layer.
  if (u.hostname.startsWith("[") || isIP(u.hostname)) {
    throw new Error("Use a domain name, not an IP address");
  }
  if (!u.hostname.includes(".") || u.hostname.endsWith(".local") || u.hostname.endsWith(".internal")) {
    throw new Error("Host must be a public domain name");
  }
  if (u.href.length > 2048) throw new Error("URL is too long");
  return u;
}

function requestOnce(
  url: URL,
  opts: PublicFetchOptions,
  headers: Record<string, string> | undefined,
): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: Buffer; truncated: boolean }> {
  return new Promise((resolve, reject) => {
    const mod = url.protocol === "https:" ? https : http;
    const req = mod.request(
      url,
      {
        method: opts.method ?? "GET",
        headers: {
          "User-Agent": "VibeStoreChecker/1.0 (+security scan)",
          Accept: "*/*",
          ...(headers ?? {}),
        },
        lookup: safeLookup as never,
        timeout: opts.timeoutMs,
      },
      (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        let truncated = false;
        res.on("data", (c: Buffer) => {
          size += c.length;
          if (size > opts.maxBytes) {
            truncated = true;
            res.destroy();
            const keep = Buffer.concat(chunks);
            resolve({ status: res.statusCode ?? 0, headers: res.headers, body: keep.subarray(0, opts.maxBytes), truncated });
            return;
          }
          chunks.push(c);
        });
        res.on("end", () => {
          if (!truncated) {
            resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks), truncated: false });
          }
        });
        res.on("error", (err) => {
          if (!truncated) reject(err);
        });
      },
    );
    req.on("timeout", () => req.destroy(new Error("Timed out")));
    req.on("error", reject);
    req.end();
  });
}

/** GET a public URL, following redirects with the SSRF check on every hop. */
export async function fetchPublic(startUrl: string | URL, opts: PublicFetchOptions): Promise<PublicFetchResult> {
  let url = startUrl instanceof URL ? startUrl : parsePublicUrl(startUrl);
  const startHost = url.hostname;
  const redirects: string[] = [];
  const max = opts.maxRedirects ?? 5;
  for (let hop = 0; ; hop++) {
    if (opts.allowHosts && !opts.allowHosts(url.hostname)) {
      throw new Error(`Host not allowed: ${url.hostname}`);
    }
    // Credentials (Authorization) only ever go to the host the caller asked for.
    const res = await requestOnce(url, opts, url.hostname === startHost ? opts.headers : undefined);
    if ([301, 302, 303, 307, 308].includes(res.status) && res.headers.location) {
      if (hop >= max) throw new Error("Too many redirects");
      const next = new URL(res.headers.location, url);
      redirects.push(next.href);
      url = parsePublicUrl(next.href);
      continue;
    }
    return { status: res.status, headers: res.headers, body: res.body, finalUrl: url.href, redirects, truncated: res.truncated };
  }
}
