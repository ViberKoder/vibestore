import { randomBytes } from "crypto";
import type { StoreApp } from "./types";

export const DEV_COOKIE = "vibe_dev";
const DEV_TTL_SEC = 60 * 60 * 24 * 365; // 1 year

export function mintDeveloperId(): string {
  return `dev_${randomBytes(18).toString("base64url")}`;
}

export function readDeveloperId(cookieHeader: string | null): string | null {
  if (!cookieHeader) return null;
  const match = cookieHeader
    .split(";")
    .map((p) => p.trim())
    .find((p) => p.startsWith(`${DEV_COOKIE}=`));
  if (!match) return null;
  const value = decodeURIComponent(match.slice(DEV_COOKIE.length + 1)).trim();
  return /^dev_[A-Za-z0-9_-]{10,}$/.test(value) ? value : null;
}

export function developerCookieHeader(
  devId: string,
  reqHost?: string | null,
): string {
  const parts = [
    `${DEV_COOKIE}=${encodeURIComponent(devId)}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    `Max-Age=${DEV_TTL_SEC}`,
  ];
  // trycloudflare.com is a public suffix — Domain= cannot span subdomains.
  // Still mark Secure on https tunnel hosts.
  const host = (reqHost ?? "").split(":")[0].toLowerCase();
  const https =
    host.endsWith(".trycloudflare.com") ||
    process.env.NODE_ENV === "production";
  if (https) parts.push("Secure");
  return parts.join("; ");
}

export function requestHost(req: Request): string | null {
  return req.headers.get("x-forwarded-host") ?? req.headers.get("host");
}

export function isAppOwner(
  app: Pick<StoreApp, "ownerId">,
  cookieHeader: string | null,
): boolean {
  const devId = readDeveloperId(cookieHeader);
  return Boolean(devId && app.ownerId && devId === app.ownerId);
}

export function normalizeDevName(name: string): string {
  return name.trim().toLowerCase().replace(/\s+/g, " ");
}

export function developerNameMatches(
  app: Pick<StoreApp, "developerName">,
  input: string,
): boolean {
  const expect = normalizeDevName(app.developerName ?? "");
  const got = normalizeDevName(input);
  return Boolean(expect && got && expect === got);
}

export type PublicStoreApp = Omit<
  StoreApp,
  "ownerKeyHash" | "filePath" | "ownerId"
> & {
  hasOwner: boolean;
  isOwner?: boolean;
  /** Non-owners can restore by typing the developer name */
  canRestore?: boolean;
};

/** Safe app payload — no disk paths / internal owner id. */
export function toPublicApp(
  app: StoreApp,
  opts?: { isOwner?: boolean },
): PublicStoreApp {
  const isOwner = Boolean(opts?.isOwner);
  return {
    id: app.id,
    slug: app.slug,
    name: app.name,
    tagline: app.tagline,
    description: app.description,
    kind: app.kind,
    category: app.category,
    developerName: app.developerName,
    developerEmail: app.developerEmail,
    version: app.version,
    homepage: app.homepage,
    tags: app.tags,
    features: app.features ?? [],
    screenshots: app.screenshots ?? [],
    status: app.status,
    createdAt: app.createdAt,
    updatedAt: app.updatedAt,
    fileName: app.fileName,
    fileSize: app.fileSize,
    mimeType: app.mimeType,
    sha256: app.sha256,
    downloads: app.downloads,
    iconHue: app.iconHue,
    iconUrl: app.iconUrl,
    scan: app.scan,
    scanProgress: app.scanProgress,
    hasOwner: Boolean(app.ownerId),
    isOwner,
    canRestore: Boolean(app.ownerId) && !isOwner,
  };
}
