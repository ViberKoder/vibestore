import { createHash, createHmac, randomBytes, timingSafeEqual } from "crypto";
import { promises as fs } from "fs";
import path from "path";
import { DATA_DIR } from "./paths";
import type { StoreApp } from "./types";

const SECRET_FILE = path.join(DATA_DIR, "owner-secret.txt");
const LEGACY_KEYS_FILE = path.join(DATA_DIR, "owner-keys.json");
const SESSION_TTL_SEC = 60 * 60 * 24 * 30; // 30 days
const COOKIE_PREFIX = "vibe_own_";

let cachedSecret: string | null = null;

async function getSecret(): Promise<string> {
  if (cachedSecret) return cachedSecret;
  if (process.env.VIBE_OWNER_SECRET?.trim()) {
    cachedSecret = process.env.VIBE_OWNER_SECRET.trim();
    return cachedSecret;
  }
  try {
    const existing = (await fs.readFile(SECRET_FILE, "utf8")).trim();
    if (existing.length >= 24) {
      cachedSecret = existing;
      return cachedSecret;
    }
  } catch {
    /* create below */
  }
  await fs.mkdir(DATA_DIR, { recursive: true });
  const generated = randomBytes(32).toString("hex");
  await fs.writeFile(SECRET_FILE, generated, { mode: 0o600 });
  cachedSecret = generated;
  return cachedSecret;
}

export function mintOwnerKey(): string {
  return `vsk_${randomBytes(24).toString("base64url")}`;
}

export function hashOwnerKey(key: string): string {
  return createHash("sha256").update(key.trim(), "utf8").digest("hex");
}

export function verifyOwnerKey(key: string, hash: string | undefined): boolean {
  if (!hash || !key?.trim()) return false;
  const got = Buffer.from(hashOwnerKey(key), "utf8");
  const expect = Buffer.from(hash, "utf8");
  if (got.length !== expect.length) return false;
  return timingSafeEqual(got, expect);
}

function cookieNameFor(appId: string): string {
  const id = createHash("sha256").update(appId).digest("hex").slice(0, 20);
  return `${COOKIE_PREFIX}${id}`;
}

async function signSession(appId: string, exp: number): Promise<string> {
  const secret = await getSecret();
  const payload = `${appId}.${exp}`;
  const sig = createHmac("sha256", secret).update(payload).digest("base64url");
  return `${payload}.${sig}`;
}

export async function verifyOwnerSession(
  appId: string,
  cookieHeader: string | null,
): Promise<boolean> {
  if (!cookieHeader) return false;
  const name = cookieNameFor(appId);
  const match = cookieHeader
    .split(";")
    .map((p) => p.trim())
    .find((p) => p.startsWith(`${name}=`));
  if (!match) return false;
  const token = decodeURIComponent(match.slice(name.length + 1));
  const parts = token.split(".");
  if (parts.length !== 3) return false;
  const [id, expStr, sig] = parts;
  if (id !== appId) return false;
  const exp = Number(expStr);
  if (!Number.isFinite(exp) || exp * 1000 < Date.now()) return false;
  const secret = await getSecret();
  const expect = createHmac("sha256", secret)
    .update(`${id}.${exp}`)
    .digest("base64url");
  const a = Buffer.from(sig);
  const b = Buffer.from(expect);
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

export async function ownerSessionCookie(
  appId: string,
): Promise<{ name: string; value: string; maxAge: number }> {
  const exp = Math.floor(Date.now() / 1000) + SESSION_TTL_SEC;
  const value = await signSession(appId, exp);
  return {
    name: cookieNameFor(appId),
    value,
    maxAge: SESSION_TTL_SEC,
  };
}

export function clearOwnerSessionCookie(appId: string): {
  name: string;
  value: string;
  maxAge: number;
} {
  return { name: cookieNameFor(appId), value: "", maxAge: 0 };
}

export type PublicStoreApp = Omit<StoreApp, "ownerKeyHash" | "filePath"> & {
  hasOwnerKey: boolean;
};

/** Safe app payload for clients / JSON APIs — no owner secrets or disk paths. */
export function toPublicApp(app: StoreApp): PublicStoreApp {
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
    hasOwnerKey: Boolean(app.ownerKeyHash),
  };
}

export async function rememberLegacyOwnerKey(
  appId: string,
  slug: string,
  key: string,
): Promise<void> {
  await fs.mkdir(DATA_DIR, { recursive: true });
  let map: Record<string, { slug: string; key: string; createdAt: string }> = {};
  try {
    map = JSON.parse(await fs.readFile(LEGACY_KEYS_FILE, "utf8")) as typeof map;
  } catch {
    map = {};
  }
  if (map[appId]) return;
  map[appId] = {
    slug,
    key,
    createdAt: new Date().toISOString(),
  };
  await fs.writeFile(LEGACY_KEYS_FILE, JSON.stringify(map, null, 2), {
    mode: 0o600,
  });
}

export function setOwnerCookieHeader(opts: {
  name: string;
  value: string;
  maxAge: number;
}): string {
  const parts = [
    `${opts.name}=${encodeURIComponent(opts.value)}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    `Max-Age=${opts.maxAge}`,
  ];
  if (process.env.NODE_ENV === "production") parts.push("Secure");
  return parts.join("; ");
}
