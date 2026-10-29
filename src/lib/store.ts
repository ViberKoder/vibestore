import { promises as fs } from "fs";
import path from "path";
import { connection } from "next/server";
import {
  hashOwnerKey,
  mintOwnerKey,
  rememberLegacyOwnerKey,
} from "./owner-auth";
import { DB_PATH, DATA_DIR, MEDIA_DIR, UPLOADS_DIR } from "./paths";
import type { ScanProgress, StoreApp, StoreDatabase } from "./types";
import { seedApps } from "./seed";

async function ensureDirs() {
  await fs.mkdir(DATA_DIR, { recursive: true });
  await fs.mkdir(UPLOADS_DIR, { recursive: true });
  await fs.mkdir(MEDIA_DIR, { recursive: true });
}

function normalizeApp(app: StoreApp): StoreApp {
  return {
    ...app,
    features: Array.isArray(app.features) ? app.features : [],
    screenshots: Array.isArray(app.screenshots) ? app.screenshots : [],
  };
}

/** Ensure every app has an owner key hash; legacy apps get keys saved once. */
async function ensureOwnerKeys(db: StoreDatabase): Promise<StoreDatabase> {
  let changed = false;
  for (const app of db.apps) {
    if (app.ownerKeyHash) continue;
    const key = mintOwnerKey();
    app.ownerKeyHash = hashOwnerKey(key);
    await rememberLegacyOwnerKey(app.id, app.slug, key);
    changed = true;
  }
  if (changed) await writeDb(db);
  return db;
}

async function readDb(): Promise<StoreDatabase> {
  await connection();
  await ensureDirs();
  try {
    const raw = await fs.readFile(DB_PATH, "utf8");
    const db = JSON.parse(raw) as StoreDatabase;
    return ensureOwnerKeys(db);
  } catch {
    const seeded: StoreDatabase = { apps: seedApps() };
    await writeDb(seeded);
    return seeded;
  }
}

async function writeDb(db: StoreDatabase) {
  await ensureDirs();
  await fs.writeFile(DB_PATH, JSON.stringify(db, null, 2), "utf8");
}

export async function listApps(opts?: {
  status?: StoreApp["status"] | "all";
  q?: string;
}): Promise<StoreApp[]> {
  const db = await readDb();
  let apps = db.apps.map(normalizeApp).sort(
    (a, b) => +new Date(b.updatedAt) - +new Date(a.updatedAt),
  );

  if (opts?.status && opts.status !== "all") {
    apps = apps.filter((a) => a.status === opts.status);
  }

  if (opts?.q?.trim()) {
    const q = opts.q.trim().toLowerCase();
    apps = apps.filter(
      (a) =>
        a.name.toLowerCase().includes(q) ||
        a.tagline.toLowerCase().includes(q) ||
        a.developerName.toLowerCase().includes(q) ||
        a.tags.some((t) => t.toLowerCase().includes(q)) ||
        a.category.toLowerCase().includes(q),
    );
  }

  return apps;
}

export async function getAppBySlug(slug: string): Promise<StoreApp | null> {
  const db = await readDb();
  const app = db.apps.find((a) => a.slug === slug);
  return app ? normalizeApp(app) : null;
}

export async function getAppById(id: string): Promise<StoreApp | null> {
  const db = await readDb();
  const app = db.apps.find((a) => a.id === id);
  return app ? normalizeApp(app) : null;
}

export async function upsertApp(app: StoreApp): Promise<StoreApp> {
  const db = await readDb();
  const idx = db.apps.findIndex((a) => a.id === app.id);
  if (idx >= 0) db.apps[idx] = app;
  else db.apps.unshift(app);
  await writeDb(db);
  return app;
}

export async function patchApp(
  id: string,
  patch: Partial<StoreApp>,
): Promise<StoreApp | null> {
  const db = await readDb();
  const idx = db.apps.findIndex((a) => a.id === id);
  if (idx < 0) return null;
  db.apps[idx] = {
    ...db.apps[idx],
    ...patch,
    updatedAt: new Date().toISOString(),
  };
  await writeDb(db);
  return db.apps[idx];
}

export async function updateScanProgress(
  id: string,
  scanProgress: ScanProgress,
): Promise<void> {
  await patchApp(id, { scanProgress, status: "scanning" });
}

export async function bumpDownloads(id: string): Promise<void> {
  const db = await readDb();
  const app = db.apps.find((a) => a.id === id);
  if (!app) return;
  app.downloads += 1;
  app.updatedAt = new Date().toISOString();
  await writeDb(db);
}

export async function deleteApp(id: string): Promise<boolean> {
  const db = await readDb();
  const idx = db.apps.findIndex((a) => a.id === id);
  if (idx < 0) return false;
  const app = db.apps[idx];
  db.apps.splice(idx, 1);
  await writeDb(db);

  if (app.filePath) {
    await fs.unlink(app.filePath).catch(() => undefined);
  }
  const mediaDir = mediaDirFor(app.id);
  await fs.rm(mediaDir, { recursive: true, force: true }).catch(() => undefined);
  return true;
}

export function uploadPathFor(fileName: string): string {
  return path.join(UPLOADS_DIR, fileName);
}

export function mediaDirFor(appId: string): string {
  return path.join(MEDIA_DIR, appId);
}

export function mediaPathFor(appId: string, fileName: string): string {
  return path.join(MEDIA_DIR, appId, fileName);
}

export { UPLOADS_DIR, MEDIA_DIR };
