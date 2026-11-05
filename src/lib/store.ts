import { promises as fs } from "fs";
import path from "path";
import { connection } from "next/server";
import { DB_PATH, DATA_DIR, MEDIA_DIR, UPLOADS_DIR } from "./paths";
import type { ScanProgress, StoreApp, StoreDatabase } from "./types";
import { seedApps } from "./seed";

/**
 * JSON-backed store with an in-memory cache.
 *
 * - The database is read from disk once per process, then served from memory.
 * - Mutations are applied synchronously to the cache (no interleaving between
 *   read-modify-write steps) and persisted to disk via an atomic tmp+rename.
 * - Concurrent persist requests are coalesced into a single write.
 *
 * State lives on globalThis because Next.js may bundle route handlers into
 * separate module instances; a module-level cache would diverge between them.
 */

interface StoreState {
  db: StoreDatabase | null;
  loading: Promise<StoreDatabase> | null;
  dirsReady: Promise<void> | null;
  writing: Promise<void> | null;
  dirty: boolean;
}

const g = globalThis as typeof globalThis & { __vibeStore?: StoreState };
const state: StoreState = (g.__vibeStore ??= {
  db: null,
  loading: null,
  dirsReady: null,
  writing: null,
  dirty: false,
});

function ensureDirs(): Promise<void> {
  state.dirsReady ??= Promise.all(
    [DATA_DIR, UPLOADS_DIR, MEDIA_DIR].map((d) =>
      fs.mkdir(d, { recursive: true }),
    ),
  ).then(() => undefined).catch((err) => {
    state.dirsReady = null;
    throw err;
  });
  return state.dirsReady;
}

function normalizeApp(app: StoreApp): StoreApp {
  return {
    ...app,
    ownerKeyHash: undefined,
    features: Array.isArray(app.features) ? app.features : [],
    screenshots: Array.isArray(app.screenshots) ? app.screenshots : [],
  };
}

/**
 * Upload files are always stored directly in UPLOADS_DIR. Re-anchoring the
 * stored path on load means a moved data directory (new volume mount path,
 * different container root) keeps working without a data migration.
 */
function reanchorPaths(db: StoreDatabase): void {
  for (const app of db.apps) {
    if (app.filePath) {
      app.filePath = uploadPathFor(path.basename(app.filePath));
    }
  }
}

/**
 * Apps whose scan was interrupted by a restart must not stay stuck in
 * "scanning" (downloads would return 409 forever). If a previous scan report
 * exists, restore the status it implied; otherwise leave "scanning" so the
 * app page re-runs the scan automatically.
 */
function recoverInterruptedScans(db: StoreDatabase): number {
  let recovered = 0;
  for (const app of db.apps) {
    if (app.status !== "scanning" && app.status !== "queued") continue;
    recovered += 1;
    if (app.scan) {
      const readiness = app.scan.readiness;
      app.status =
        readiness === "blocked"
          ? "rejected"
          : readiness === "needs_fixes"
            ? "quarantined"
            : "published";
    } else {
      app.status = "scanning";
    }
    app.scanProgress = {
      phase: "error",
      label: "Scan interrupted by a restart — open the app page to run it again",
      percent: 0,
      engines: [],
      error: "interrupted by restart",
      updatedAt: new Date().toISOString(),
    };
  }
  return recovered;
}

async function loadDb(): Promise<StoreDatabase> {
  if (state.db) return state.db;
  state.loading ??= (async () => {
    await ensureDirs();
    let db: StoreDatabase;
    try {
      db = JSON.parse(await fs.readFile(DB_PATH, "utf8")) as StoreDatabase;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      // Only a missing file means "first run". A corrupt file must NOT be
      // silently replaced by an empty catalog — that would wipe real data.
      if (code !== "ENOENT") throw err;
      db = { apps: seedApps() };
      console.warn(`[store] no store.json at ${DB_PATH}: starting with an empty catalog`);
    }
    reanchorPaths(db);
    const recovered = recoverInterruptedScans(db);
    state.db = db;
    if (recovered > 0) {
      console.warn(`[store] recovered ${recovered} app(s) with interrupted scans`);
    }
    await schedulePersist();
    const storage = await storageStatus();
    if (!storage.persistent) {
      console.error(
        `[store] WARNING: DATA_DIR ${DATA_DIR} is NOT on a persistent volume — uploads and catalog will be lost on redeploy. Attach a Railway volume (mount path /data).`,
      );
    }
    return db;
  })().finally(() => {
    state.loading = null;
  });
  return state.loading;
}

/**
 * Whether DATA_DIR is on separate storage. On Railway, RAILWAY_VOLUME_MOUNT_PATH
 * is set when a volume is attached; a mount point also has a different device
 * id than its parent directory. Used by /api/health and the boot warning.
 */
export async function storageStatus(): Promise<{
  dataDir: string;
  persistent: boolean;
  appCount: number | null;
}> {
  let persistent = false;
  try {
    const [here, parent] = await Promise.all([
      fs.stat(DATA_DIR),
      fs.stat(path.dirname(DATA_DIR)),
    ]);
    persistent = here.dev !== parent.dev;
  } catch {
    persistent = false;
  }
  const mount = process.env.RAILWAY_VOLUME_MOUNT_PATH?.trim();
  if (mount && path.resolve(mount) === DATA_DIR) persistent = true;
  return {
    dataDir: DATA_DIR,
    persistent,
    appCount: state.db ? state.db.apps.length : null,
  };
}

async function writeAtomic(db: StoreDatabase): Promise<void> {
  await ensureDirs();
  // Keep the previous version as a backup, so one bad write cannot lose the catalog.
  await fs.copyFile(DB_PATH, `${DB_PATH}.bak`).catch(() => undefined);
  const tmp = `${DB_PATH}.${process.pid}.${Date.now()}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(db), "utf8");
  await fs.rename(tmp, DB_PATH);
}

/**
 * Persist the cached database. Calls that arrive while a write is in flight
 * mark the state dirty and share the same writer loop, so bursts of progress
 * updates collapse into a handful of disk writes.
 */
function schedulePersist(): Promise<void> {
  state.dirty = true;
  state.writing ??= (async () => {
    try {
      while (state.dirty && state.db) {
        state.dirty = false;
        await writeAtomic(state.db);
      }
    } finally {
      state.writing = null;
    }
  })();
  return state.writing;
}

/** Read-only access to the cached database (never mutate the returned object). */
async function readOnlyDb(): Promise<StoreDatabase> {
  await connection();
  return loadDb();
}

export async function listApps(opts?: {
  status?: StoreApp["status"] | "all";
  q?: string;
}): Promise<StoreApp[]> {
  const db = await readOnlyDb();
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
  const db = await readOnlyDb();
  const app = db.apps.find((a) => a.slug === slug);
  return app ? normalizeApp(app) : null;
}

export async function getAppById(id: string): Promise<StoreApp | null> {
  const db = await readOnlyDb();
  const app = db.apps.find((a) => a.id === id);
  return app ? normalizeApp(app) : null;
}

export async function upsertApp(app: StoreApp): Promise<StoreApp> {
  const db = await readOnlyDb();
  const idx = db.apps.findIndex((a) => a.id === app.id);
  if (idx >= 0) db.apps[idx] = app;
  else db.apps.unshift(app);
  await schedulePersist();
  return app;
}

export async function patchApp(
  id: string,
  patch: Partial<StoreApp>,
): Promise<StoreApp | null> {
  const db = await readOnlyDb();
  const idx = db.apps.findIndex((a) => a.id === id);
  if (idx < 0) return null;
  db.apps[idx] = {
    ...db.apps[idx],
    ...patch,
    updatedAt: new Date().toISOString(),
  };
  const updated = { ...db.apps[idx] };
  await schedulePersist();
  return updated;
}

/**
 * Progress ticks are frequent and only matter to a live poller, so they update
 * memory immediately and persist in the background (coalesced).
 */
export async function updateScanProgress(
  id: string,
  scanProgress: ScanProgress,
): Promise<void> {
  const db = await readOnlyDb();
  const idx = db.apps.findIndex((a) => a.id === id);
  if (idx < 0) return;
  db.apps[idx] = {
    ...db.apps[idx],
    scanProgress,
    status: "scanning",
    updatedAt: new Date().toISOString(),
  };
  void schedulePersist().catch((err) => {
    console.error("[store] progress persist failed", err);
  });
}

export async function bumpDownloads(id: string): Promise<void> {
  const db = await readOnlyDb();
  const app = db.apps.find((a) => a.id === id);
  if (!app) return;
  app.downloads += 1;
  app.updatedAt = new Date().toISOString();
  void schedulePersist().catch((err) => {
    console.error("[store] download counter persist failed", err);
  });
}

export async function deleteApp(id: string): Promise<boolean> {
  const db = await readOnlyDb();
  const idx = db.apps.findIndex((a) => a.id === id);
  if (idx < 0) return false;
  const app = db.apps[idx];
  db.apps.splice(idx, 1);
  await schedulePersist();

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
