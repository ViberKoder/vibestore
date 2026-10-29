import { promises as fs } from "fs";
import path from "path";
import { createHash, randomBytes } from "crypto";
import { NextResponse } from "next/server";
import { createWriteStream } from "fs";
import { Readable } from "stream";
import { pipeline } from "stream/promises";
import {
  deleteApp,
  getAppById,
  getAppBySlug,
  mediaDirFor,
  patchApp,
  uploadPathFor,
} from "@/lib/store";
import {
  isAppOwner,
  toPublicApp,
} from "@/lib/owner-auth";
import { initialScanProgress } from "@/lib/scanners/pipeline";
import {
  MAX_FEATURES,
  MAX_SCREENSHOT_BYTES,
  MAX_SCREENSHOTS,
  MAX_UPLOAD_BYTES,
  type AppFeature,
  type AppKind,
  type AppScreenshot,
  type StoreApp,
} from "@/lib/types";

export const runtime = "nodejs";
export const maxDuration = 600;

const IMAGE_EXT = new Set([".png", ".jpg", ".jpeg", ".webp", ".gif"]);

const ALLOWED_BUILD_EXT = new Set([
  ".exe",
  ".msi",
  ".dll",
  ".zip",
  ".7z",
  ".rar",
  ".dmg",
  ".pkg",
  ".appimage",
  ".deb",
  ".rpm",
  ".html",
  ".htm",
  ".js",
  ".jar",
  ".apk",
  ".ipa",
  ".py",
  ".sh",
  ".bat",
  ".ps1",
  ".wasm",
  ".bin",
  ".com",
  ".txt",
  ".md",
  ".json",
  ".tar",
  ".gz",
  ".tgz",
]);

async function resolveApp(id: string) {
  return (await getAppById(id)) ?? (await getAppBySlug(id));
}

function denyUnlessOwner(req: Request, app: StoreApp): NextResponse | null {
  if (isAppOwner(app, req.headers.get("cookie"))) return null;
  if (!app.ownerId) {
    return NextResponse.json(
      {
        error:
          "Приложение ещё не привязано. Откройте «Управление» и нажмите «Это моё приложение».",
      },
      { status: 403 },
    );
  }
  return NextResponse.json(
    { error: "Только тот, кто загрузил приложение, может его менять." },
    { status: 403 },
  );
}

function parseFeatures(raw: string): AppFeature[] {
  return raw
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .slice(0, MAX_FEATURES)
    .map((line) => {
      const [title, ...rest] = line.split("|").map((s) => s.trim());
      return {
        title: title.slice(0, 80),
        detail: rest.join(" | ").slice(0, 240) || undefined,
      };
    })
    .filter((f) => f.title.length > 0);
}

async function saveBinary(
  file: File,
  dest: string,
): Promise<{ size: number; sha256: string }> {
  await fs.mkdir(path.dirname(dest), { recursive: true });
  const hash = createHash("sha256");
  let size = 0;
  const nodeReadable = Readable.fromWeb(
    file.stream() as import("stream/web").ReadableStream,
  );
  const out = createWriteStream(dest);
  nodeReadable.on("data", (chunk: Buffer | string) => {
    const buf = typeof chunk === "string" ? Buffer.from(chunk) : chunk;
    size += buf.length;
    hash.update(buf);
    if (size > MAX_UPLOAD_BYTES) nodeReadable.destroy(new Error("FILE_TOO_LARGE"));
  });
  try {
    await pipeline(nodeReadable, out);
  } catch (err) {
    await fs.unlink(dest).catch(() => undefined);
    throw err;
  }
  return { size, sha256: hash.digest("hex") };
}

async function saveIcon(appId: string, file: File): Promise<string | null> {
  if (file.size <= 0 || file.size > MAX_SCREENSHOT_BYTES) return null;
  const ext = path.extname(file.name).toLowerCase() || ".png";
  if (!IMAGE_EXT.has(ext)) return null;
  const dir = mediaDirFor(appId);
  await fs.mkdir(dir, { recursive: true });
  const existing = await fs.readdir(dir).catch(() => [] as string[]);
  for (const name of existing) {
    if (name.startsWith("icon.")) {
      await fs.unlink(path.join(dir, name)).catch(() => undefined);
    }
  }
  const stored = `icon${ext}`;
  await fs.writeFile(path.join(dir, stored), Buffer.from(await file.arrayBuffer()));
  return `/api/media/${appId}/${stored}`;
}

async function appendScreenshots(
  appId: string,
  files: File[],
  current: AppScreenshot[],
): Promise<AppScreenshot[]> {
  const room = Math.max(0, MAX_SCREENSHOTS - current.length);
  if (!room) return current;
  const dir = mediaDirFor(appId);
  await fs.mkdir(dir, { recursive: true });
  const next = [...current];
  for (const file of files.slice(0, room)) {
    if (file.size <= 0 || file.size > MAX_SCREENSHOT_BYTES) continue;
    const ext = path.extname(file.name).toLowerCase() || ".png";
    if (!IMAGE_EXT.has(ext)) continue;
    const id = `shot_${randomBytes(4).toString("hex")}`;
    const stored = `${id}${ext}`;
    await fs.writeFile(
      path.join(dir, stored),
      Buffer.from(await file.arrayBuffer()),
    );
    next.push({
      id,
      fileName: stored,
      url: `/api/media/${appId}/${stored}`,
      caption: file.name.replace(/\.[^.]+$/, "").slice(0, 80) || undefined,
    });
  }
  return next;
}

export async function GET(
  req: Request,
  ctx: { params: Promise<{ id: string }> },
) {
  const { id } = await ctx.params;
  const app = await resolveApp(id);
  if (!app) {
    return NextResponse.json({ error: "App not found" }, { status: 404 });
  }
  return NextResponse.json({
    app: toPublicApp(app, {
      isOwner: isAppOwner(app, req.headers.get("cookie")),
    }),
  });
}

export async function PATCH(
  req: Request,
  ctx: { params: Promise<{ id: string }> },
) {
  const { id } = await ctx.params;
  const app = await resolveApp(id);
  if (!app) {
    return NextResponse.json({ error: "App not found" }, { status: 404 });
  }

  const denied = denyUnlessOwner(req, app);
  if (denied) return denied;

  const contentType = req.headers.get("content-type") ?? "";
  const patch: Partial<StoreApp> = {};
  let rescan = false;

  if (contentType.includes("multipart/form-data")) {
    const form = await req.formData();

    const str = (key: string) => {
      const v = form.get(key);
      return typeof v === "string" ? v.trim() : undefined;
    };

    const name = str("name");
    const tagline = str("tagline");
    const description = str("description");
    const developerName = str("developerName");
    const developerEmail = str("developerEmail");
    const version = str("version");
    const category = str("category");
    const kind = str("kind") as AppKind | undefined;
    const homepage = str("homepage");
    const tagsRaw = str("tags");
    const featuresRaw = str("features");
    const clearIcon = str("clearIcon") === "1";
    const removeShotIds = str("removeScreenshotIds");

    if (name) patch.name = name.slice(0, 80);
    if (tagline) patch.tagline = tagline.slice(0, 160);
    if (description) patch.description = description.slice(0, 8000);
    if (developerName) patch.developerName = developerName.slice(0, 80);
    if (developerEmail !== undefined) {
      patch.developerEmail = developerEmail || undefined;
    }
    if (version) patch.version = version.slice(0, 40);
    if (category) patch.category = category.slice(0, 60);
    if (kind) patch.kind = kind;
    if (homepage !== undefined) patch.homepage = homepage || undefined;
    if (tagsRaw !== undefined) {
      patch.tags = tagsRaw
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean)
        .slice(0, 12);
    }
    if (featuresRaw !== undefined) {
      patch.features = parseFeatures(featuresRaw);
    }

    if (clearIcon) patch.iconUrl = undefined;

    const icon = form.get("icon");
    if (icon instanceof File && icon.size > 0) {
      const url = await saveIcon(app.id, icon);
      if (url) patch.iconUrl = url;
    }

    let shots = [...(app.screenshots ?? [])];
    if (removeShotIds) {
      const remove = new Set(
        removeShotIds
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
      );
      const dir = mediaDirFor(app.id);
      for (const s of shots) {
        if (!remove.has(s.id)) continue;
        await fs.unlink(path.join(dir, s.fileName)).catch(() => undefined);
      }
      shots = shots.filter((s) => !remove.has(s.id));
    }
    const newShots = form
      .getAll("screenshots")
      .filter((f): f is File => f instanceof File && f.size > 0);
    if (newShots.length) {
      shots = await appendScreenshots(app.id, newShots, shots);
    }
    if (removeShotIds !== undefined || newShots.length) {
      patch.screenshots = shots;
    }

    const build = form.get("file");
    if (build instanceof File && build.size > 0) {
      if (build.size > MAX_UPLOAD_BYTES) {
        return NextResponse.json(
          {
            error: `Файл слишком большой (макс. ${Math.round(MAX_UPLOAD_BYTES / 1024 / 1024)} МБ)`,
          },
          { status: 400 },
        );
      }
      const ext = path.extname(build.name).toLowerCase();
      if (ext && !ALLOWED_BUILD_EXT.has(ext)) {
        return NextResponse.json(
          { error: `Extension ${ext} is not allowed` },
          { status: 400 },
        );
      }
      const storedName = `${app.id}${ext || ".bin"}`;
      const filePath = uploadPathFor(storedName);
      if (app.filePath && app.filePath !== filePath) {
        await fs.unlink(app.filePath).catch(() => undefined);
      }
      try {
        const saved = await saveBinary(build, filePath);
        patch.fileName = build.name;
        patch.fileSize = saved.size;
        patch.mimeType = build.type || "application/octet-stream";
        patch.filePath = filePath;
        patch.sha256 = saved.sha256;
        patch.status = "scanning";
        patch.scanProgress = initialScanProgress();
        patch.scan = undefined;
        rescan = true;
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        return NextResponse.json(
          { error: `Ошибка сохранения файла: ${message}` },
          { status: 500 },
        );
      }
    }
  } else {
    const body = (await req.json().catch(() => null)) as Partial<StoreApp> | null;
    if (!body || typeof body !== "object") {
      return NextResponse.json({ error: "Invalid body" }, { status: 400 });
    }
    const allowed: Array<keyof StoreApp> = [
      "name",
      "tagline",
      "description",
      "developerName",
      "developerEmail",
      "version",
      "category",
      "kind",
      "homepage",
      "tags",
      "features",
      "iconHue",
    ];
    for (const key of allowed) {
      if (key in body) {
        // @ts-expect-error dynamic assign of allowed keys
        patch[key] = body[key];
      }
    }
  }

  const updated = await patchApp(app.id, patch);
  if (!updated) {
    return NextResponse.json({ error: "Update failed" }, { status: 500 });
  }

  return NextResponse.json({
    app: toPublicApp(updated, { isOwner: true }),
    rescan,
  });
}

export async function DELETE(
  req: Request,
  ctx: { params: Promise<{ id: string }> },
) {
  const { id } = await ctx.params;
  const app = await resolveApp(id);
  if (!app) {
    return NextResponse.json({ error: "App not found" }, { status: 404 });
  }

  const denied = denyUnlessOwner(req, app);
  if (denied) return denied;

  await deleteApp(app.id);
  return NextResponse.json({ ok: true, deleted: app.id });
}
