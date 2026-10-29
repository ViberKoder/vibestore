import { createWriteStream } from "fs";
import { promises as fs } from "fs";
import path from "path";
import { Readable } from "stream";
import { pipeline } from "stream/promises";
import { NextResponse } from "next/server";
import { createHash, randomBytes } from "crypto";
import { initialScanProgress } from "@/lib/scanners/pipeline";
import { listApps, mediaDirFor, uploadPathFor, upsertApp } from "@/lib/store";
import { uniqueSlug } from "@/lib/slug";
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

const ALLOWED_EXT = new Set([
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

const IMAGE_EXT = new Set([".png", ".jpg", ".jpeg", ".webp", ".gif"]);

async function saveUpload(
  file: File,
  dest: string,
): Promise<{ size: number; sha256: string }> {
  await fs.mkdir(path.dirname(dest), { recursive: true });
  const hash = createHash("sha256");
  let size = 0;

  const webStream = file.stream();
  const nodeReadable = Readable.fromWeb(
    webStream as import("stream/web").ReadableStream,
  );
  const out = createWriteStream(dest);

  nodeReadable.on("data", (chunk: Buffer | string) => {
    const buf = typeof chunk === "string" ? Buffer.from(chunk) : chunk;
    size += buf.length;
    hash.update(buf);
    if (size > MAX_UPLOAD_BYTES) {
      nodeReadable.destroy(new Error("FILE_TOO_LARGE"));
    }
  });

  try {
    await pipeline(nodeReadable, out);
  } catch (err) {
    await fs.unlink(dest).catch(() => undefined);
    throw err;
  }

  return { size, sha256: hash.digest("hex") };
}

function parseFeatures(raw: string): AppFeature[] {
  // Lines: "Title | optional detail" or plain title
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

async function saveIcon(appId: string, file: File): Promise<string | null> {
  if (file.size <= 0 || file.size > MAX_SCREENSHOT_BYTES) return null;
  const ext = path.extname(file.name).toLowerCase() || ".png";
  if (!IMAGE_EXT.has(ext)) return null;
  const dir = mediaDirFor(appId);
  await fs.mkdir(dir, { recursive: true });
  const stored = `icon${ext}`;
  await fs.writeFile(
    path.join(dir, stored),
    Buffer.from(await file.arrayBuffer()),
  );
  return `/api/media/${appId}/${stored}`;
}

async function saveScreenshots(
  appId: string,
  files: File[],
): Promise<AppScreenshot[]> {
  const dir = mediaDirFor(appId);
  await fs.mkdir(dir, { recursive: true });
  const out: AppScreenshot[] = [];

  for (const file of files.slice(0, MAX_SCREENSHOTS)) {
    if (file.size <= 0 || file.size > MAX_SCREENSHOT_BYTES) continue;
    const ext = path.extname(file.name).toLowerCase() || ".png";
    if (!IMAGE_EXT.has(ext)) continue;
    const id = `shot_${randomBytes(4).toString("hex")}`;
    const stored = `${id}${ext}`;
    const dest = path.join(dir, stored);
    const buf = Buffer.from(await file.arrayBuffer());
    if (buf.length > MAX_SCREENSHOT_BYTES) continue;
    await fs.writeFile(dest, buf);
    out.push({
      id,
      fileName: stored,
      url: `/api/media/${appId}/${stored}`,
      caption: file.name.replace(/\.[^.]+$/, "").slice(0, 80) || undefined,
    });
  }
  return out;
}

export async function POST(req: Request) {
  const form = await req.formData();
  const file = form.get("file");

  if (!(file instanceof File)) {
    return NextResponse.json({ error: "File is required" }, { status: 400 });
  }

  const name = String(form.get("name") ?? "").trim();
  const tagline = String(form.get("tagline") ?? "").trim();
  const description = String(form.get("description") ?? "").trim();
  const developerName = String(form.get("developerName") ?? "").trim();
  const developerEmail = String(form.get("developerEmail") ?? "").trim();
  const version = String(form.get("version") ?? "0.1.0").trim() || "0.1.0";
  const category = String(form.get("category") ?? "Utilities").trim();
  const kind = (String(form.get("kind") ?? "other") as AppKind) || "other";
  const homepage = String(form.get("homepage") ?? "").trim();
  const tags = String(form.get("tags") ?? "")
    .split(",")
    .map((t) => t.trim())
    .filter(Boolean)
    .slice(0, 12);
  const features = parseFeatures(String(form.get("features") ?? ""));

  if (!name || !tagline || !description || !developerName) {
    return NextResponse.json(
      { error: "name, tagline, description, developerName are required" },
      { status: 400 },
    );
  }

  const ext = path.extname(file.name).toLowerCase();
  if (ext && !ALLOWED_EXT.has(ext)) {
    return NextResponse.json(
      { error: `Extension ${ext} is not allowed` },
      { status: 400 },
    );
  }

  if (file.size > MAX_UPLOAD_BYTES) {
    return NextResponse.json(
      {
        error: `Файл слишком большой (макс. ${Math.round(MAX_UPLOAD_BYTES / 1024 / 1024)} МБ)`,
      },
      { status: 400 },
    );
  }

  const existing = await listApps({ status: "all" });
  const slug = uniqueSlug(
    name,
    existing.map((a) => a.slug),
  );
  const id = `app_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 7)}`;
  const storedName = `${id}${ext || ".bin"}`;
  const filePath = uploadPathFor(storedName);

  let size: number;
  let sha256: string;
  try {
    const saved = await saveUpload(file, filePath);
    size = saved.size;
    sha256 = saved.sha256;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (message.includes("FILE_TOO_LARGE")) {
      return NextResponse.json(
        {
          error: `Файл слишком большой (макс. ${Math.round(MAX_UPLOAD_BYTES / 1024 / 1024)} МБ)`,
        },
        { status: 400 },
      );
    }
    return NextResponse.json(
      { error: `Ошибка сохранения файла: ${message}` },
      { status: 500 },
    );
  }

  const shotFiles = form
    .getAll("screenshots")
    .filter((f): f is File => f instanceof File && f.size > 0);
  let screenshots: AppScreenshot[] = [];
  try {
    screenshots = await saveScreenshots(id, shotFiles);
  } catch {
    screenshots = [];
  }

  let iconUrl: string | undefined;
  const iconFile = form.get("icon");
  if (iconFile instanceof File && iconFile.size > 0) {
    try {
      iconUrl = (await saveIcon(id, iconFile)) ?? undefined;
    } catch {
      iconUrl = undefined;
    }
  }

  const now = new Date().toISOString();
  const app: StoreApp = {
    id,
    slug,
    name,
    tagline,
    description,
    kind,
    category,
    developerName,
    developerEmail: developerEmail || undefined,
    version,
    homepage: homepage || undefined,
    tags,
    features,
    screenshots,
    status: "scanning",
    createdAt: now,
    updatedAt: now,
    fileName: file.name,
    fileSize: size,
    mimeType: file.type || "application/octet-stream",
    filePath,
    sha256,
    downloads: 0,
    iconHue: Math.floor(Math.random() * 360),
    iconUrl,
    scanProgress: initialScanProgress(),
  };

  await upsertApp(app);

  return NextResponse.json({ app, scanRequired: true });
}
