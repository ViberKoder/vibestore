import { createWriteStream } from "fs";
import { promises as fs } from "fs";
import path from "path";
import { Readable } from "stream";
import { pipeline } from "stream/promises";
import { NextResponse } from "next/server";
import { createHash } from "crypto";
import { initialScanProgress } from "@/lib/scanners/pipeline";
import { listApps, uploadPathFor, upsertApp } from "@/lib/store";
import { uniqueSlug } from "@/lib/slug";
import { MAX_UPLOAD_BYTES, type AppKind, type StoreApp } from "@/lib/types";

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

async function saveUpload(file: File, dest: string): Promise<{ size: number; sha256: string }> {
  await fs.mkdir(path.dirname(dest), { recursive: true });
  const hash = createHash("sha256");
  let size = 0;

  // Web File stream → Node writable (avoids buffering entire 200MB twice when possible)
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
    scanProgress: initialScanProgress(),
  };

  await upsertApp(app);

  // Scan runs separately so UI can show live per-engine progress
  return NextResponse.json({ app, scanRequired: true });
}
