import { promises as fs } from "fs";
import path from "path";
import { NextResponse } from "next/server";
import { sha256Buffer } from "@/lib/hash";
import { runScanPipeline, statusFromReport } from "@/lib/scanners/pipeline";
import { listApps, uploadPathFor, upsertApp } from "@/lib/store";
import { uniqueSlug } from "@/lib/slug";
import type { AppKind, StoreApp } from "@/lib/types";

export const runtime = "nodejs";
export const maxDuration = 120;

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

  if (file.size > 64 * 1024 * 1024) {
    return NextResponse.json(
      { error: "Max upload size is 64 MB" },
      { status: 400 },
    );
  }

  const existing = await listApps({ status: "all" });
  const slug = uniqueSlug(name, existing.map((a) => a.slug));
  const id = `app_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 7)}`;
  const storedName = `${id}${ext || ".bin"}`;
  const filePath = uploadPathFor(storedName);

  const ab = await file.arrayBuffer();
  const buffer = Buffer.from(ab);
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, buffer);

  const sha256 = sha256Buffer(buffer);
  const now = new Date().toISOString();

  let app: StoreApp = {
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
    fileSize: buffer.length,
    mimeType: file.type || "application/octet-stream",
    filePath,
    sha256,
    downloads: 0,
    iconHue: Math.floor(Math.random() * 360),
  };

  await upsertApp(app);

  const scan = await runScanPipeline({
    filePath,
    buffer,
    fileName: file.name,
  });

  app = {
    ...app,
    scan,
    status: statusFromReport(scan),
    updatedAt: new Date().toISOString(),
  };
  await upsertApp(app);

  return NextResponse.json({ app });
}
