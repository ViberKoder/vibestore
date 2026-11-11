import { promises as fs } from "fs";
import { randomBytes } from "crypto";
import { NextResponse } from "next/server";
import { GITHUB_API_BASE, apiHeaders, getRepo } from "@/lib/auth/github";
import { getSessionToken, getSessionUser } from "@/lib/auth/session";
import { developerCookieHeader, mintDeveloperId, readDeveloperId, requestHost, toPublicApp } from "@/lib/owner-auth";
import { initialScanProgress } from "@/lib/scanners/pipeline";
import { sha256Buffer } from "@/lib/hash";
import { limitRequest } from "@/lib/security/rate-limit";
import { listApps, upsertApp, uploadPathFor } from "@/lib/store";
import { uniqueSlug } from "@/lib/slug";
import type { AppKind, StoreApp } from "@/lib/types";

export const runtime = "nodejs";
export const maxDuration = 600;

/** Source archives above this size are refused (kept in memory while scanning). */
const IMPORT_MAX_BYTES = 200 * 1024 * 1024;
const KINDS: AppKind[] = ["desktop", "web", "cli", "mobile", "other"];
const NAME = /^[A-Za-z0-9_.-]{1,100}$/;
const REF = /^[A-Za-z0-9._/-]{1,200}$/;

/** Reads a response body with a hard byte cap, so a huge archive cannot exhaust memory. */
async function readCapped(res: Response, max: number): Promise<Buffer> {
  const declared = Number(res.headers.get("content-length") ?? 0);
  if (declared > max) throw new Error("Repository archive is larger than 200 MB");
  if (!res.body) return Buffer.alloc(0);
  const reader = res.body.getReader();
  const chunks: Buffer[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel();
      throw new Error("Repository archive is larger than 200 MB");
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks);
}

/** Only HTTPS GitHub hosts; a custom API base (tests / GitHub Enterprise) is allowed explicitly. */
function archiveHostAllowed(url: string): boolean {
  const u = new URL(url);
  const custom = new URL(GITHUB_API_BASE).host;
  if (u.host === custom && GITHUB_API_BASE !== "https://api.github.com") return true;
  return u.protocol === "https:" && (u.hostname === "github.com" || u.hostname.endsWith(".github.com") || u.hostname.endsWith(".githubusercontent.com"));
}

/**
 * Follows GitHub's archive redirect by hand. The token is sent only to the first
 * (GitHub API) hop; the signed download target never sees it.
 */
async function fetchArchive(start: string, token: string): Promise<Response> {
  let url = start;
  for (let hop = 0; hop < 5; hop++) {
    const first = hop === 0;
    const res = await fetch(url, {
      headers: first ? { ...apiHeaders(token), Accept: "application/vnd.github+json" } : { "User-Agent": "VibeStore/1.0" },
      redirect: "manual",
      cache: "no-store",
    });
    if ([301, 302, 303, 307, 308].includes(res.status)) {
      const next = res.headers.get("location");
      if (!next) throw new Error("GitHub redirect without a location");
      url = new URL(next, url).href;
      if (!archiveHostAllowed(url)) throw new Error("Unexpected archive host");
      continue;
    }
    return res;
  }
  throw new Error("Too many redirects while downloading the archive");
}

/** Imports a repository's source archive at a branch/tag/commit and queues it for scanning. */
export async function POST(req: Request) {
  const limited = limitRequest(req, "importRepo");
  if (limited) return limited;
  const cookie = req.headers.get("cookie");
  const token = getSessionToken(cookie);
  const user = getSessionUser(cookie);
  if (!token || !user) {
    return NextResponse.json({ error: "Sign in with GitHub first" }, { status: 401 });
  }

  const body = (await req.json().catch(() => null)) as Record<string, unknown> | null;
  const owner = String(body?.owner ?? "");
  const repoName = String(body?.repo ?? "");
  const ref = String(body?.ref ?? "").trim();
  const name = String(body?.name ?? "").trim().slice(0, 80);
  const tagline = String(body?.tagline ?? "").trim().slice(0, 160);
  const description = String(body?.description ?? "").trim().slice(0, 8000);
  const kind = (KINDS.includes(body?.kind as AppKind) ? body?.kind : "other") as AppKind;
  const category = String(body?.category ?? "Utilities").trim().slice(0, 60) || "Utilities";
  const version = String(body?.version ?? "0.1.0").trim().slice(0, 40) || "0.1.0";
  const developerName = String(body?.developerName ?? "").trim().slice(0, 80) || user.login;

  if (!NAME.test(owner) || !NAME.test(repoName)) {
    return NextResponse.json({ error: "Invalid repository name" }, { status: 400 });
  }
  if (ref && (!REF.test(ref) || ref.includes(".."))) {
    return NextResponse.json({ error: "Invalid branch, tag or commit" }, { status: 400 });
  }
  if (!name || !tagline || !description) {
    return NextResponse.json({ error: "name, tagline and description are required" }, { status: 400 });
  }

  // Access check with the user's own token: the user can only import what they can read.
  const repo = await getRepo(owner, repoName, token);
  if (!repo) {
    return NextResponse.json({ error: "Repository not found or not accessible with your GitHub permissions" }, { status: 404 });
  }
  const useRef = ref || repo.default_branch;

  let archive: Buffer;
  try {
    const res = await fetchArchive(`${GITHUB_API_BASE}/repos/${repo.owner.login}/${repo.name}/zipball/${useRef}`, token);
    if (!res.ok) {
      return NextResponse.json({ error: `GitHub returned ${res.status} for this branch or commit` }, { status: 502 });
    }
    archive = await readCapped(res, IMPORT_MAX_BYTES);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Download failed";
    return NextResponse.json({ error: message }, { status: 502 });
  }
  if (archive.length < 22) {
    return NextResponse.json({ error: "The repository archive is empty" }, { status: 400 });
  }

  const existing = await listApps({ status: "all" });
  const slug = uniqueSlug(name, existing.map((a) => a.slug));
  const id = `app_${Date.now().toString(36)}_${randomBytes(3).toString("hex")}`;
  const storedName = `${id}.zip`;
  const filePath = uploadPathFor(storedName);
  await fs.writeFile(filePath, archive);

  let devId = readDeveloperId(cookie);
  if (!devId) devId = mintDeveloperId();
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
    version,
    homepage: repo.html_url,
    tags: [repo.language ?? "source"].filter(Boolean),
    features: [],
    screenshots: [],
    status: "scanning",
    createdAt: now,
    updatedAt: now,
    fileName: `${repo.name}-${useRef.replace(/[^A-Za-z0-9._-]/g, "-")}.zip`,
    fileSize: archive.length,
    mimeType: "application/zip",
    filePath,
    sha256: sha256Buffer(archive),
    downloads: 0,
    iconHue: Math.floor(Math.random() * 360),
    ownerId: devId,
    ownerGithub: { id: user.id, login: user.login },
    scanProgress: initialScanProgress(),
  };
  await upsertApp(app);

  const res = NextResponse.json({
    app: toPublicApp(app, { isOwner: true }),
    slug,
    scanRequired: true,
    source: `${repo.full_name}@${useRef}`,
  });
  res.headers.append("Set-Cookie", developerCookieHeader(devId, requestHost(req)));
  return res;
}
