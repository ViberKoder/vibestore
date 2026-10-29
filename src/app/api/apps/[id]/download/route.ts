import { promises as fs } from "fs";
import { NextResponse } from "next/server";
import { bumpDownloads, getAppById, getAppBySlug } from "@/lib/store";

export async function GET(
  _req: Request,
  ctx: { params: Promise<{ id: string }> },
) {
  const { id } = await ctx.params;
  const app = (await getAppById(id)) ?? (await getAppBySlug(id));
  if (!app) {
    return NextResponse.json({ error: "App not found" }, { status: 404 });
  }

  if (app.status === "rejected" || app.scan?.readiness === "blocked") {
    return NextResponse.json(
      { error: "Download blocked: security scan failed." },
      { status: 403 },
    );
  }

  if (app.status === "scanning" || app.status === "queued") {
    return NextResponse.json(
      { error: "Scan still in progress." },
      { status: 409 },
    );
  }

  await bumpDownloads(app.id);

  if (app.filePath) {
    try {
      const buf = await fs.readFile(app.filePath);
      return new NextResponse(buf, {
        headers: {
          "Content-Type": app.mimeType || "application/octet-stream",
          "Content-Disposition": `attachment; filename="${app.fileName}"`,
          "X-VibeStore-SHA256": app.sha256,
          "X-VibeStore-Score": String(app.scan?.securityScore ?? ""),
        },
      });
    } catch {
      /* fall through to demo payload */
    }
  }

  const demo = Buffer.from(
    [
      "Vibe Store demo download",
      `App: ${app.name}`,
      `Version: ${app.version}`,
      `SHA256: ${app.sha256}`,
      `Score: ${app.scan?.securityScore ?? "n/a"}`,
      "",
      "This seed listing has no uploaded binary.",
      "Publish your own build via /publish to get a real file.",
      "vibestore-clean-fixture",
    ].join("\n"),
    "utf8",
  );

  return new NextResponse(demo, {
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Content-Disposition": `attachment; filename="${app.slug}-vibestore.txt"`,
      "X-VibeStore-SHA256": app.sha256,
    },
  });
}
