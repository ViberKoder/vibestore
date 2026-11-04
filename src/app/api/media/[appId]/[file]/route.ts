import { promises as fs } from "fs";
import path from "path";
import { NextResponse } from "next/server";
import { mediaPathFor } from "@/lib/store";

export const runtime = "nodejs";

const MIME: Record<string, string> = {
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".webp": "image/webp",
  ".gif": "image/gif",
};

export async function GET(
  _req: Request,
  ctx: { params: Promise<{ appId: string; file: string }> },
) {
  const { appId, file } = await ctx.params;
  if (
    !appId ||
    !file ||
    appId.includes("..") ||
    file.includes("..") ||
    file.includes("/") ||
    file.includes("\\")
  ) {
    return NextResponse.json({ error: "Bad path" }, { status: 400 });
  }

  const full = mediaPathFor(appId, file);
  try {
    const buf = await fs.readFile(full);
    const ext = path.extname(file).toLowerCase();
    return new NextResponse(buf, {
      headers: {
        "Content-Type": MIME[ext] ?? "application/octet-stream",
        "Cache-Control": "public, max-age=86400",
      },
    });
  } catch {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }
}
