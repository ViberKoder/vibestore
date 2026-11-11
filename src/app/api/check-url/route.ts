import { NextResponse } from "next/server";
import { runWebsiteCheck } from "@/lib/scanners/website";
import { limitRequest } from "@/lib/security/rate-limit";

export const runtime = "nodejs";
export const maxDuration = 120;

/** Website check: analyses a public URL and returns a report. Nothing is stored. */
export async function POST(req: Request) {
  const limited = limitRequest(req, "checkUrl");
  if (limited) return limited;
  const body = (await req.json().catch(() => null)) as { url?: unknown } | null;
  const url = typeof body?.url === "string" ? body.url.trim() : "";
  if (!url) {
    return NextResponse.json({ error: "Enter a website address" }, { status: 400 });
  }
  try {
    const { report, finalUrl } = await runWebsiteCheck(url);
    return NextResponse.json({ report, finalUrl });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
