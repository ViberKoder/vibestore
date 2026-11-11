import { NextResponse } from "next/server";
import { publicOrigin } from "@/lib/auth/github";
import { clearSessionCookie, destroySession } from "@/lib/auth/session";

export const runtime = "nodejs";

export async function POST(req: Request) {
  destroySession(req.headers.get("cookie"));
  const res = NextResponse.json({ ok: true });
  res.headers.append("Set-Cookie", clearSessionCookie(publicOrigin(req).startsWith("https")));
  return res;
}
