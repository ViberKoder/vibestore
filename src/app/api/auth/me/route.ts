import { NextResponse } from "next/server";
import { githubConfigured } from "@/lib/auth/github";
import { getSessionUser } from "@/lib/auth/session";

export const runtime = "nodejs";

export async function GET(req: Request) {
  return NextResponse.json({
    configured: githubConfigured(),
    user: getSessionUser(req.headers.get("cookie")),
  });
}
