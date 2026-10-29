import { NextResponse } from "next/server";
import { toPublicApp } from "@/lib/owner-auth";
import { listApps } from "@/lib/store";

export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  const q = searchParams.get("q") ?? undefined;
  const status = (searchParams.get("status") ?? "published") as
    | "published"
    | "quarantined"
    | "rejected"
    | "scanning"
    | "queued"
    | "all";

  const apps = await listApps({ q, status });
  return NextResponse.json({ apps: apps.map((a) => toPublicApp(a)) });
}
