import { NextResponse } from "next/server";
import {
  ownerSessionCookie,
  setOwnerCookieHeader,
  verifyOwnerKey,
  verifyOwnerSession,
  clearOwnerSessionCookie,
} from "@/lib/owner-auth";
import { getAppById, getAppBySlug } from "@/lib/store";

export const runtime = "nodejs";

async function resolveApp(id: string) {
  return (await getAppById(id)) ?? (await getAppBySlug(id));
}

/** Check whether the current browser already has an owner session. */
export async function GET(
  req: Request,
  ctx: { params: Promise<{ id: string }> },
) {
  const { id } = await ctx.params;
  const app = await resolveApp(id);
  if (!app) {
    return NextResponse.json({ error: "App not found" }, { status: 404 });
  }
  const unlocked = await verifyOwnerSession(
    app.id,
    req.headers.get("cookie"),
  );
  return NextResponse.json({ unlocked, appId: app.id, slug: app.slug });
}

/** Unlock management with the one-time owner key. */
export async function POST(
  req: Request,
  ctx: { params: Promise<{ id: string }> },
) {
  const { id } = await ctx.params;
  const app = await resolveApp(id);
  if (!app) {
    return NextResponse.json({ error: "App not found" }, { status: 404 });
  }

  const body = (await req.json().catch(() => null)) as {
    ownerKey?: string;
  } | null;
  const ownerKey = body?.ownerKey?.trim() ?? "";

  if (!app.ownerKeyHash) {
    return NextResponse.json(
      { error: "У приложения ещё нет ключа владельца" },
      { status: 400 },
    );
  }

  if (!verifyOwnerKey(ownerKey, app.ownerKeyHash)) {
    return NextResponse.json(
      { error: "Неверный ключ владельца" },
      { status: 401 },
    );
  }

  const cookie = await ownerSessionCookie(app.id);
  const res = NextResponse.json({
    ok: true,
    unlocked: true,
    appId: app.id,
    slug: app.slug,
  });
  res.headers.append("Set-Cookie", setOwnerCookieHeader(cookie));
  return res;
}

/** Drop the owner session cookie. */
export async function DELETE(
  _req: Request,
  ctx: { params: Promise<{ id: string }> },
) {
  const { id } = await ctx.params;
  const app = await resolveApp(id);
  if (!app) {
    return NextResponse.json({ error: "App not found" }, { status: 404 });
  }
  const cookie = clearOwnerSessionCookie(app.id);
  const res = NextResponse.json({ ok: true, unlocked: false });
  res.headers.append("Set-Cookie", setOwnerCookieHeader(cookie));
  return res;
}
