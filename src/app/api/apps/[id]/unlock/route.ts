import { NextResponse } from "next/server";
import {
  developerCookieHeader,
  isAppOwner,
  mintDeveloperId,
  readDeveloperId,
} from "@/lib/owner-auth";
import { getAppById, getAppBySlug, patchApp } from "@/lib/store";

export const runtime = "nodejs";

async function resolveApp(id: string) {
  return (await getAppById(id)) ?? (await getAppBySlug(id));
}

/** Who am I for this app — owner / can claim / stranger. */
export async function GET(
  req: Request,
  ctx: { params: Promise<{ id: string }> },
) {
  const { id } = await ctx.params;
  const app = await resolveApp(id);
  if (!app) {
    return NextResponse.json({ error: "App not found" }, { status: 404 });
  }
  const cookie = req.headers.get("cookie");
  const isOwner = isAppOwner(app, cookie);
  const canClaim = !app.ownerId;
  return NextResponse.json({
    appId: app.id,
    slug: app.slug,
    isOwner,
    canClaim,
    hasOwner: Boolean(app.ownerId),
  });
}

/**
 * Claim an app that has no owner yet (uploaded before ownership tracking).
 * Binds it to the current browser developer cookie.
 */
export async function POST(
  req: Request,
  ctx: { params: Promise<{ id: string }> },
) {
  const { id } = await ctx.params;
  const app = await resolveApp(id);
  if (!app) {
    return NextResponse.json({ error: "App not found" }, { status: 404 });
  }

  if (app.ownerId) {
    if (isAppOwner(app, req.headers.get("cookie"))) {
      return NextResponse.json({ ok: true, isOwner: true, already: true });
    }
    return NextResponse.json(
      { error: "Приложение уже привязано к другому браузеру" },
      { status: 403 },
    );
  }

  let devId = readDeveloperId(req.headers.get("cookie"));
  const setCookie = !devId;
  if (!devId) devId = mintDeveloperId();

  const updated = await patchApp(app.id, {
    ownerId: devId,
    ownerKeyHash: undefined,
  });
  if (!updated) {
    return NextResponse.json({ error: "Claim failed" }, { status: 500 });
  }

  const res = NextResponse.json({
    ok: true,
    isOwner: true,
    claimed: true,
    appId: app.id,
    slug: app.slug,
  });
  if (setCookie) {
    res.headers.append("Set-Cookie", developerCookieHeader(devId));
  }
  return res;
}
