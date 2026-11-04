import { NextResponse } from "next/server";
import {
  developerCookieHeader,
  developerNameMatches,
  isAppOwner,
  mintDeveloperId,
  readDeveloperId,
  requestHost,
} from "@/lib/owner-auth";
import { getAppById, getAppBySlug, patchApp } from "@/lib/store";

export const runtime = "nodejs";

async function resolveApp(id: string) {
  return (await getAppById(id)) ?? (await getAppBySlug(id));
}

function bindOwnerCookie(
  res: NextResponse,
  req: Request,
  devId: string,
) {
  res.headers.append(
    "Set-Cookie",
    developerCookieHeader(devId, requestHost(req)),
  );
}

/** Who am I for this app — owner / can claim / can restore. */
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
  return NextResponse.json({
    appId: app.id,
    slug: app.slug,
    isOwner,
    canClaim: !app.ownerId,
    canRestore: Boolean(app.ownerId) && !isOwner,
    hasOwner: Boolean(app.ownerId),
    developerNameHint: app.developerName
      ? `${app.developerName.slice(0, 1)}…`
      : null,
  });
}

/**
 * Claim (no owner yet) or restore (cookie lost after tunnel/domain change).
 * Restore requires typing the same developerName as on the listing.
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

  const body = (await req.json().catch(() => ({}))) as {
    reclaim?: boolean;
    developerName?: string;
  };

  if (isAppOwner(app, req.headers.get("cookie"))) {
    const devId = readDeveloperId(req.headers.get("cookie"))!;
    const res = NextResponse.json({
      ok: true,
      isOwner: true,
      already: true,
    });
    bindOwnerCookie(res, req, devId);
    return res;
  }

  // Fresh claim — app never bound
  if (!app.ownerId) {
    let devId = readDeveloperId(req.headers.get("cookie"));
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
    bindOwnerCookie(res, req, devId);
    return res;
  }

  // Restore after lost cookie (new tunnel URL / cleared cookies)
  if (body.reclaim) {
    const name = body.developerName ?? "";
    if (!developerNameMatches(app, name)) {
      return NextResponse.json(
        {
          error:
            "Имя разработчика не совпало. Введите его точно как в карточке приложения.",
        },
        { status: 403 },
      );
    }

    let devId = readDeveloperId(req.headers.get("cookie"));
    if (!devId) devId = mintDeveloperId();

    const updated = await patchApp(app.id, { ownerId: devId });
    if (!updated) {
      return NextResponse.json({ error: "Restore failed" }, { status: 500 });
    }

    const res = NextResponse.json({
      ok: true,
      isOwner: true,
      restored: true,
      appId: app.id,
      slug: app.slug,
    });
    bindOwnerCookie(res, req, devId);
    return res;
  }

  return NextResponse.json(
    {
      error:
        "Доступ привязан к другому браузеру. Нажмите «Восстановить» и введите имя разработчика с карточки.",
    },
    { status: 403 },
  );
}
