import { NextResponse } from "next/server";
import { exchangeCode, fetchUser, publicOrigin } from "@/lib/auth/github";
import { createSession, readCookie, sessionCookie } from "@/lib/auth/session";

export const runtime = "nodejs";

function back(req: Request, query: string) {
  return new URL(`/dashboard?${query}`, publicOrigin(req));
}

/** GitHub redirects here with ?code & ?state. The state must match our cookie. */
export async function GET(req: Request) {
  const url = new URL(req.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const expected = readCookie(req.headers.get("cookie"), "vibe_oauth_state");
  const origin = publicOrigin(req);
  const secure = origin.startsWith("https");

  const fail = (reason: string) => {
    const res = NextResponse.redirect(back(req, `auth_error=${encodeURIComponent(reason)}`));
    res.headers.append("Set-Cookie", `vibe_oauth_state=; Path=/api/auth/github; Max-Age=0; HttpOnly; SameSite=Lax`);
    return res;
  };

  if (!code || !state || !expected || state !== expected) return fail("Sign-in expired. Try again.");
  if (url.searchParams.get("error")) return fail("GitHub sign-in was cancelled.");
  try {
    const token = await exchangeCode(code, origin);
    const user = await fetchUser(token);
    const sid = createSession(
      { id: user.id, login: user.login, name: user.name, avatarUrl: user.avatar_url },
      token,
    );
    const res = NextResponse.redirect(back(req, "login=ok"));
    res.headers.append("Set-Cookie", sessionCookie(sid, secure));
    res.headers.append("Set-Cookie", `vibe_oauth_state=; Path=/api/auth/github; Max-Age=0; HttpOnly; SameSite=Lax`);
    return res;
  } catch (err) {
    return fail(err instanceof Error ? err.message : "Sign-in failed");
  }
}
