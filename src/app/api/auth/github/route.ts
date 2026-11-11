import { NextResponse } from "next/server";
import { authorizeUrl, githubConfigured, newOAuthState, publicOrigin } from "@/lib/auth/github";

export const runtime = "nodejs";

/** Starts GitHub sign-in: sets a one-time state cookie and redirects to GitHub. */
export async function GET(req: Request) {
  if (!githubConfigured()) {
    return NextResponse.redirect(new URL("/dashboard?auth=not-configured", publicOrigin(req)));
  }
  const origin = publicOrigin(req);
  const state = newOAuthState();
  const res = NextResponse.redirect(authorizeUrl(origin, state));
  res.headers.append(
    "Set-Cookie",
    `vibe_oauth_state=${state}; Path=/api/auth/github; HttpOnly; SameSite=Lax; Max-Age=600${origin.startsWith("https") ? "; Secure" : ""}`,
  );
  return res;
}
