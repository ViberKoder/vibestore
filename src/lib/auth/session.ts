import { randomBytes } from "crypto";

/**
 * Server-side sessions for GitHub sign-in. The browser only holds an opaque
 * session id (HttpOnly). The GitHub access token never leaves the server.
 * Sessions live in process memory, so a restart signs users out.
 */
export interface SessionUser {
  id: number;
  login: string;
  name: string | null;
  avatarUrl: string | null;
}

interface Session {
  user: SessionUser;
  token: string;
  expiresAt: number;
}

export const SESSION_COOKIE = "vibe_session";
const TTL_MS = 7 * 24 * 60 * 60 * 1000;

const g = globalThis as typeof globalThis & { __vibeSessions?: Map<string, Session> };
const sessions = (g.__vibeSessions ??= new Map<string, Session>());

export function readCookie(header: string | null | undefined, name: string): string | null {
  if (!header) return null;
  const hit = header
    .split(";")
    .map((p) => p.trim())
    .find((p) => p.startsWith(`${name}=`));
  return hit ? decodeURIComponent(hit.slice(name.length + 1)) : null;
}

export function createSession(user: SessionUser, token: string): string {
  const sid = randomBytes(32).toString("base64url");
  sessions.set(sid, { user, token, expiresAt: Date.now() + TTL_MS });
  // Opportunistic cleanup so the map cannot grow without bound.
  if (sessions.size > 5_000) {
    const now = Date.now();
    for (const [k, s] of sessions) if (s.expiresAt <= now) sessions.delete(k);
  }
  return sid;
}

function live(sid: string | null): Session | null {
  if (!sid) return null;
  const s = sessions.get(sid);
  if (!s) return null;
  if (s.expiresAt <= Date.now()) {
    sessions.delete(sid);
    return null;
  }
  return s;
}

export function getSessionUser(cookieHeader: string | null | undefined): SessionUser | null {
  return live(readCookie(cookieHeader, SESSION_COOKIE))?.user ?? null;
}

/** Access token for server-side GitHub calls on behalf of the signed-in user. */
export function getSessionToken(cookieHeader: string | null | undefined): string | null {
  return live(readCookie(cookieHeader, SESSION_COOKIE))?.token ?? null;
}

export function destroySession(cookieHeader: string | null | undefined): void {
  const sid = readCookie(cookieHeader, SESSION_COOKIE);
  if (sid) sessions.delete(sid);
}

export function sessionCookie(sid: string, secure: boolean): string {
  return [
    `${SESSION_COOKIE}=${encodeURIComponent(sid)}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    `Max-Age=${TTL_MS / 1000}`,
    ...(secure ? ["Secure"] : []),
  ].join("; ");
}

export function clearSessionCookie(secure: boolean): string {
  return [`${SESSION_COOKIE}=`, "Path=/", "HttpOnly", "SameSite=Lax", "Max-Age=0", ...(secure ? ["Secure"] : [])].join("; ");
}
