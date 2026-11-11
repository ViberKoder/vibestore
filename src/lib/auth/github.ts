import { randomBytes } from "crypto";

/**
 * GitHub OAuth + REST helpers. Endpoints are configurable so tests can point at a
 * local stand-in; production defaults are github.com / api.github.com.
 */
export const GITHUB_OAUTH_BASE = process.env.GITHUB_OAUTH_BASE?.replace(/\/$/, "") || "https://github.com";
export const GITHUB_API_BASE = process.env.GITHUB_API_BASE?.replace(/\/$/, "") || "https://api.github.com";

export function githubConfigured(): boolean {
  return Boolean(process.env.GITHUB_CLIENT_ID?.trim() && process.env.GITHUB_CLIENT_SECRET?.trim());
}

/** Public origin for OAuth callbacks: APP_URL if set, otherwise derived from the request. */
export function publicOrigin(req: Request): string {
  const configured = process.env.APP_URL?.trim().replace(/\/$/, "");
  if (configured) return configured;
  const host = req.headers.get("x-forwarded-host") ?? req.headers.get("host") ?? "localhost:3000";
  const proto = req.headers.get("x-forwarded-proto") ?? (host.startsWith("localhost") ? "http" : "https");
  return `${proto}://${host}`;
}

export function newOAuthState(): string {
  return randomBytes(24).toString("base64url");
}

export function authorizeUrl(origin: string, state: string): string {
  const q = new URLSearchParams({
    client_id: process.env.GITHUB_CLIENT_ID ?? "",
    redirect_uri: `${origin}/api/auth/github/callback`,
    scope: "read:user repo",
    state,
    allow_signup: "true",
  });
  return `${GITHUB_OAUTH_BASE}/login/oauth/authorize?${q.toString()}`;
}

export async function exchangeCode(code: string, origin: string): Promise<string> {
  const res = await fetch(`${GITHUB_OAUTH_BASE}/login/oauth/access_token`, {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify({
      client_id: process.env.GITHUB_CLIENT_ID,
      client_secret: process.env.GITHUB_CLIENT_SECRET,
      code,
      redirect_uri: `${origin}/api/auth/github/callback`,
    }),
    cache: "no-store",
  });
  const json = (await res.json().catch(() => ({}))) as { access_token?: string; error_description?: string };
  if (!json.access_token) throw new Error(json.error_description ?? "GitHub did not return an access token");
  return json.access_token;
}

export function apiHeaders(token?: string): Record<string, string> {
  return {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "VibeApps/1.0",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
}

export async function apiJson<T>(path: string, token: string): Promise<{ status: number; data: T | null }> {
  const res = await fetch(`${GITHUB_API_BASE}${path}`, { headers: apiHeaders(token), cache: "no-store" });
  if (res.status === 404 || res.status === 403) return { status: res.status, data: null };
  if (!res.ok) throw new Error(`GitHub API ${res.status}`);
  return { status: res.status, data: (await res.json()) as T };
}

export interface GithubUser {
  id: number;
  login: string;
  name: string | null;
  avatar_url: string | null;
}

export async function fetchUser(token: string): Promise<GithubUser> {
  const { data } = await apiJson<GithubUser>("/user", token);
  if (!data) throw new Error("Could not read the GitHub profile");
  return data;
}

export interface GithubRepo {
  id: number;
  full_name: string;
  name: string;
  owner: { login: string };
  private: boolean;
  fork: boolean;
  archived: boolean;
  description: string | null;
  default_branch: string;
  html_url: string;
  language: string | null;
  size: number;
  pushed_at: string;
}

export async function listRepos(token: string, page: number): Promise<GithubRepo[]> {
  const { data } = await apiJson<GithubRepo[]>(
    `/user/repos?per_page=50&page=${page}&sort=pushed&affiliation=owner,collaborator,organization_member`,
    token,
  );
  return data ?? [];
}

export async function getRepo(owner: string, repo: string, token: string): Promise<GithubRepo | null> {
  const { data } = await apiJson<GithubRepo>(`/repos/${owner}/${repo}`, token);
  return data;
}
