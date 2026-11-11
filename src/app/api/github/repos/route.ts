import { NextResponse } from "next/server";
import { listRepos } from "@/lib/auth/github";
import { getSessionToken } from "@/lib/auth/session";

export const runtime = "nodejs";

export async function GET(req: Request) {
  const token = getSessionToken(req.headers.get("cookie"));
  if (!token) return NextResponse.json({ error: "Sign in with GitHub first" }, { status: 401 });
  const page = Math.max(1, Math.min(20, Number(new URL(req.url).searchParams.get("page") ?? 1) || 1));
  try {
    const repos = await listRepos(token, page);
    return NextResponse.json({
      repos: repos
        .filter((r) => !r.archived)
        .map((r) => ({
          fullName: r.full_name,
          owner: r.owner.login,
          name: r.name,
          private: r.private,
          fork: r.fork,
          description: r.description,
          defaultBranch: r.default_branch,
          htmlUrl: r.html_url,
          language: r.language,
          sizeKb: r.size,
          pushedAt: r.pushed_at,
        })),
      page,
      hasMore: repos.length === 50,
    });
  } catch (err) {
    return NextResponse.json({ error: err instanceof Error ? err.message : "GitHub request failed" }, { status: 502 });
  }
}
