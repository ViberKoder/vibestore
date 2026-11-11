"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { useT } from "@/lib/i18n/client";
import { fill } from "@/lib/i18n/core";

type Repo = {
  fullName: string;
  owner: string;
  name: string;
  private: boolean;
  fork: boolean;
  description: string | null;
  defaultBranch: string;
  htmlUrl: string;
  language: string | null;
  sizeKb: number;
  pushedAt: string;
};

type Me = { configured: boolean; user: { login: string } | null };

export function GithubImportForm() {
  const t = useT();
  const router = useRouter();
  const [me, setMe] = useState<Me | null>(null);
  const [repos, setRepos] = useState<Repo[]>([]);
  const [page, setPage] = useState(1);
  const [hasMore, setHasMore] = useState(false);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState("");
  const [selected, setSelected] = useState<Repo | null>(null);
  const [ref, setRef] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [form, setForm] = useState({
    name: "",
    tagline: "",
    description: "",
    kind: "other",
    category: "Utilities",
    version: "0.1.0",
  });

  useEffect(() => {
    fetch("/api/auth/me", { cache: "no-store" })
      .then((r) => r.json())
      .then((j: Me) => setMe(j))
      .catch(() => setMe({ configured: false, user: null }));
  }, []);

  useEffect(() => {
    if (!me?.user) return;
    fetch(`/api/github/repos?page=${page}`, { cache: "no-store" })
      .then(async (r) => {
        const j = (await r.json()) as { repos?: Repo[]; hasMore?: boolean; error?: string };
        if (!r.ok) throw new Error(j.error ?? "GitHub request failed");
        setRepos((prev) => (page === 1 ? j.repos ?? [] : [...prev, ...(j.repos ?? [])]));
        setHasMore(Boolean(j.hasMore));
      })
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  }, [me?.user, page]);

  const visible = useMemo(() => {
    const q = filter.trim().toLowerCase();
    return q ? repos.filter((r) => r.fullName.toLowerCase().includes(q)) : repos;
  }, [repos, filter]);

  function pick(r: Repo) {
    setSelected(r);
    setRef("");
    setError(null);
    setForm((f) => ({
      ...f,
      name: r.name.replace(/[-_]+/g, " ").replace(/\b\w/g, (c) => c.toUpperCase()).slice(0, 80),
      tagline: (r.description ?? "").slice(0, 160),
      description: r.description ?? `Imported from ${r.htmlUrl}`,
    }));
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!selected) return;
    setBusy(true);
    setError(null);
    try {
      const res = await fetch("/api/github/import", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ owner: selected.owner, repo: selected.name, ref: ref.trim(), ...form }),
      });
      const json = (await res.json()) as { slug?: string; error?: string };
      if (!res.ok || !json.slug) throw new Error(json.error ?? "Import failed");
      router.push(`/apps/${json.slug}?scanning=1`);
      router.refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Import failed");
      setBusy(false);
    }
  }

  if (!me) return <p className="text-[14px] text-ink-2">{t("Loading…")}</p>;
  if (!me.configured) {
    return <p className="text-[14px] text-ink-2">{t("GitHub sign-in is not configured on this server.")}</p>;
  }
  if (!me.user) {
    return (
      <div className="space-y-4">
        <p className="text-[14px] text-ink-2">
          {t("Sign in with GitHub to choose one of your repositories. We download the source archive of the branch you pick and scan it like an upload.")}
        </p>
        <a href="/api/auth/github" className="btn-primary inline-flex">{t("Sign in with GitHub")}</a>
      </div>
    );
  }

  const field = (label: string, key: keyof typeof form, multiline = false) => (
    <label className="block space-y-2">
      <span className="text-[13px] font-semibold text-ink">{t(label)}</span>
      {multiline ? (
        <textarea
          value={form[key]}
          onChange={(e) => setForm({ ...form, [key]: e.target.value })}
          rows={3}
          required
          className="field-input min-h-[88px] resize-y"
        />
      ) : (
        <input
          value={form[key]}
          onChange={(e) => setForm({ ...form, [key]: e.target.value })}
          required={key !== "version" && key !== "category"}
          className="field-input"
        />
      )}
    </label>
  );

  return (
    <div className="grid gap-6 md:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)]">
      <div className="space-y-3">
        <input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder={t("Filter repositories")}
          className="field-input"
        />
        <ul className="max-h-[460px] space-y-1 overflow-y-auto rounded-2xl border border-[var(--line)] p-1.5">
          {visible.map((r) => (
            <li key={r.fullName}>
              <button
                type="button"
                onClick={() => pick(r)}
                className={`w-full rounded-xl px-3 py-2.5 text-left transition ${
                  selected?.fullName === r.fullName ? "bg-blue-soft" : "hover:bg-black/[0.04]"
                }`}
              >
                <div className="flex items-center gap-2 text-[14px] font-semibold text-ink">
                  <span className="truncate">{r.fullName}</span>
                  {r.private && (
                    <span className="rounded-full bg-black/[0.06] px-2 py-0.5 text-[10px] font-semibold uppercase text-ink-3">
                      {t("private")}
                    </span>
                  )}
                </div>
                <div className="mt-0.5 truncate text-[12px] text-ink-3">
                  {[r.language, r.description].filter(Boolean).join(" · ") || t("No description")}
                </div>
              </button>
            </li>
          ))}
          {!loading && visible.length === 0 && (
            <li className="px-3 py-6 text-center text-[13px] text-ink-3">{t("No repositories found.")}</li>
          )}
        </ul>
        {hasMore && (
          <button
            type="button"
            onClick={() => {
              setLoading(true);
              setPage((p) => p + 1);
            }}
            disabled={loading}
            className="btn-secondary"
          >
            {loading ? t("Loading…") : t("Load more")}
          </button>
        )}
      </div>

      <form onSubmit={submit} className="space-y-4">
        {!selected ? (
          <p className="rounded-2xl bg-black/[0.03] px-4 py-6 text-center text-[14px] text-ink-3">
            {t("Pick a repository on the left.")}
          </p>
        ) : (
          <>
            <p className="text-[13px] text-ink-2">
              {fill(t("Source: {repo}"), { repo: selected.fullName })}
            </p>
            <label className="block space-y-2">
              <span className="text-[13px] font-semibold text-ink">{t("Branch, tag or commit")}</span>
              <input
                value={ref}
                onChange={(e) => setRef(e.target.value)}
                placeholder={selected.defaultBranch}
                className="field-input font-mono text-[13px]"
              />
            </label>
            {field("Name", "name")}
            {field("Tagline", "tagline")}
            {field("Description", "description", true)}
            <div className="grid gap-4 sm:grid-cols-2">
              <label className="block space-y-2">
                <span className="text-[13px] font-semibold text-ink">{t("Type")}</span>
                <select value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value })} className="field-input">
                  <option value="desktop">Desktop (Electron, .exe)</option>
                  <option value="web">Web / website</option>
                  <option value="cli">CLI</option>
                  <option value="mobile">Mobile</option>
                  <option value="other">Other</option>
                </select>
              </label>
              {field("Version", "version")}
            </div>
            {error && <p className="rounded-2xl bg-red-soft px-4 py-3 text-[13px] text-red-ink">{t(error)}</p>}
            <button type="submit" disabled={busy} className="btn-primary w-full sm:w-auto">
              {busy ? t("Importing…") : t("Import and scan")}
            </button>
          </>
        )}
      </form>
    </div>
  );
}
