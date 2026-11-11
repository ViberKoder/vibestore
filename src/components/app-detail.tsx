"use client";

import Link from "next/link";
import { useState } from "react";
import type { PublicStoreApp } from "@/lib/owner-auth";
import { formatBytes, formatNumber } from "@/lib/format";
import { fill } from "@/lib/i18n/core";
import { useLocale, useT } from "@/lib/i18n/client";
import { AppIcon } from "./app-icon";
import { AppRow } from "./app-row";
import { AppScanGate } from "./app-scan-gate";
import { SafetyBadge } from "./safety-badge";
import type { StoreApp } from "@/lib/types";

type Tab = "overview" | "gallery" | "audit";

export function AppDetail({
  app,
  related,
  developer,
  forceScanning,
  showManage = false,
}: {
  app: PublicStoreApp;
  related: PublicStoreApp[];
  developer?: { name: string; total: number; verified: number; blocked: number };
  forceScanning?: boolean;
  /** Only the uploader (or claimable legacy app) sees manage */
  showManage?: boolean;
}) {
  const t = useT();
  const locale = useLocale();
  const features = app.features ?? [];
  const shots = app.screenshots ?? [];
  const hasGallery = shots.length > 0;
  const defaultTab: Tab =
    forceScanning || app.status === "scanning" || app.status === "queued"
      ? "audit"
      : "overview";
  const [tab, setTab] = useState<Tab>(defaultTab);

  const canDownload =
    app.status === "published" ||
    (app.status === "quarantined" && app.scan?.readiness !== "blocked");

  const tabs: Array<{ id: Tab; label: string; hidden?: boolean }> = [
    { id: "overview", label: "Overview" },
    {
      id: "gallery",
      label: hasGallery ? "Gallery" : "Feature list",
      hidden: !hasGallery && features.length === 0,
    },
    { id: "audit", label: "Audit" },
  ];

  return (
    <div>
      <section className="fade-up flex flex-col gap-5 sm:flex-row sm:items-start">
        <AppIcon app={app} size="xl" />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2.5">
            <h1 className="text-[32px] font-extrabold tracking-[-0.04em] text-ink md:text-[40px]">
              {app.name}
            </h1>
            <SafetyBadge app={app} />
          </div>
          <p className="mt-1 text-[15px] text-blue">{app.developerName}</p>
          <p className="mt-2 max-w-xl text-[14px] leading-relaxed text-ink-2">
            {app.tagline}
          </p>

          <div className="mt-5 flex flex-wrap items-center gap-2.5">
            {canDownload ? (
              <a
                href={`/api/apps/${app.id}/download`}
                className="btn-primary !h-10 !px-6 !text-[14px]"
              >
                {app.status === "quarantined"
                  ? t("Download at your own risk")
                  : t("Download")}
              </a>
            ) : app.status === "scanning" || forceScanning ? (
              <span className="inline-flex h-10 items-center rounded-full bg-blue-soft px-5 text-[14px] font-semibold text-blue">
                {t("Scanning…")}
              </span>
            ) : (
              <span className="inline-flex h-10 items-center rounded-full bg-red-soft px-5 text-[14px] font-semibold text-red-ink">
                {t("Download unavailable")}
              </span>
            )}
            {app.homepage && (
              <a
                href={app.homepage}
                target="_blank"
                rel="noreferrer"
                className="btn-secondary !h-10 !px-5 !text-[14px]"
              >
                {t("Website")}
              </a>
            )}
            {showManage && (
              <Link
                href={`/apps/${app.slug}/edit`}
                className="btn-secondary !h-10 !px-5 !text-[14px]"
              >
                {app.isOwner
                  ? t("Manage")
                  : app.canRestore
                    ? t("Restore")
                    : t("Is this mine?")}
              </Link>
            )}
            <span className="ml-1 text-[12px] tabular-nums text-ink-3">
              {fill(t("v{version} · {size} · {count} downloads"), {
                version: app.version,
                size: formatBytes(app.fileSize),
                count: formatNumber(app.downloads, locale),
              })}
            </span>
          </div>
        </div>
      </section>

      <nav className="fade-up-d1 mt-6 flex gap-1 border-b border-[var(--line)]">
        {tabs
          .filter((tb) => !tb.hidden)
          .map((tb) => (
            <button
              key={tb.id}
              type="button"
              onClick={() => setTab(tb.id)}
              className={`relative px-4 py-2.5 text-[14px] font-semibold tracking-[-0.01em] transition ${
                tab === tb.id
                  ? "text-ink"
                  : "text-ink-3 hover:text-ink-2"
              }`}
            >
              {t(tb.label)}
              {tab === tb.id && (
                <span className="absolute inset-x-3 -bottom-px h-0.5 rounded-full bg-blue" />
              )}
            </button>
          ))}
      </nav>

      <div className="fade-up-d2 mt-6">
        {tab === "overview" && (
          <OverviewTab app={app} features={features} related={related} developer={developer} />
        )}
        {tab === "gallery" && (
          <GalleryTab shots={shots} features={features} />
        )}
        {tab === "audit" && (
          <div className="surface-card max-w-2xl px-5 py-5 md:px-6 md:py-6">
            <AppScanGate app={app} forceScanning={forceScanning} />
          </div>
        )}
      </div>
    </div>
  );
}

function OverviewTab({
  app,
  features,
  related,
  developer,
}: {
  app: PublicStoreApp;
  features: StoreApp["features"];
  related: PublicStoreApp[];
  developer?: { name: string; total: number; verified: number; blocked: number };
}) {
  const t = useT();
  return (
    <div className="grid gap-8 lg:grid-cols-[1fr_280px]">
      <div className="space-y-8">
        <section>
          <h2 className="text-[17px] font-bold tracking-[-0.02em]">{t("Description")}</h2>
          <p className="mt-2 whitespace-pre-wrap text-[14px] leading-[1.65] text-ink-2">
            {app.description}
          </p>
        </section>

        {features.length > 0 && (
          <section>
            <h2 className="text-[17px] font-bold tracking-[-0.02em]">
              {t("Features")}
            </h2>
            <ul className="mt-3 space-y-2.5">
              {features.map((f, i) => (
                <li key={`${f.title}-${i}`} className="flex gap-3">
                  <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-blue" />
                  <div>
                    <p className="text-[14px] font-semibold tracking-[-0.01em]">
                      {f.title}
                    </p>
                    {f.detail && (
                      <p className="mt-0.5 text-[13px] leading-relaxed text-ink-2">
                        {f.detail}
                      </p>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          </section>
        )}

        {related.length > 0 && (
          <section>
            <h2 className="text-[17px] font-bold tracking-[-0.02em]">
              {t("More from the catalog")}
            </h2>
            <div className="mt-2 surface-card px-3">
              {related.slice(0, 3).map((a) => (
                <AppRow key={a.id} app={a} />
              ))}
            </div>
          </section>
        )}
      </div>

      <aside className="h-fit space-y-3 rounded-2xl bg-surface px-4 py-4 shadow-[var(--shadow-sm)]">
        <MetaRow label={t("Category")} value={app.category || "—"} />
        <MetaRow label={t("Type")} value={app.kind} />
        <MetaRow label={t("File")} value={app.fileName} />
        {app.source && (
          <MetaRow
            label={t("Source")}
            value={`${app.source.repo}@${app.source.commit.slice(0, 10)}`}
            mono
          />
        )}
        {app.scanHistory && app.scanHistory.length > 0 && (
          <div className="space-y-1.5 border-t border-[var(--line)] pt-3">
            <p className="text-[12px] font-semibold text-ink">{t("Verification history")}</p>
            <ul className="space-y-1">
              {[...app.scanHistory].reverse().slice(0, 5).map((h) => (
                <li key={h.scanId} className="flex items-baseline justify-between gap-2 text-[11px] text-ink-3">
                  <span className="tabular-nums">{h.at.slice(0, 16).replace("T", " ")}</span>
                  <span className="font-semibold text-ink">
                    {t(readinessWord(h.readiness))} · {h.score}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        )}
        {developer && (
          <div className="space-y-1 border-t border-[var(--line)] pt-3">
            <MetaRow label={t("Developer")} value={developer.name} />
            <p className="text-[12px] leading-relaxed text-ink-3">
              {fill(t("{total} app(s) · {verified} verified · {blocked} blocked"), {
                total: developer.total,
                verified: developer.verified,
                blocked: developer.blocked,
              })}
            </p>
            {developer.blocked > 0 && (
              <p className="text-[12px] text-red-ink">{t("This developer has builds that were blocked.")}</p>
            )}
          </div>
        )}
        <MetaRow label="SHA256" value={`${app.sha256.slice(0, 12)}…`} mono />
        {app.tags.length > 0 && (
          <div className="flex flex-wrap gap-1.5 pt-1">
            {app.tags.map((t) => (
              <span
                key={t}
                className="rounded-full bg-black/[0.04] px-2.5 py-0.5 text-[11px] font-medium text-ink-2"
              >
                {t}
              </span>
            ))}
          </div>
        )}
        {typeof app.scan?.securityScore === "number" && (
          <p className="border-t border-[var(--line)] pt-3 text-[12px] text-ink-3">
            {t("Trust score")}{" "}
            <span className="font-semibold tabular-nums text-ink">
              {app.scan.trustScore ?? app.scan.securityScore}
            </span>
            {" · "}
            {t("details in the «Audit» tab")}
          </p>
        )}
      </aside>
    </div>
  );
}

function GalleryTab({
  shots,
  features,
}: {
  shots: PublicStoreApp["screenshots"];
  features: PublicStoreApp["features"];
}) {
  const t = useT();
  const [active, setActive] = useState(0);
  if (!shots.length && !features.length) {
    return (
      <p className="text-[14px] text-ink-2">
        {t("The developer has not added screenshots or a feature list yet.")}
      </p>
    );
  }

  return (
    <div className="space-y-8">
      {shots.length > 0 && (
        <section>
          <div className="overflow-hidden rounded-2xl bg-black/[0.04]">
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img
              src={shots[active]?.url}
              alt={shots[active]?.caption ?? "Screenshot"}
              className="mx-auto max-h-[520px] w-auto object-contain"
            />
          </div>
          {shots.length > 1 && (
            <div className="mt-3 flex gap-2 overflow-x-auto pb-1">
              {shots.map((s, i) => (
                <button
                  key={s.id}
                  type="button"
                  onClick={() => setActive(i)}
                  className={`h-16 w-24 shrink-0 overflow-hidden rounded-lg border-2 ${
                    i === active
                      ? "border-blue"
                      : "border-transparent opacity-70 hover:opacity-100"
                  }`}
                >
                  {/* eslint-disable-next-line @next/next/no-img-element */}
                  <img
                    src={s.url}
                    alt={s.caption ?? ""}
                    className="h-full w-full object-cover"
                  />
                </button>
              ))}
            </div>
          )}
          {shots[active]?.caption && (
            <p className="mt-2 text-[13px] text-ink-3">{shots[active].caption}</p>
          )}
        </section>
      )}

      {features.length > 0 && (
        <section>
          <h2 className="text-[17px] font-bold tracking-[-0.02em]">{t("Feature list")}</h2>
          <div className="mt-3 grid gap-3 sm:grid-cols-2">
            {features.map((f, i) => (
              <div
                key={`${f.title}-${i}`}
                className="rounded-2xl bg-surface px-4 py-3.5 shadow-[var(--shadow-sm)]"
              >
                <p className="text-[14px] font-semibold">{f.title}</p>
                {f.detail && (
                  <p className="mt-1 text-[13px] leading-relaxed text-ink-2">
                    {f.detail}
                  </p>
                )}
              </div>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}

function MetaRow({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="flex items-baseline justify-between gap-3 text-[12px]">
      <span className="text-ink-3">{label}</span>
      <span
        className={`truncate text-right font-medium text-ink ${
          mono ? "font-mono text-[11px]" : ""
        }`}
      >
        {value}
      </span>
    </div>
  );
}

function readinessWord(r: "ready" | "needs_fixes" | "blocked"): string {
  return r === "ready" ? "Ready" : r === "needs_fixes" ? "Needs fixes" : "Blocked";
}
