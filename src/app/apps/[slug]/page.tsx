import Link from "next/link";
import { notFound } from "next/navigation";
import { AppIcon } from "@/components/app-icon";
import { AppRow } from "@/components/app-row";
import { AppScanGate } from "@/components/app-scan-gate";
import { SafetyBadge } from "@/components/safety-badge";
import { formatBytes, formatNumber } from "@/lib/format";
import { getAppBySlug, listApps } from "@/lib/store";

export default async function AppPage({
  params,
  searchParams,
}: {
  params: Promise<{ slug: string }>;
  searchParams: Promise<{ scanning?: string }>;
}) {
  const { slug } = await params;
  const sp = await searchParams;
  const app = await getAppBySlug(slug);
  if (!app) notFound();

  const forceScanning = sp.scanning === "1";
  const canDownload =
    app.status === "published" ||
    (app.status === "quarantined" && app.scan?.readiness !== "blocked");

  const related = (await listApps({ status: "published" }))
    .filter((a) => a.id !== app.id)
    .slice(0, 4);

  return (
    <main className="flex-1 pb-20 pt-6 md:pt-10">
      <div className="container-store">
        <Link
          href="/#catalog"
          className="text-[14px] font-medium text-blue hover:underline"
        >
          ← Каталог
        </Link>

        <section className="fade-up mt-6 flex flex-col gap-6 sm:flex-row sm:items-start">
          <AppIcon app={app} size="xl" />
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2.5">
              <h1 className="text-[34px] font-extrabold tracking-[-0.04em] text-ink md:text-[44px]">
                {app.name}
              </h1>
              <SafetyBadge app={app} />
            </div>
            <p className="mt-1 text-[17px] text-blue">{app.developerName}</p>
            <p className="mt-3 max-w-xl text-[15px] leading-relaxed text-ink-2">
              {app.tagline}
            </p>

            <div className="mt-6 flex flex-wrap items-center gap-3">
              {canDownload ? (
                <a
                  href={`/api/apps/${app.id}/download`}
                  className="btn-primary !h-10 !px-6 !text-[14px]"
                >
                  {app.status === "quarantined"
                    ? "Скачать на свой риск"
                    : "Скачать"}
                </a>
              ) : app.status === "scanning" || forceScanning ? (
                <span className="inline-flex h-10 items-center rounded-full bg-blue-soft px-5 text-[14px] font-semibold text-blue">
                  Сканирование…
                </span>
              ) : (
                <span className="inline-flex h-10 items-center rounded-full bg-red-soft px-5 text-[14px] font-semibold text-red-ink">
                  Скачивание недоступно
                </span>
              )}
              {app.homepage && (
                <a
                  href={app.homepage}
                  target="_blank"
                  rel="noreferrer"
                  className="btn-secondary !h-10 !px-5 !text-[14px]"
                >
                  Сайт
                </a>
              )}
            </div>
          </div>
        </section>

        <div className="fade-up-d1 mt-10 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <Stat
            label="Оценка"
            value={String(app.scan?.securityScore ?? "—")}
          />
          <Stat label="Категория" value={app.category} />
          <Stat label="Версия" value={app.version} />
          <Stat label="Загрузки" value={formatNumber(app.downloads)} />
        </div>

        <div className="fade-up-d2 mt-12 grid gap-10 lg:grid-cols-[1fr_400px] lg:gap-14">
          <div className="space-y-10">
            <section>
              <h2 className="text-[20px] font-bold tracking-[-0.03em]">
                Описание
              </h2>
              <p className="mt-3 text-[15px] leading-[1.7] text-ink-2">
                {app.description}
              </p>
            </section>

            <section>
              <h2 className="text-[20px] font-bold tracking-[-0.03em]">
                Информация
              </h2>
              <dl className="mt-4 divide-y divide-black/[0.06] border-y border-black/[0.06]">
                <InfoRow label="Разработчик" value={app.developerName} />
                <InfoRow label="Размер" value={formatBytes(app.fileSize)} />
                <InfoRow label="Файл" value={app.fileName} />
                <InfoRow label="Тип" value={app.kind} />
                <InfoRow
                  label="SHA256"
                  value={`${app.sha256.slice(0, 16)}…`}
                  mono
                />
              </dl>
              {app.tags.length > 0 && (
                <div className="mt-4 flex flex-wrap gap-2">
                  {app.tags.map((t) => (
                    <span
                      key={t}
                      className="rounded-full bg-black/[0.04] px-3 py-1 text-[12px] font-medium text-ink-2"
                    >
                      {t}
                    </span>
                  ))}
                </div>
              )}
            </section>

            {related.length > 0 && (
              <section>
                <h2 className="text-[20px] font-bold tracking-[-0.03em]">
                  Ещё из каталога
                </h2>
                <div className="mt-3 surface-card px-4">
                  {related.map((a) => (
                    <AppRow key={a.id} app={a} />
                  ))}
                </div>
              </section>
            )}
          </div>

          <aside className="h-fit">
            <AppScanGate app={app} forceScanning={forceScanning} />
          </aside>
        </div>
      </div>
    </main>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-2xl bg-surface px-4 py-4 shadow-[var(--shadow-sm)]">
      <div className="text-[11px] font-semibold uppercase tracking-[0.12em] text-ink-3">
        {label}
      </div>
      <div className="mt-1 truncate text-[18px] font-bold tracking-[-0.02em]">
        {value}
      </div>
    </div>
  );
}

function InfoRow({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="flex items-baseline justify-between gap-4 py-3.5">
      <dt className="text-[13px] text-ink-2">{label}</dt>
      <dd
        className={`text-right text-[13px] font-medium text-ink ${
          mono ? "font-mono text-[12px]" : ""
        }`}
      >
        {value}
      </dd>
    </div>
  );
}
