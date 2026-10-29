import Link from "next/link";
import { notFound } from "next/navigation";
import { ScanReportView } from "@/components/scan-report";
import { SafetyBadge } from "@/components/safety-badge";
import { formatBytes, formatNumber } from "@/lib/format";
import { getAppBySlug } from "@/lib/store";

export default async function AppPage({
  params,
}: {
  params: Promise<{ slug: string }>;
}) {
  const { slug } = await params;
  const app = await getAppBySlug(slug);
  if (!app) notFound();

  const canDownload =
    app.status === "published" ||
    (app.status === "quarantined" && app.scan?.readiness !== "blocked");

  return (
    <main className="mx-auto w-full max-w-6xl flex-1 px-5 pb-20 pt-4 md:px-8">
      <Link
        href="/#catalog"
        className="text-sm text-ink-soft transition hover:text-ink"
      >
        ← Каталог
      </Link>

      <div className="mt-6 grid gap-10 lg:grid-cols-[1.1fr_0.9fr]">
        <section className="anim-rise">
          <div className="flex items-start gap-5">
            <div
              className="grid h-20 w-20 shrink-0 place-items-center rounded-3xl text-2xl font-bold text-white"
              style={{
                background: `linear-gradient(145deg, hsl(${app.iconHue} 42% 38%), hsl(${(app.iconHue + 40) % 360} 48% 28%))`,
              }}
            >
              {app.name.slice(0, 1)}
            </div>
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <h1 className="font-display text-4xl font-extrabold tracking-tight md:text-5xl">
                  {app.name}
                </h1>
                <SafetyBadge app={app} />
              </div>
              <p className="mt-2 text-lg text-ink-soft">{app.tagline}</p>
            </div>
          </div>

          <p className="mt-8 max-w-2xl text-base leading-relaxed text-ink">
            {app.description}
          </p>

          <dl className="mt-8 grid grid-cols-2 gap-3 text-sm md:grid-cols-3">
            <Meta label="Разработчик" value={app.developerName} />
            <Meta label="Версия" value={app.version} />
            <Meta label="Категория" value={app.category} />
            <Meta label="Тип" value={app.kind} />
            <Meta label="Файл" value={app.fileName} />
            <Meta label="Размер" value={formatBytes(app.fileSize)} />
            <Meta label="Загрузки" value={formatNumber(app.downloads)} />
            <Meta
              label="SHA256"
              value={`${app.sha256.slice(0, 12)}…`}
              mono
            />
          </dl>

          {app.tags.length > 0 && (
            <div className="mt-6 flex flex-wrap gap-2">
              {app.tags.map((t) => (
                <span
                  key={t}
                  className="rounded-md bg-white/60 px-2 py-1 text-xs text-ink-soft ring-1 ring-ink/8"
                >
                  {t}
                </span>
              ))}
            </div>
          )}

          <div className="mt-10 flex flex-wrap gap-3">
            {canDownload ? (
              <a
                href={`/api/apps/${app.id}/download`}
                className="inline-flex h-12 items-center rounded-xl bg-teal px-6 text-sm font-semibold text-white transition hover:bg-teal-deep"
              >
                Скачать
                {app.status === "quarantined" ? " (на свой риск)" : ""}
              </a>
            ) : (
              <span className="inline-flex h-12 items-center rounded-xl bg-coral/15 px-6 text-sm font-semibold text-coral ring-1 ring-coral/25">
                Скачивание заблокировано
              </span>
            )}
            {app.homepage && (
              <a
                href={app.homepage}
                target="_blank"
                rel="noreferrer"
                className="inline-flex h-12 items-center rounded-xl bg-white/70 px-6 text-sm font-semibold ring-1 ring-ink/10"
              >
                Сайт проекта
              </a>
            )}
          </div>
        </section>

        <aside className="anim-rise-delay-1 rounded-[1.5rem] bg-white/55 p-6 ring-1 ring-ink/8 md:p-8">
          {app.scan ? (
            <ScanReportView report={app.scan} />
          ) : (
            <p className="text-ink-soft">Отчёт сканирования ещё не готов.</p>
          )}
        </aside>
      </div>
    </main>
  );
}

function Meta({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="rounded-xl bg-white/55 px-3 py-3 ring-1 ring-ink/8">
      <dt className="text-[10px] uppercase tracking-wider text-ink-soft">
        {label}
      </dt>
      <dd className={`mt-1 ${mono ? "font-mono text-xs" : "font-medium"}`}>
        {value}
      </dd>
    </div>
  );
}
