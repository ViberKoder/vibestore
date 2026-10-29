import Link from "next/link";
import { AppIcon } from "@/components/app-icon";
import { SafetyBadge } from "@/components/safety-badge";
import { formatNumber } from "@/lib/format";
import { listApps } from "@/lib/store";

export default async function DashboardPage() {
  const apps = await listApps({ status: "all" });

  return (
    <main className="flex-1 pb-20 pt-8 md:pt-12">
      <div className="container-store">
        <div className="fade-up flex flex-col gap-5 md:flex-row md:items-end md:justify-between">
          <div>
            <p className="text-[13px] font-semibold uppercase tracking-[0.14em] text-ink-3">
              Кабинет
            </p>
            <h1 className="mt-2 text-[36px] font-extrabold tracking-[-0.04em] md:text-[44px]">
              Готовность к релизу
            </h1>
            <p className="mt-3 max-w-xl text-[16px] text-ink-2">
              Security score и вердикт движков — можно ли выпускать продукт в
              массы.
            </p>
          </div>
          <Link href="/publish" className="btn-primary shrink-0">
            Новая публикация
          </Link>
        </div>

        <div className="fade-up-d1 mt-10 overflow-hidden surface-card">
          <div className="hidden grid-cols-[1.4fr_1fr_80px_1.2fr_90px] gap-3 border-b border-black/[0.06] px-5 py-3 text-[11px] font-semibold uppercase tracking-[0.1em] text-ink-3 md:grid">
            <span>Приложение</span>
            <span>Статус</span>
            <span>Score</span>
            <span>Readiness</span>
            <span className="text-right">Loads</span>
          </div>
          {apps.map((app) => (
            <Link
              key={app.id}
              href={`/apps/${app.slug}`}
              className="flex items-center gap-4 border-b border-black/[0.06] px-4 py-4 transition hover:bg-black/[0.02] last:border-0 md:grid md:grid-cols-[1.4fr_1fr_80px_1.2fr_90px] md:gap-3 md:px-5"
            >
              <div className="flex min-w-0 items-center gap-3">
                <AppIcon app={app} size="sm" />
                <div className="min-w-0">
                  <div className="truncate text-[15px] font-semibold tracking-[-0.02em]">
                    {app.name}
                  </div>
                  <div className="text-[12px] text-ink-3">v{app.version}</div>
                </div>
              </div>
              <div>
                <SafetyBadge app={app} />
              </div>
              <div className="hidden text-[14px] font-semibold tabular-nums md:block">
                {app.scan?.securityScore ?? "—"}
              </div>
              <div className="hidden truncate text-[13px] text-ink-2 md:block">
                {app.scan?.readinessLabel ?? "—"}
              </div>
              <div className="ml-auto text-[13px] tabular-nums text-ink-2 md:ml-0 md:text-right">
                {formatNumber(app.downloads)}
              </div>
            </Link>
          ))}
        </div>
      </div>
    </main>
  );
}
