import Link from "next/link";
import { AppIcon } from "@/components/app-icon";
import { DashboardAppActions } from "@/components/dashboard-app-actions";
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
              Ваши приложения
            </h1>
            <p className="mt-3 max-w-xl text-[16px] text-ink-2">
              Управление приложением — только с ключом владельца, выданным при
              публикации.
            </p>
          </div>
          <Link href="/publish" className="btn-primary shrink-0">
            Новая публикация
          </Link>
        </div>

        <div className="fade-up-d1 mt-10 overflow-hidden surface-card">
          <div className="hidden grid-cols-[1.3fr_0.9fr_70px_1fr_88px_150px] gap-3 border-b border-[var(--line)] px-5 py-3 text-[11px] font-semibold uppercase tracking-[0.1em] text-ink-3 md:grid">
            <span>Приложение</span>
            <span>Статус</span>
            <span>Score</span>
            <span>Readiness</span>
            <span className="text-right">Loads</span>
            <span className="text-right">Действия</span>
          </div>
          {apps.length === 0 && (
            <p className="px-5 py-10 text-center text-[14px] text-ink-2">
              Пока пусто.{" "}
              <Link href="/publish" className="font-semibold text-blue">
                Опубликуйте первое приложение
              </Link>
            </p>
          )}
          {apps.map((app) => (
            <div
              key={app.id}
              className="flex flex-col gap-3 border-b border-[var(--line)] px-4 py-4 last:border-0 md:grid md:grid-cols-[1.3fr_0.9fr_70px_1fr_88px_150px] md:items-center md:gap-3 md:px-5"
            >
              <Link
                href={`/apps/${app.slug}`}
                className="flex min-w-0 items-center gap-3"
              >
                <AppIcon app={app} size="sm" />
                <div className="min-w-0">
                  <div className="truncate text-[15px] font-semibold tracking-[-0.02em]">
                    {app.name}
                  </div>
                  <div className="text-[12px] text-ink-3">v{app.version}</div>
                </div>
              </Link>
              <div>
                <SafetyBadge app={app} />
              </div>
              <div className="hidden text-[14px] font-semibold tabular-nums md:block">
                {app.scan?.securityScore ?? "—"}
              </div>
              <div className="hidden truncate text-[13px] text-ink-2 md:block">
                {app.scan?.readinessLabel ?? "—"}
              </div>
              <div className="hidden text-[13px] tabular-nums text-ink-2 md:block md:text-right">
                {formatNumber(app.downloads)}
              </div>
              <div className="md:justify-self-end">
                <DashboardAppActions appId={app.id} slug={app.slug} name={app.name} />
              </div>
            </div>
          ))}
        </div>
      </div>
    </main>
  );
}
