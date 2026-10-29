import Link from "next/link";
import { SafetyBadge } from "@/components/safety-badge";
import { formatNumber } from "@/lib/format";
import { listApps } from "@/lib/store";

export default async function DashboardPage() {
  const apps = await listApps({ status: "all" });

  return (
    <main className="mx-auto w-full max-w-6xl flex-1 px-5 pb-20 pt-6 md:px-8">
      <div className="flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
        <div className="anim-rise">
          <p className="text-sm uppercase tracking-[0.16em] text-ink-soft">
            Кабинет разработчика
          </p>
          <h1 className="mt-2 font-display text-4xl font-extrabold tracking-tight">
            Готовность к релизу
          </h1>
          <p className="mt-2 max-w-xl text-ink-soft">
            Смотрите security score и вердикт движков — можно ли выпускать
            продукт в массы.
          </p>
        </div>
        <Link
          href="/publish"
          className="anim-rise-delay-1 inline-flex h-11 items-center rounded-xl bg-teal px-5 text-sm font-semibold text-white hover:bg-teal-deep"
        >
          Новая публикация
        </Link>
      </div>

      <div className="mt-10 overflow-hidden rounded-2xl bg-white/60 ring-1 ring-ink/8">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-ink/10 text-xs uppercase tracking-wider text-ink-soft">
            <tr>
              <th className="px-4 py-3 font-medium">Приложение</th>
              <th className="px-4 py-3 font-medium">Статус</th>
              <th className="px-4 py-3 font-medium">Score</th>
              <th className="hidden px-4 py-3 font-medium md:table-cell">
                Readiness
              </th>
              <th className="hidden px-4 py-3 font-medium sm:table-cell">
                Downloads
              </th>
            </tr>
          </thead>
          <tbody>
            {apps.map((app) => (
              <tr key={app.id} className="border-b border-ink/5 last:border-0">
                <td className="px-4 py-3">
                  <Link
                    href={`/apps/${app.slug}`}
                    className="font-medium text-ink hover:text-teal-deep"
                  >
                    {app.name}
                  </Link>
                  <div className="font-mono text-xs text-ink-soft">
                    v{app.version}
                  </div>
                </td>
                <td className="px-4 py-3">
                  <SafetyBadge app={app} />
                </td>
                <td className="px-4 py-3 font-mono">
                  {app.scan?.securityScore ?? "—"}
                </td>
                <td className="hidden px-4 py-3 text-ink-soft md:table-cell">
                  {app.scan?.readinessLabel ?? "—"}
                </td>
                <td className="hidden px-4 py-3 font-mono sm:table-cell">
                  {formatNumber(app.downloads)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </main>
  );
}
