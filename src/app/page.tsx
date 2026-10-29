import { Suspense } from "react";
import Link from "next/link";
import { AppCard } from "@/components/app-card";
import { CatalogSearch } from "@/components/catalog-search";
import { HeroScanVisual } from "@/components/hero-scan-visual";
import { listApps } from "@/lib/store";

export default async function Home({
  searchParams,
}: {
  searchParams: Promise<{ q?: string; status?: string }>;
}) {
  const sp = await searchParams;
  const q = sp.q ?? "";
  const statusFilter = sp.status === "all" ? "all" : "published";

  const published = await listApps({ status: "published", q });
  const extra =
    statusFilter === "all"
      ? await listApps({ status: "all", q })
      : published;
  const apps =
    statusFilter === "all"
      ? extra.filter((a) => a.status !== "queued")
      : published;

  return (
    <main className="flex-1">
      <section className="mx-auto grid w-full max-w-6xl items-center gap-10 px-5 pb-16 pt-6 md:grid-cols-2 md:px-8 md:pb-24 md:pt-10">
        <div className="anim-rise">
          <p className="font-display text-5xl font-extrabold leading-[0.95] tracking-tight text-ink sm:text-6xl md:text-7xl">
            Vibe&nbsp;Store
          </p>
          <h1 className="mt-5 max-w-md text-xl font-medium leading-snug text-ink md:text-2xl">
            App Store для вайбкодерских приложений — скачивай только после
            проверки.
          </h1>
          <p className="mt-4 max-w-md text-base leading-relaxed text-ink-soft">
            VirusTotal, ClamAV, ClamWin и собственные движки ловят вирусы,
            трояны, стиллеры и баги до того, как файл попадёт к пользователю.
          </p>
          <div className="mt-8 flex flex-wrap gap-3">
            <Link
              href="#catalog"
              className="inline-flex h-12 items-center rounded-xl bg-teal px-5 text-sm font-semibold text-white transition hover:bg-teal-deep"
            >
              Открыть каталог
            </Link>
            <Link
              href="/publish"
              className="inline-flex h-12 items-center rounded-xl bg-white/70 px-5 text-sm font-semibold text-ink ring-1 ring-ink/10 transition hover:bg-white"
            >
              Опубликовать сборку
            </Link>
          </div>
        </div>
        <div className="anim-rise-delay-1">
          <HeroScanVisual />
        </div>
      </section>

      <section
        id="catalog"
        className="mx-auto w-full max-w-6xl px-5 pb-20 md:px-8"
      >
        <div className="anim-rise-delay-2 flex flex-col gap-4 border-t border-ink/10 pt-10 md:flex-row md:items-end md:justify-between">
          <div>
            <h2 className="font-display text-3xl font-bold tracking-tight">
              Каталог
            </h2>
            <p className="mt-1 text-sm text-ink-soft">
              {statusFilter === "published"
                ? "Только сборки со статусом «Проверено»."
                : "Все статусы, включая карантин и блокировки."}
            </p>
          </div>
          <div className="flex flex-col items-stretch gap-3 sm:items-end">
            <Suspense fallback={null}>
              <CatalogSearch initialQ={q} />
            </Suspense>
            <div className="flex gap-2 text-xs">
              <Link
                href="/#catalog"
                className={`rounded-md px-2 py-1 ${statusFilter === "published" ? "bg-teal/15 text-teal-deep" : "text-ink-soft"}`}
              >
                Безопасные
              </Link>
              <Link
                href="/?status=all#catalog"
                className={`rounded-md px-2 py-1 ${statusFilter === "all" ? "bg-teal/15 text-teal-deep" : "text-ink-soft"}`}
              >
                Все статусы
              </Link>
            </div>
          </div>
        </div>

        <div className="mt-2">
          {apps.length === 0 ? (
            <p className="py-16 text-center text-ink-soft">
              Ничего не найдено. Опубликуйте первую сборку.
            </p>
          ) : (
            apps.map((app, i) => <AppCard key={app.id} app={app} index={i} />)
          )}
        </div>
      </section>
    </main>
  );
}
