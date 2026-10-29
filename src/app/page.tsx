import { Suspense } from "react";
import Link from "next/link";
import { AppRow } from "@/components/app-row";
import { CatalogSearch } from "@/components/catalog-search";
import { CollectionCard } from "@/components/collection-card";
import { FeaturedCard } from "@/components/featured-card";
import { SectionHeader } from "@/components/section-header";
import { TrustStrip } from "@/components/trust-strip";
import { listApps } from "@/lib/store";
import type { StoreApp } from "@/lib/types";

export default async function Home({
  searchParams,
}: {
  searchParams: Promise<{ q?: string; status?: string }>;
}) {
  const sp = await searchParams;
  const q = sp.q ?? "";
  const showAll = sp.status === "all";

  const published = await listApps({ status: "published", q });
  const all = showAll ? await listApps({ status: "all", q }) : published;
  const catalog = showAll
    ? all.filter((a) => a.status !== "queued")
    : published;

  const featured =
    published.find((a) => a.slug === "pixel-notes") ?? published[0];
  const topCharts = published.slice(0, 6);
  const desktop = published.filter((a) => a.kind === "desktop");
  const web = published.filter((a) => a.kind === "web");
  const caution = (await listApps({ status: "all" })).filter(
    (a) => a.status === "quarantined" || a.status === "rejected",
  );

  return (
    <main className="flex-1 pb-20 pt-6 md:pt-10">
      <div className="container-store space-y-10 md:space-y-14">
        <section className="fade-up max-w-2xl">
          <p className="text-[13px] font-semibold uppercase tracking-[0.14em] text-ink-3">
            Discover
          </p>
          <h1 className="mt-2 text-[40px] font-extrabold leading-[1.05] tracking-[-0.045em] text-ink md:text-[56px]">
            Приложения,
            <br />
            которым можно доверять.
          </h1>
          <p className="mt-4 max-w-xl text-[17px] leading-relaxed text-ink-2 md:text-[19px]">
            Vibe Store — каталог вайбкодерских программ и сайтов. Каждая сборка
            проходит VirusTotal, ClamAV и собственные проверки до публикации.
          </p>
          <div className="mt-7 flex flex-wrap gap-3">
            <Link href="#catalog" className="btn-primary">
              Смотреть каталог
            </Link>
            <Link href="/publish" className="btn-secondary">
              Опубликовать приложение
            </Link>
          </div>
        </section>

        {featured && (
          <section className="fade-up-d1">
            <FeaturedCard app={featured} />
          </section>
        )}

        <section className="fade-up-d2">
          <TrustStrip />
        </section>

        {!q && (
          <section>
            <SectionHeader
              title="Подборки"
              subtitle="Как в App Store — по смыслу, не по хаосу"
            />
            <div className="rail">
              <CollectionCard
                title="Проверено сегодня"
                subtitle="Сборки с высоким security score"
                apps={published}
                href="/#catalog"
              />
              <CollectionCard
                title="Для Mac и Windows"
                subtitle="Desktop-утилиты и .exe"
                apps={desktop.length ? desktop : published}
                href="/?status=all#catalog"
              />
              <CollectionCard
                title="Веб-инструменты"
                subtitle="Сайты и HTML-утилиты"
                apps={web.length ? web : published}
                href="/#catalog"
              />
            </div>
          </section>
        )}

        {!q && topCharts.length > 0 && (
          <section>
            <SectionHeader
              title="Топ чарт"
              subtitle="Популярные проверенные приложения"
            />
            <div className="surface-card px-4 md:px-6">
              <ChartGrid apps={topCharts} />
            </div>
          </section>
        )}

        <section id="catalog">
          <div className="mb-5 flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
            <div>
              <h2 className="text-[22px] font-bold tracking-[-0.03em] md:text-[24px]">
                {q ? `Результаты: «${q}»` : "Каталог"}
              </h2>
              <p className="mt-1 text-[13px] text-ink-2">
                {showAll
                  ? "Все статусы, включая карантин и блокировки"
                  : "Только сборки со статусом «Проверено»"}
              </p>
            </div>
            <div className="flex flex-col items-stretch gap-3 sm:flex-row sm:items-center">
              <Suspense fallback={null}>
                <CatalogSearch initialQ={q} />
              </Suspense>
              <div className="flex gap-1 rounded-full bg-black/[0.04] p-1 text-[12px] font-semibold">
                <Link
                  href="/#catalog"
                  className={`rounded-full px-3 py-1.5 ${
                    !showAll ? "bg-white text-ink shadow-sm" : "text-ink-2"
                  }`}
                >
                  Безопасные
                </Link>
                <Link
                  href="/?status=all#catalog"
                  className={`rounded-full px-3 py-1.5 ${
                    showAll ? "bg-white text-ink shadow-sm" : "text-ink-2"
                  }`}
                >
                  Все
                </Link>
              </div>
            </div>
          </div>

          <div className="surface-card px-4 md:px-6">
            {catalog.length === 0 ? (
              <p className="py-16 text-center text-[14px] text-ink-2">
                Ничего не найдено.{" "}
                <Link href="/publish" className="text-blue hover:underline">
                  Опубликуйте первую сборку
                </Link>
              </p>
            ) : (
              catalog.map((app) => <AppRow key={app.id} app={app} />)
            )}
          </div>
        </section>

        {!q && caution.length > 0 && (
          <section>
            <SectionHeader
              title="Лаборатория угроз"
              subtitle="Учебные и заблокированные образцы — скачивание закрыто"
              href="/security"
              action="Как ловим"
            />
            <div className="surface-card px-4 md:px-6">
              {caution.map((app) => (
                <AppRow key={app.id} app={app} />
              ))}
            </div>
          </section>
        )}
      </div>
    </main>
  );
}

function ChartGrid({ apps }: { apps: StoreApp[] }) {
  if (apps.length <= 3) {
    return (
      <>
        {apps.map((app, i) => (
          <AppRow key={app.id} app={app} rank={i + 1} />
        ))}
      </>
    );
  }

  const mid = Math.ceil(apps.length / 2);
  const left = apps.slice(0, mid);
  const right = apps.slice(mid);

  return (
    <div className="grid md:grid-cols-2 md:gap-10">
      <div>
        {left.map((app, i) => (
          <AppRow key={app.id} app={app} rank={i + 1} />
        ))}
      </div>
      <div className="hidden md:block">
        {right.map((app, i) => (
          <AppRow key={app.id} app={app} rank={mid + i + 1} />
        ))}
      </div>
    </div>
  );
}
