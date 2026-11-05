import { Suspense } from "react";
import Link from "next/link";
import { AppRow } from "@/components/app-row";
import { CatalogSearch } from "@/components/catalog-search";
import { CollectionCard } from "@/components/collection-card";
import { FeaturedCard } from "@/components/featured-card";
import { SectionHeader } from "@/components/section-header";
import { TrustStrip } from "@/components/trust-strip";
import { getT } from "@/lib/i18n/server";
import { listApps } from "@/lib/store";
import type { StoreApp } from "@/lib/types";

export default async function Home({
  searchParams,
}: {
  searchParams: Promise<{ q?: string; status?: string }>;
}) {
  const sp = await searchParams;
  const t = await getT();
  const q = sp.q ?? "";
  const showAll = sp.status === "all";

  const published = await listApps({ status: "published", q });
  const all = showAll ? await listApps({ status: "all", q }) : published;
  const catalog = showAll
    ? all.filter((a) => a.status !== "queued")
    : published;

  const featured = published[0];
  const topCharts = published.slice(0, 6);
  const desktop = published.filter((a) => a.kind === "desktop");
  const web = published.filter((a) => a.kind === "web");
  const caution = (await listApps({ status: "all" })).filter(
    (a) => a.status === "quarantined" || a.status === "rejected",
  );
  const hasApps = (await listApps({ status: "all" })).length > 0;

  return (
    <main className="flex-1 pb-20 pt-6 md:pt-10">
      <div className="container-store space-y-10 md:space-y-14">
        <section className="fade-up max-w-2xl">
          <p className="text-[13px] font-semibold uppercase tracking-[0.14em] text-ink-3">
            {t("Discover")}
          </p>
          <h1 className="mt-2 text-[40px] font-extrabold leading-[1.05] tracking-[-0.045em] text-ink md:text-[56px]">
            {t("Apps you can trust.")}
          </h1>
          <p className="mt-4 max-w-xl text-[17px] leading-relaxed text-ink-2 md:text-[19px]">
            {t(
              "Vibe Store is a catalog of vibe-coded programs and websites. Every build goes through VirusTotal, ClamAV and our own checks before it is published.",
            )}
          </p>
          <div className="mt-7 flex flex-wrap gap-3">
            <Link href={hasApps ? "#catalog" : "/publish"} className="btn-primary">
              {hasApps ? t("Browse the catalog") : t("Publish your first app")}
            </Link>
            <Link href="/publish" className="btn-secondary">
              {t("Publish an app")}
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

        {!q && published.length > 0 && (
          <section>
            <SectionHeader
              title={t("Collections")}
              subtitle={t("Like the App Store — by meaning, not chaos")}
            />
            <div className="rail">
              <CollectionCard
                title={t("Verified today")}
                subtitle={t("Builds with a high security score")}
                apps={published}
                href="/#catalog"
              />
              {desktop.length > 0 && (
                <CollectionCard
                  title={t("For Mac and Windows")}
                  subtitle={t("Desktop utilities and .exe")}
                  apps={desktop}
                  href="/?status=all#catalog"
                />
              )}
              {web.length > 0 && (
                <CollectionCard
                  title={t("Web tools")}
                  subtitle={t("Websites and HTML utilities")}
                  apps={web}
                  href="/#catalog"
                />
              )}
            </div>
          </section>
        )}

        {!q && topCharts.length > 0 && (
          <section>
            <SectionHeader
              title={t("Top chart")}
              subtitle={t("Popular verified apps")}
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
                {q ? `${t("Results for")} «${q}»` : t("Catalog")}
              </h2>
              <p className="mt-1 text-[13px] text-ink-2">
                {showAll
                  ? t("All statuses, including quarantined and blocked")
                  : t("Only builds with the «Verified» status")}
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
                  {t("Safe")}
                </Link>
                <Link
                  href="/?status=all#catalog"
                  className={`rounded-full px-3 py-1.5 ${
                    showAll ? "bg-white text-ink shadow-sm" : "text-ink-2"
                  }`}
                >
                  {t("All")}
                </Link>
              </div>
            </div>
          </div>

          <div className="surface-card px-4 md:px-6">
            {catalog.length === 0 ? (
              <div className="py-16 text-center">
                <p className="text-[16px] font-semibold text-ink">
                  {t("The catalog is empty")}
                </p>
                <p className="mt-2 text-[14px] text-ink-2">
                  {t("Only real builds appear here after checks. There are no fake apps.")}
                </p>
                <Link href="/publish" className="btn-primary mt-6 inline-flex">
                  {t("Publish a build")}
                </Link>
              </div>
            ) : (
              catalog.map((app) => <AppRow key={app.id} app={app} />)
            )}
          </div>
        </section>

        {!q && caution.length > 0 && (
          <section>
            <SectionHeader
              title={t("Rejected / needs work")}
              subtitle={t("Real builds that did not pass the checks")}
              href="/security"
              action={t("How we catch threats")}
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
