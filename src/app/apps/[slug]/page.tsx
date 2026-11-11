import Link from "next/link";
import { headers } from "next/headers";
import { notFound } from "next/navigation";
import { AppDetail } from "@/components/app-detail";
import { isAppOwner, toPublicApp } from "@/lib/owner-auth";
import { getT } from "@/lib/i18n/server";
import { getAppBySlug, listApps } from "@/lib/store";

export default async function AppPage({
  params,
  searchParams,
}: {
  params: Promise<{ slug: string }>;
  searchParams: Promise<{ scanning?: string }>;
}) {
  const t = await getT();
  const { slug } = await params;
  const sp = await searchParams;
  const app = await getAppBySlug(slug);
  if (!app) notFound();

  const cookie = (await headers()).get("cookie");
  const owner = isAppOwner(app, cookie);
  const publicApp = toPublicApp(app, { isOwner: owner });

  const forceScanning = sp.scanning === "1";
  // Developer reputation from the catalogue itself: same GitHub account, else same developer name.
  const everything = await listApps({ status: "all" });
  const sameDev = (a: typeof app) =>
    app.ownerGithub
      ? a.ownerGithub?.id === app.ownerGithub.id
      : !a.ownerGithub && a.developerName.trim().toLowerCase() === app.developerName.trim().toLowerCase();
  const devApps = everything.filter(sameDev);
  const developer = {
    name: app.ownerGithub?.login ?? app.developerName,
    total: devApps.length,
    verified: devApps.filter((a) => a.status === "published").length,
    blocked: devApps.filter((a) => a.status === "rejected").length,
  };
  const related = (await listApps({ status: "published" }))
    .filter((a) => a.id !== app.id)
    .slice(0, 4)
    .map((a) => toPublicApp(a));

  return (
    <main className="flex-1 pb-16 pt-6 md:pt-8">
      <div className="container-store">
        <Link
          href="/#catalog"
          className="text-[14px] font-medium text-blue hover:underline"
        >
          ← {t("Catalog")}
        </Link>

        <div className="mt-5">
          <AppDetail
            app={publicApp}
            related={related}
            developer={developer}
            forceScanning={forceScanning}
            showManage={
              Boolean(publicApp.isOwner) ||
              !publicApp.hasOwner ||
              Boolean(publicApp.canRestore)
            }
          />
        </div>
      </div>
    </main>
  );
}
