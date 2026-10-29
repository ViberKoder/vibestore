import Link from "next/link";
import { headers } from "next/headers";
import { notFound } from "next/navigation";
import { AppDetail } from "@/components/app-detail";
import { isAppOwner, toPublicApp } from "@/lib/owner-auth";
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

  const cookie = (await headers()).get("cookie");
  const owner = isAppOwner(app, cookie);
  const canClaim = !app.ownerId;

  const forceScanning = sp.scanning === "1";
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
          ← Каталог
        </Link>

        <div className="mt-5">
          <AppDetail
            app={toPublicApp(app, { isOwner: owner })}
            related={related}
            forceScanning={forceScanning}
            showManage={owner || canClaim}
          />
        </div>
      </div>
    </main>
  );
}
