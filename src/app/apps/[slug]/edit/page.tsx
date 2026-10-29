import Link from "next/link";
import { headers } from "next/headers";
import { notFound } from "next/navigation";
import { AppEditForm } from "@/components/app-edit-form";
import { OwnerGate } from "@/components/owner-gate";
import { isAppOwner, toPublicApp } from "@/lib/owner-auth";
import { getAppBySlug } from "@/lib/store";

export default async function EditAppPage({
  params,
}: {
  params: Promise<{ slug: string }>;
}) {
  const { slug } = await params;
  const app = await getAppBySlug(slug);
  if (!app) notFound();

  const cookie = (await headers()).get("cookie");
  const owner = isAppOwner(app, cookie);
  const publicApp = toPublicApp(app, { isOwner: owner });

  return (
    <main className="flex-1 pb-16 pt-6 md:pt-8">
      <div className="container-store max-w-3xl">
        <Link
          href={`/apps/${app.slug}`}
          className="text-[14px] font-medium text-blue hover:underline"
        >
          ← {app.name}
        </Link>
        <h1 className="mt-4 text-[28px] font-extrabold tracking-[-0.04em] md:text-[34px]">
          Управление
        </h1>
        <p className="mt-2 text-[14px] text-ink-2">
          Доступно только с браузера, с которого загрузили приложение.
        </p>
        <div className="mt-8 surface-card px-5 py-6 md:px-7 md:py-7">
          <OwnerGate appId={app.id} appName={app.name}>
            <AppEditForm app={publicApp} />
          </OwnerGate>
        </div>
      </div>
    </main>
  );
}
