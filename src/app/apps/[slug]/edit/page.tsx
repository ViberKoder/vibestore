import Link from "next/link";
import { notFound } from "next/navigation";
import { AppEditForm } from "@/components/app-edit-form";
import { getAppBySlug } from "@/lib/store";

export default async function EditAppPage({
  params,
}: {
  params: Promise<{ slug: string }>;
}) {
  const { slug } = await params;
  const app = await getAppBySlug(slug);
  if (!app) notFound();

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
          Редактировать
        </h1>
        <p className="mt-2 text-[14px] text-ink-2">
          Аватарка, описание, версия, скриншоты — или новая сборка с ресканом.
        </p>
        <div className="mt-8 surface-card px-5 py-6 md:px-7 md:py-7">
          <AppEditForm app={app} />
        </div>
      </div>
    </main>
  );
}
