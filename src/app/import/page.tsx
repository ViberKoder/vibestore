import { GithubImportForm } from "@/components/github-import-form";
import { getT } from "@/lib/i18n/server";

export default async function ImportPage() {
  const t = await getT();
  return (
    <main className="flex-1 pb-20 pt-8 md:pt-12">
      <div className="container-store max-w-5xl">
        <div className="fade-up">
          <p className="text-[13px] font-semibold uppercase tracking-[0.14em] text-ink-3">{t("Import from GitHub")}</p>
          <h1 className="mt-2 text-[36px] font-extrabold tracking-[-0.04em] text-ink md:text-[44px]">
            {t("Publish a repository")}
          </h1>
          <p className="mt-3 max-w-2xl text-[16px] leading-relaxed text-ink-2">
            {t("Your source archive goes through the same scanners as an upload. Nothing is built or run on our side.")}
          </p>
        </div>
        <div className="fade-up-d1 mt-8 surface-card p-6 md:p-8">
          <GithubImportForm />
        </div>
      </div>
    </main>
  );
}
