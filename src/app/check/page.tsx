import { UrlCheckForm } from "@/components/url-check-form";
import { getT } from "@/lib/i18n/server";

export default async function CheckPage() {
  const t = await getT();
  return (
    <main className="flex-1 pb-20 pt-8 md:pt-12">
      <div className="container-store max-w-3xl">
        <div className="fade-up">
          <p className="text-[13px] font-semibold uppercase tracking-[0.14em] text-ink-3">
            {t("Website check")}
          </p>
          <h1 className="mt-2 text-[36px] font-extrabold tracking-[-0.04em] text-ink md:text-[44px]">
            {t("Is this site safe?")}
          </h1>
          <p className="mt-3 text-[16px] leading-relaxed text-ink-2">
            {t(
              "Enter a public address. We check TLS and security headers, forms that collect passwords, scripts and trackers, and ask VirusTotal about the URL. Only public addresses are fetched.",
            )}
          </p>
        </div>
        <div className="fade-up-d1 mt-8 surface-card p-6 md:p-8">
          <UrlCheckForm />
        </div>
      </div>
    </main>
  );
}
