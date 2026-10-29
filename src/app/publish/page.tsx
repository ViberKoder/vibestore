import { PublishForm } from "@/components/publish-form";

export default function PublishPage() {
  return (
    <main className="flex-1 pb-20 pt-8 md:pt-12">
      <div className="container-store max-w-2xl">
        <div className="fade-up">
          <p className="text-[13px] font-semibold uppercase tracking-[0.14em] text-ink-3">
            Для разработчиков
          </p>
          <h1 className="mt-2 text-[36px] font-extrabold tracking-[-0.04em] text-ink md:text-[44px]">
            Опубликовать приложение
          </h1>
          <p className="mt-3 text-[16px] leading-relaxed text-ink-2">
            Загрузите сайт или программу — включая .exe. Мы прогоним VirusTotal,
            ClamAV, ClamWin и VibeGuard и покажем, готов ли продукт к массовому
            релизу.
          </p>
        </div>

        <div className="fade-up-d1 mt-8 surface-card p-6 md:p-8">
          <PublishForm />
        </div>
      </div>
    </main>
  );
}
