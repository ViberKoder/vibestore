import { PublishForm } from "@/components/publish-form";

export default function PublishPage() {
  return (
    <main className="mx-auto w-full max-w-3xl flex-1 px-5 pb-20 pt-6 md:px-8">
      <div className="anim-rise">
        <p className="text-sm uppercase tracking-[0.16em] text-ink-soft">
          Для разработчиков
        </p>
        <h1 className="mt-2 font-display text-4xl font-extrabold tracking-tight md:text-5xl">
          Опубликовать в Vibe&nbsp;Store
        </h1>
        <p className="mt-3 max-w-xl text-ink-soft">
          Загрузите сайт или программу — включая .exe. Мы прогоним VirusTotal,
          ClamAV, ClamWin, VibeGuard и покажем, готов ли продукт к массовому
          релизу.
        </p>
      </div>

      <div className="anim-rise-delay-1 mt-10 rounded-[1.5rem] bg-white/60 p-6 ring-1 ring-ink/8 md:p-8">
        <PublishForm />
      </div>
    </main>
  );
}
