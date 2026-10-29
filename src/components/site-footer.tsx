import Link from "next/link";

export function SiteFooter() {
  return (
    <footer className="mx-auto mt-auto w-full max-w-6xl px-5 py-10 md:px-8">
      <div className="flex flex-col gap-4 border-t border-ink/10 pt-8 text-sm text-ink-soft md:flex-row md:items-center md:justify-between">
        <p>
          Vibe Store — маркетплейс вайбкодерских приложений с обязательным
          мультиантивирусным сканом.
        </p>
        <div className="flex gap-4">
          <Link href="/security" className="hover:text-ink">
            Как мы сканируем
          </Link>
          <Link href="/publish" className="hover:text-ink">
            Для разработчиков
          </Link>
        </div>
      </div>
    </footer>
  );
}
