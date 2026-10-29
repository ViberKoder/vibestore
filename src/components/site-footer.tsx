import Link from "next/link";

export function SiteFooter() {
  return (
    <footer className="mt-auto border-t border-black/[0.06] bg-bg">
      <div className="container-store flex flex-col gap-6 py-12 md:flex-row md:items-start md:justify-between">
        <div className="max-w-sm">
          <div className="flex items-center gap-2">
            <span className="grid h-6 w-6 place-items-center rounded-[7px] bg-ink text-[11px] font-bold text-white">
              V
            </span>
            <span className="text-[15px] font-bold tracking-[-0.02em]">
              Vibe Store
            </span>
          </div>
          <p className="mt-3 text-[13px] leading-relaxed text-ink-2">
            Каталог вайбкодерских приложений с обязательной проверкой на
            вирусы, трояны и стиллеры — до того, как файл попадёт к
            пользователю.
          </p>
        </div>
        <div className="grid grid-cols-2 gap-8 text-[13px] sm:grid-cols-3">
          <div className="space-y-2">
            <p className="font-semibold text-ink">Магазин</p>
            <Link href="/#catalog" className="block text-ink-2 hover:text-blue">
              Каталог
            </Link>
            <Link href="/publish" className="block text-ink-2 hover:text-blue">
              Опубликовать
            </Link>
            <Link href="/dashboard" className="block text-ink-2 hover:text-blue">
              Кабинет
            </Link>
          </div>
          <div className="space-y-2">
            <p className="font-semibold text-ink">Доверие</p>
            <Link href="/security" className="block text-ink-2 hover:text-blue">
              Как мы сканируем
            </Link>
            <p className="text-ink-3">VirusTotal · ClamAV · VibeGuard</p>
          </div>
        </div>
      </div>
      <div className="container-store border-t border-black/[0.06] py-5 text-[12px] text-ink-3">
        © {new Date().getFullYear()} Vibe Store
      </div>
    </footer>
  );
}
