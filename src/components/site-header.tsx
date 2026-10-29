import Link from "next/link";

const links = [
  { href: "/#catalog", label: "Каталог" },
  { href: "/security", label: "Безопасность" },
  { href: "/dashboard", label: "Кабинет" },
  { href: "/publish", label: "Опубликовать" },
];

export function SiteHeader() {
  return (
    <header className="mx-auto flex w-full max-w-6xl items-center justify-between gap-4 px-5 py-5 md:px-8">
      <Link href="/" className="group flex items-baseline gap-2">
        <span className="font-display text-2xl font-extrabold tracking-tight text-ink md:text-[1.75rem]">
          Vibe&nbsp;Store
        </span>
        <span className="hidden text-xs font-medium uppercase tracking-[0.18em] text-ink-soft sm:inline">
          verified builds
        </span>
      </Link>
      <nav className="flex items-center gap-1 text-sm md:gap-2">
        {links.map((l) => (
          <Link
            key={l.href}
            href={l.href}
            className="rounded-md px-2.5 py-1.5 text-ink-soft transition hover:bg-white/50 hover:text-ink"
          >
            {l.label}
          </Link>
        ))}
      </nav>
    </header>
  );
}
