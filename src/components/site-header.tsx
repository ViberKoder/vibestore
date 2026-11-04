"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { ThemeToggle } from "./theme-toggle";

const links = [
  { href: "/", label: "Обзор" },
  { href: "/#catalog", label: "Каталог" },
  { href: "/security", label: "Безопасность" },
  { href: "/dashboard", label: "Кабинет" },
];

export function SiteHeader() {
  const pathname = usePathname();

  return (
    <header className="sticky top-0 z-40 border-b border-[var(--line)] bg-[color-mix(in_srgb,var(--bg)_78%,transparent)] backdrop-blur-xl">
      <div className="container-store flex h-[52px] items-center justify-between gap-4 md:h-[58px]">
        <div className="flex items-center gap-8">
          <Link href="/" className="flex items-center gap-2.5">
            <span className="grid h-7 w-7 place-items-center rounded-[8px] bg-ink text-[13px] font-bold text-bg">
              V
            </span>
            <span className="text-[17px] font-bold tracking-[-0.03em] text-ink">
              Vibe Store
            </span>
          </Link>
          <nav className="hidden items-center gap-1 md:flex">
            {links.map((l) => {
              const active =
                l.href === "/"
                  ? pathname === "/"
                  : pathname === l.href || pathname.startsWith(l.href + "/");
              return (
                <Link
                  key={l.href}
                  href={l.href}
                  className={`rounded-full px-3 py-1.5 text-[13px] font-medium transition ${
                    active
                      ? "bg-[color-mix(in_srgb,var(--ink)_8%,transparent)] text-ink"
                      : "text-ink-2 hover:text-ink"
                  }`}
                >
                  {l.label}
                </Link>
              );
            })}
          </nav>
        </div>
        <div className="flex items-center gap-2">
          <ThemeToggle />
          <Link
            href="/publish"
            className="btn-get !h-9 !min-w-0 !px-4 !text-[13px]"
          >
            Опубликовать
          </Link>
        </div>
      </div>
    </header>
  );
}
