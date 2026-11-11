"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { LanguageSwitcher, useT } from "@/lib/i18n/client";
import { ThemeToggle } from "./theme-toggle";
import { GithubAuthButton } from "./github-auth-button";

const links = [
  { href: "/", label: "Overview" },
  { href: "/#catalog", label: "Catalog" },
  { href: "/security", label: "Security" },
  { href: "/dashboard", label: "Dashboard" },
];

export function SiteHeader() {
  const pathname = usePathname();
  const t = useT();

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
                  {t(l.label)}
                </Link>
              );
            })}
          </nav>
        </div>
        <div className="flex items-center gap-2">
          <GithubAuthButton />
          <LanguageSwitcher />
          <ThemeToggle />
          <Link
            href="/publish"
            className="btn-get !h-9 !min-w-0 !px-4 !text-[13px]"
          >
            {t("Publish")}
          </Link>
        </div>
      </div>
    </header>
  );
}
