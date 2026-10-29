import Link from "next/link";
import type { StoreApp } from "@/lib/types";
import { AppIcon } from "./app-icon";

export function CollectionCard({
  title,
  subtitle,
  apps,
  href,
}: {
  title: string;
  subtitle: string;
  apps: StoreApp[];
  href: string;
}) {
  return (
    <Link
      href={href}
      className="block w-[280px] rounded-[24px] bg-surface p-5 shadow-[var(--shadow-sm)] transition hover:shadow-[var(--shadow-md)] md:w-[300px]"
    >
      <p className="text-[11px] font-semibold uppercase tracking-[0.12em] text-ink-3">
        Подборка
      </p>
      <h3 className="mt-1.5 text-[18px] font-bold tracking-[-0.03em] text-ink">
        {title}
      </h3>
      <p className="mt-1 text-[13px] leading-snug text-ink-2">{subtitle}</p>
      <div className="mt-5 flex -space-x-2">
        {apps.slice(0, 4).map((app) => (
          <AppIcon
            key={app.id}
            app={app}
            size="sm"
            className="ring-2 ring-white"
          />
        ))}
      </div>
    </Link>
  );
}
