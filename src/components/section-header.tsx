"use client";

import Link from "next/link";
import { useT } from "@/lib/i18n/client";

export function SectionHeader({
  title,
  subtitle,
  href,
  action,
}: {
  title: string;
  subtitle?: string;
  href?: string;
  action?: string;
}) {
  const t = useT();
  return (
    <div className="mb-3 flex items-end justify-between gap-4">
      <div>
        <h2 className="text-[22px] font-bold tracking-[-0.03em] text-ink md:text-[24px]">
          {title}
        </h2>
        {subtitle && (
          <p className="mt-0.5 text-[13px] text-ink-2">{subtitle}</p>
        )}
      </div>
      {href && (
        <Link
          href={href}
          className="shrink-0 text-[14px] font-medium text-blue hover:underline"
        >
          {action ?? t("See all")}
        </Link>
      )}
    </div>
  );
}
