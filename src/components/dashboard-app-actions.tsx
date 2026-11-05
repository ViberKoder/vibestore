"use client";

import Link from "next/link";
import { useT } from "@/lib/i18n/client";

export function DashboardAppActions({
  slug,
  label,
}: {
  slug: string;
  label?: string;
}) {
  const t = useT();
  return (
    <div className="flex items-center gap-2">
      <Link
        href={`/apps/${slug}/edit`}
        className="btn-get !h-8 !min-w-0 !px-3 !text-[12px]"
      >
        {label ?? t("Manage")}
      </Link>
    </div>
  );
}
