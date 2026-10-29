"use client";

import Link from "next/link";

export function DashboardAppActions({
  slug,
}: {
  appId: string;
  slug: string;
  name: string;
}) {
  return (
    <div className="flex items-center gap-2">
      <Link
        href={`/apps/${slug}/edit`}
        className="btn-get !h-8 !min-w-0 !px-3 !text-[12px]"
      >
        Управление
      </Link>
    </div>
  );
}
