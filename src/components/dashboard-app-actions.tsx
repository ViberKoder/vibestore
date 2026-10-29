"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";

export function DashboardAppActions({
  appId,
  slug,
  name,
}: {
  appId: string;
  slug: string;
  name: string;
}) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);

  async function onDelete() {
    if (
      !window.confirm(
        `Удалить «${name}»? Сборка и медиа будут удалены безвозвратно.`,
      )
    ) {
      return;
    }
    setBusy(true);
    try {
      const res = await fetch(`/api/apps/${appId}`, { method: "DELETE" });
      if (!res.ok) {
        setBusy(false);
        return;
      }
      router.refresh();
    } catch {
      setBusy(false);
    }
  }

  return (
    <div className="flex items-center gap-2">
      <Link
        href={`/apps/${slug}/edit`}
        className="btn-get !h-8 !min-w-0 !px-3 !text-[12px]"
      >
        Изменить
      </Link>
      <button
        type="button"
        onClick={onDelete}
        disabled={busy}
        className="inline-flex h-8 items-center rounded-full bg-red-soft px-3 text-[12px] font-semibold text-red-ink disabled:opacity-50"
      >
        {busy ? "…" : "Удалить"}
      </button>
    </div>
  );
}
