import Link from "next/link";
import type { PublicStoreApp } from "@/lib/owner-auth";
import type { StoreApp } from "@/lib/types";
import { AppIcon } from "./app-icon";
import { SafetyBadge } from "./safety-badge";

export function AppRow({
  app,
  rank,
  divider = true,
}: {
  app: StoreApp | PublicStoreApp;
  rank?: number;
  divider?: boolean;
}) {
  const canGet = app.status === "published";

  return (
    <div
      className={`flex items-center gap-3.5 py-3.5 ${
        divider ? "border-b border-black/[0.06] last:border-0" : ""
      }`}
    >
      {typeof rank === "number" && (
        <span className="w-5 shrink-0 text-center text-[15px] font-semibold tabular-nums text-ink-3">
          {rank}
        </span>
      )}
      <Link href={`/apps/${app.slug}`} className="shrink-0">
        <AppIcon app={app} size="md" />
      </Link>
      <Link href={`/apps/${app.slug}`} className="min-w-0 flex-1">
        <div className="truncate text-[15px] font-semibold tracking-[-0.02em] text-ink">
          {app.name}
        </div>
        <div className="mt-0.5 truncate text-[12px] text-ink-2">
          {app.category}
          {app.scan ? ` · Score ${app.scan.securityScore}` : ""}
        </div>
        <div className="mt-1.5 md:hidden">
          <SafetyBadge app={app} />
        </div>
      </Link>
      <div className="hidden md:block">
        <SafetyBadge app={app} />
      </div>
      {canGet ? (
        <Link href={`/apps/${app.slug}`} className="btn-get shrink-0">
          Открыть
        </Link>
      ) : (
        <Link
          href={`/apps/${app.slug}`}
          className="inline-flex h-[30px] shrink-0 items-center rounded-full bg-black/[0.04] px-3.5 text-[12px] font-semibold text-ink-2"
        >
          Отчёт
        </Link>
      )}
    </div>
  );
}
