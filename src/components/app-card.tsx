import Link from "next/link";
import { formatNumber } from "@/lib/format";
import type { StoreApp } from "@/lib/types";
import { SafetyBadge } from "./safety-badge";

export function AppCard({ app, index = 0 }: { app: StoreApp; index?: number }) {
  return (
    <Link
      href={`/apps/${app.slug}`}
      className="anim-rise group block border-b border-ink/10 py-6 transition hover:bg-white/35"
      style={{ animationDelay: `${Math.min(index, 8) * 0.05}s` }}
    >
      <div className="flex items-start gap-4 md:gap-6">
        <div
          className="grid h-14 w-14 shrink-0 place-items-center rounded-2xl text-lg font-bold text-white shadow-sm md:h-16 md:w-16"
          style={{
            background: `linear-gradient(145deg, hsl(${app.iconHue} 42% 38%), hsl(${(app.iconHue + 40) % 360} 48% 28%))`,
          }}
          aria-hidden
        >
          {app.name.slice(0, 1)}
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="font-display text-xl font-semibold tracking-tight text-ink group-hover:text-teal-deep md:text-2xl">
              {app.name}
            </h3>
            <SafetyBadge app={app} />
          </div>
          <p className="mt-1 max-w-2xl text-sm text-ink-soft md:text-base">
            {app.tagline}
          </p>
          <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1 font-mono text-xs text-ink-soft">
            <span>{app.category}</span>
            <span>v{app.version}</span>
            <span>{formatNumber(app.downloads)} загрузок</span>
            <span>{app.developerName}</span>
          </div>
        </div>
      </div>
    </Link>
  );
}
