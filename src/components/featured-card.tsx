import Link from "next/link";
import type { StoreApp } from "@/lib/types";
import { AppIcon } from "./app-icon";

export function FeaturedCard({ app }: { app: StoreApp }) {
  return (
    <Link
      href={`/apps/${app.slug}`}
      className="group relative block overflow-hidden rounded-[28px] shadow-[var(--shadow-lg)]"
    >
      <div
        className="relative min-h-[320px] w-full md:min-h-[380px]"
        style={{
          background: `
            radial-gradient(ellipse at 18% 15%, hsl(${app.iconHue} 75% 62% / 0.55), transparent 48%),
            radial-gradient(ellipse at 88% 20%, hsl(${(app.iconHue + 52) % 360} 65% 58% / 0.28), transparent 42%),
            linear-gradient(165deg, hsl(${app.iconHue} 30% 16%) 0%, hsl(${(app.iconHue + 16) % 360} 34% 8%) 100%)
          `,
        }}
      >
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_72%_38%,rgba(255,255,255,0.14),transparent_42%)]" />

        <div className="relative flex min-h-[320px] flex-col justify-between p-6 pb-0 md:min-h-[380px] md:p-10 md:pb-0">
          <div className="max-w-xl">
            <p className="text-[12px] font-semibold uppercase tracking-[0.16em] text-white/65">
              Приложение дня
            </p>
            <h2 className="mt-3 text-[34px] font-extrabold leading-[1.05] tracking-[-0.045em] text-white md:text-[48px]">
              {app.name}
            </h2>
            <p className="mt-3 max-w-md text-[15px] leading-snug text-white/72 md:text-[17px]">
              {app.tagline}
            </p>
          </div>

          <div className="mt-10 -mx-6 flex items-center gap-3.5 border-t border-white/10 bg-black/25 px-6 py-4 backdrop-blur-xl md:-mx-10 md:px-10 md:py-5">
            <AppIcon app={app} size="md" />
            <div className="min-w-0 flex-1">
              <div className="truncate text-[15px] font-semibold text-white">
                {app.name}
              </div>
              <div className="truncate text-[12px] text-white/60">
                {app.category}
                {app.scan ? ` · Score ${app.scan.securityScore}` : ""}
              </div>
            </div>
            <span className="inline-flex h-[30px] shrink-0 items-center rounded-full bg-white px-4 text-[13px] font-semibold text-blue transition group-hover:bg-white/90">
              Смотреть
            </span>
          </div>
        </div>
      </div>
    </Link>
  );
}
