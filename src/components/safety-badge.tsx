import type { CSSProperties } from "react";
import type { ReleaseReadiness, StoreApp } from "@/lib/types";

const labels: Record<
  ReleaseReadiness | "scanning" | "unknown",
  { text: string; className: string }
> = {
  ready: {
    text: "Проверено",
    className: "bg-green-soft text-green-ink",
  },
  needs_fixes: {
    text: "На проверке",
    className: "bg-amber-soft text-amber-ink",
  },
  blocked: {
    text: "Заблокировано",
    className: "bg-red-soft text-red-ink",
  },
  scanning: {
    text: "Сканирование",
    className: "bg-black/[0.04] text-ink-2",
  },
  unknown: {
    text: "Без отчёта",
    className: "bg-black/[0.04] text-ink-2",
  },
};

export function readinessKey(app: StoreApp) {
  if (app.status === "scanning" || app.status === "queued") return "scanning";
  return app.scan?.readiness ?? "unknown";
}

export function SafetyBadge({
  app,
  showScore = true,
}: {
  app: StoreApp;
  showScore?: boolean;
}) {
  const key = readinessKey(app);
  const cfg = labels[key];
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full px-2.5 py-1 text-[11px] font-semibold tracking-[-0.01em] ${cfg.className}`}
    >
      {cfg.text}
      {showScore && typeof app.scan?.securityScore === "number" && (
        <span className="opacity-70">{app.scan.securityScore}</span>
      )}
    </span>
  );
}

export function ScoreRing({
  score,
  size = 96,
}: {
  score: number;
  size?: number;
}) {
  const color =
    score >= 75 ? "var(--green)" : score >= 45 ? "var(--amber)" : "var(--red)";
  const r = 42;
  const c = 2 * Math.PI * r;
  const offset = c - (score / 100) * c;

  return (
    <div
      className="relative grid place-items-center"
      style={{ width: size, height: size }}
    >
      <svg
        viewBox="0 0 100 100"
        className="absolute inset-0 -rotate-90"
        aria-hidden
      >
        <circle
          cx="50"
          cy="50"
          r={r}
          fill="none"
          stroke="rgba(0,0,0,0.06)"
          strokeWidth="7"
        />
        <circle
          cx="50"
          cy="50"
          r={r}
          fill="none"
          stroke={color}
          strokeWidth="7"
          strokeLinecap="round"
          strokeDasharray={c}
          strokeDashoffset={offset}
          className="score-animate"
          style={{ "--tw": offset } as CSSProperties}
        />
      </svg>
      <div className="text-center">
        <div className="text-[28px] font-bold leading-none tracking-[-0.04em] text-ink">
          {score}
        </div>
        <div className="mt-1 text-[10px] font-semibold uppercase tracking-[0.14em] text-ink-3">
          score
        </div>
      </div>
    </div>
  );
}
