import type { CSSProperties } from "react";
import type { ReleaseReadiness, StoreApp } from "@/lib/types";

const labels: Record<
  ReleaseReadiness | "scanning" | "unknown",
  { text: string; className: string }
> = {
  ready: {
    text: "Проверено",
    className: "bg-teal/15 text-teal-deep ring-teal/25",
  },
  needs_fixes: {
    text: "На доработке",
    className: "bg-amber/15 text-amber ring-amber/30",
  },
  blocked: {
    text: "Заблокировано",
    className: "bg-coral/15 text-coral ring-coral/30",
  },
  scanning: {
    text: "Сканируется",
    className: "bg-ink/5 text-ink-soft ring-ink/10",
  },
  unknown: {
    text: "Без отчёта",
    className: "bg-ink/5 text-ink-soft ring-ink/10",
  },
};

export function SafetyBadge({ app }: { app: StoreApp }) {
  const key =
    app.status === "scanning" || app.status === "queued"
      ? "scanning"
      : (app.scan?.readiness ?? "unknown");
  const cfg = labels[key];
  return (
    <span
      className={`inline-flex items-center rounded-md px-2 py-0.5 text-xs font-semibold ring-1 ring-inset ${cfg.className}`}
    >
      {cfg.text}
      {typeof app.scan?.securityScore === "number" && (
        <span className="ml-1.5 font-mono opacity-80">
          {app.scan.securityScore}
        </span>
      )}
    </span>
  );
}

export function ScoreOrb({
  score,
  size = 88,
}: {
  score: number;
  size?: number;
}) {
  const color =
    score >= 75 ? "var(--teal)" : score >= 45 ? "var(--amber)" : "var(--coral)";
  return (
    <div
      className="score-ring relative grid place-items-center rounded-full p-[5px]"
      style={
        {
          width: size,
          height: size,
          "--score": score,
          "--ring-color": color,
        } as CSSProperties
      }
    >
      <div className="grid h-full w-full place-items-center rounded-full bg-paper-2">
        <div className="text-center">
          <div className="font-display text-2xl font-bold leading-none text-ink">
            {score}
          </div>
          <div className="mt-0.5 text-[10px] uppercase tracking-wider text-ink-soft">
            score
          </div>
        </div>
      </div>
    </div>
  );
}
