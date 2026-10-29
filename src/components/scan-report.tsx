import type { ScanReport, ScannerVerdict } from "@/lib/types";
import { ScoreRing } from "./safety-badge";

const verdictCopy: Record<ScannerVerdict, { label: string; className: string }> =
  {
    clean: { label: "Чисто", className: "text-green-ink" },
    suspicious: { label: "Подозрительно", className: "text-amber-ink" },
    malicious: { label: "Угроза", className: "text-red-ink" },
    error: { label: "Ошибка", className: "text-red-ink" },
    skipped: { label: "Пропуск", className: "text-ink-3" },
  };

export function ScanReportView({ report }: { report: ScanReport }) {
  const findings = report.engines.flatMap((e) =>
    e.findings.map((f) => ({ ...f, engine: e.displayName })),
  );

  return (
    <div className="space-y-8">
      <div className="flex flex-col gap-6 sm:flex-row sm:items-center">
        <ScoreRing score={report.securityScore} />
        <div className="min-w-0 flex-1">
          <p className="text-[12px] font-semibold uppercase tracking-[0.14em] text-ink-3">
            Отчёт безопасности
          </p>
          <h2 className="mt-1 text-[24px] font-bold tracking-[-0.03em] text-ink md:text-[28px]">
            {report.readinessLabel}
          </h2>
          <p className="mt-2 text-[14px] leading-relaxed text-ink-2">
            {report.readinessHint}
          </p>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-2.5">
        <Metric label="Угрозы" value={report.threatCount} />
        <Metric label="Critical" value={report.criticalCount} tone="danger" />
        <Metric label="High" value={report.highCount} tone="warn" />
      </div>

      <p className="rounded-2xl bg-bg px-4 py-3.5 text-[13px] leading-relaxed text-ink-2">
        {report.consensus}
      </p>

      <div>
        <h3 className="text-[15px] font-semibold tracking-[-0.02em]">
          Движки
        </h3>
        <div className="mt-3 overflow-hidden rounded-2xl border border-black/[0.06]">
          {report.engines.map((e, i) => {
            const v = verdictCopy[e.verdict];
            return (
              <div
                key={e.scanner}
                className={`flex items-start justify-between gap-4 px-4 py-3.5 ${
                  i < report.engines.length - 1
                    ? "border-b border-black/[0.06]"
                    : ""
                }`}
              >
                <div className="min-w-0">
                  <div className="text-[14px] font-semibold tracking-[-0.01em]">
                    {e.displayName}
                  </div>
                  <div className="mt-0.5 text-[12px] text-ink-2">{e.summary}</div>
                </div>
                <div className="shrink-0 text-right">
                  <div className={`text-[12px] font-semibold ${v.className}`}>
                    {v.label}
                  </div>
                  <div className="mt-0.5 text-[12px] tabular-nums text-ink-3">
                    {e.score}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {findings.length > 0 && (
        <div>
          <h3 className="text-[15px] font-semibold tracking-[-0.02em]">
            Находки
          </h3>
          <ul className="mt-3 space-y-2">
            {findings.map((f) => (
              <li
                key={f.id}
                className="rounded-2xl border border-black/[0.06] px-4 py-3.5"
              >
                <div className="flex flex-wrap items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.06em]">
                  <SeverityDot severity={f.severity} />
                  <span className="text-ink-3">{f.engine}</span>
                  <span className="text-ink-3">· {f.category}</span>
                </div>
                <p className="mt-1.5 text-[14px] font-semibold tracking-[-0.01em]">
                  {f.title}
                </p>
                <p className="mt-0.5 text-[13px] text-ink-2">{f.detail}</p>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function Metric({
  label,
  value,
  tone,
}: {
  label: string;
  value: number;
  tone?: "danger" | "warn";
}) {
  return (
    <div className="rounded-2xl bg-bg px-3 py-3 text-center">
      <div
        className={`text-[22px] font-bold tabular-nums tracking-[-0.03em] ${
          tone === "danger"
            ? "text-red-ink"
            : tone === "warn"
              ? "text-amber-ink"
              : "text-ink"
        }`}
      >
        {value}
      </div>
      <div className="mt-0.5 text-[11px] font-medium text-ink-3">{label}</div>
    </div>
  );
}

function SeverityDot({ severity }: { severity: string }) {
  const color =
    severity === "critical" || severity === "high"
      ? "text-red-ink"
      : severity === "medium"
        ? "text-amber-ink"
        : "text-ink-3";
  return <span className={color}>{severity}</span>;
}
