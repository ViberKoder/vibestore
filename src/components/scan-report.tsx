import type { ScanReport, ScannerVerdict } from "@/lib/types";
import { ScoreOrb } from "./safety-badge";

const verdictStyle: Record<ScannerVerdict, string> = {
  clean: "text-teal-deep",
  suspicious: "text-amber",
  malicious: "text-coral",
  error: "text-coral",
  skipped: "text-ink-soft",
};

export function ScanReportView({ report }: { report: ScanReport }) {
  return (
    <section className="space-y-8">
      <div className="flex flex-col gap-6 md:flex-row md:items-center md:justify-between">
        <div className="flex items-center gap-5">
          <ScoreOrb score={report.securityScore} />
          <div>
            <p className="text-sm uppercase tracking-[0.16em] text-ink-soft">
              Отчёт безопасности
            </p>
            <h2 className="font-display text-2xl font-bold text-ink md:text-3xl">
              {report.readinessLabel}
            </h2>
            <p className="mt-1 max-w-xl text-sm text-ink-soft">
              {report.readinessHint}
            </p>
          </div>
        </div>
        <div className="grid grid-cols-3 gap-3 text-center font-mono text-xs">
          <Stat label="threats" value={report.threatCount} />
          <Stat label="critical" value={report.criticalCount} danger />
          <Stat label="high" value={report.highCount} warn />
        </div>
      </div>

      <p className="rounded-xl bg-white/55 px-4 py-3 text-sm text-ink-soft ring-1 ring-ink/8">
        {report.consensus}
      </p>

      <div className="overflow-hidden rounded-2xl bg-white/60 ring-1 ring-ink/8">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-ink/10 text-xs uppercase tracking-wider text-ink-soft">
            <tr>
              <th className="px-4 py-3 font-medium">Движок</th>
              <th className="px-4 py-3 font-medium">Вердикт</th>
              <th className="px-4 py-3 font-medium">Score</th>
              <th className="hidden px-4 py-3 font-medium md:table-cell">
                Итог
              </th>
            </tr>
          </thead>
          <tbody>
            {report.engines.map((e) => (
              <tr key={e.scanner} className="border-b border-ink/5 last:border-0">
                <td className="px-4 py-3 font-medium text-ink">
                  {e.displayName}
                </td>
                <td
                  className={`px-4 py-3 font-mono text-xs uppercase ${verdictStyle[e.verdict]}`}
                >
                  {e.verdict}
                </td>
                <td className="px-4 py-3 font-mono">{e.score}</td>
                <td className="hidden px-4 py-3 text-ink-soft md:table-cell">
                  {e.summary}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {report.engines.some((e) => e.findings.length > 0) && (
        <div className="space-y-3">
          <h3 className="font-display text-lg font-semibold">Находки</h3>
          <ul className="space-y-2">
            {report.engines.flatMap((e) =>
              e.findings.map((f) => (
                <li
                  key={f.id}
                  className="rounded-xl bg-white/55 px-4 py-3 ring-1 ring-ink/8"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={`font-mono text-[11px] uppercase ${
                        f.severity === "critical" || f.severity === "high"
                          ? "text-coral"
                          : f.severity === "medium"
                            ? "text-amber"
                            : "text-ink-soft"
                      }`}
                    >
                      {f.severity}
                    </span>
                    <span className="text-xs text-ink-soft">{e.displayName}</span>
                    <span className="text-xs text-ink-soft">· {f.category}</span>
                  </div>
                  <p className="mt-1 font-medium text-ink">{f.title}</p>
                  <p className="mt-0.5 text-sm text-ink-soft">{f.detail}</p>
                </li>
              )),
            )}
          </ul>
        </div>
      )}
    </section>
  );
}

function Stat({
  label,
  value,
  danger,
  warn,
}: {
  label: string;
  value: number;
  danger?: boolean;
  warn?: boolean;
}) {
  return (
    <div className="rounded-xl bg-white/55 px-3 py-3 ring-1 ring-ink/8">
      <div
        className={`text-xl font-semibold ${
          danger ? "text-coral" : warn ? "text-amber" : "text-ink"
        }`}
      >
        {value}
      </div>
      <div className="text-[10px] uppercase tracking-wider text-ink-soft">
        {label}
      </div>
    </div>
  );
}
