"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import type {
  EngineResult,
  ScanReport,
  ScannerVerdict,
  ThreatFinding,
} from "@/lib/types";
import { ScoreRing } from "./safety-badge";

const verdictCopy: Record<
  ScannerVerdict,
  { label: string; className: string; blurb: string }
> = {
  clean: {
    label: "Чисто",
    className: "text-green-ink",
    blurb: "Движок не нашёл известных угроз.",
  },
  suspicious: {
    label: "Подозрительно",
    className: "text-amber-ink",
    blurb: "Есть признаки риска, но это ещё не подтверждённый malware.",
  },
  malicious: {
    label: "Угроза",
    className: "text-red-ink",
    blurb: "Движок считает файл вредоносным.",
  },
  error: {
    label: "Не завершено / ошибка",
    className: "text-amber-ink",
    blurb: "Проверка не закончилась или сбой API — это не равно «вирус».",
  },
  skipped: {
    label: "Пропуск",
    className: "text-ink-3",
    blurb: "Движок не применим к этому типу файла.",
  },
};

const severityRu: Record<string, string> = {
  critical: "Критично",
  high: "Высокий",
  medium: "Средний",
  low: "Низкий",
  info: "Инфо",
};

const categoryRu: Record<string, string> = {
  virus: "Вирус",
  trojan: "Троян",
  stealer: "Стиллер",
  adware: "Adware",
  vulnerability: "Уязвимость",
  bug: "Баг",
  packed: "Упаковка",
  network: "Сеть",
  policy: "Политика / процесс",
  other: "Прочее",
};

export function ScanReportView({
  report,
  appId,
}: {
  report: ScanReport;
  appId?: string;
}) {
  const findings = report.engines.flatMap((e) =>
    e.findings.map((f) => ({ ...f, engine: e.displayName, engineResult: e })),
  );
  const vt = report.engines.find((e) => e.scanner === "virustotal");
  const vtPending = vt?.meta?.mode === "pending-analysis";
  const vtPermalink =
    typeof vt?.meta?.permalink === "string" ? vt.meta.permalink : undefined;

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

      {vtPending && (
        <div className="rounded-2xl border border-amber/30 bg-amber-soft px-4 py-4">
          <p className="text-[14px] font-semibold text-amber-ink">
            VirusTotal не «зафейлил» файл как вирус
          </p>
          <p className="mt-1 text-[13px] leading-relaxed text-ink-2">
            Крупный .exe был загружен в VirusTotal, но вендоры не успели вернуть
            вердикты за время ожидания. Это таймаут анализа, а не детект
            malware. Подождите 1–3 минуты и перепроверьте.
          </p>
          <div className="mt-3 flex flex-wrap gap-2">
            {appId && <RescanButton appId={appId} engine="virustotal" />}
            {vtPermalink && (
              <a
                href={vtPermalink}
                target="_blank"
                rel="noreferrer"
                className="btn-secondary !h-9 !px-4 !text-[13px]"
              >
                Открыть на VirusTotal
              </a>
            )}
          </div>
        </div>
      )}

      <div className="grid grid-cols-3 gap-2.5">
        <Metric label="Находки" value={report.threatCount} />
        <Metric label="Critical" value={report.criticalCount} tone="danger" />
        <Metric label="High" value={report.highCount} tone="warn" />
      </div>

      <p className="rounded-2xl bg-bg px-4 py-3.5 text-[13px] leading-relaxed text-ink-2">
        {report.consensus}
      </p>

      <div>
        <div className="mb-3 flex items-center justify-between gap-3">
          <h3 className="text-[15px] font-semibold tracking-[-0.02em]">
            Что сказал каждый движок
          </h3>
          {appId && <RescanButton appId={appId} engine="all" label="Скан заново" />}
        </div>
        <div className="space-y-2">
          {report.engines.map((e) => (
            <EngineCard key={e.scanner} engine={e} />
          ))}
        </div>
      </div>

      <div>
        <h3 className="text-[15px] font-semibold tracking-[-0.02em]">
          Разбор находок — что это и что делать
        </h3>
        {findings.length === 0 ? (
          <p className="mt-3 rounded-2xl bg-green-soft px-4 py-3 text-[13px] text-green-ink">
            Критичных находок нет. Все применимые движки отработали без malware
            alerts.
          </p>
        ) : (
          <ul className="mt-3 space-y-3">
            {findings.map((f) => (
              <FindingCard key={f.id} finding={f} />
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function EngineCard({ engine }: { engine: EngineResult }) {
  const v = verdictCopy[engine.verdict];
  const permalink =
    typeof engine.meta?.permalink === "string"
      ? engine.meta.permalink
      : undefined;
  const mode =
    typeof engine.meta?.mode === "string" ? engine.meta.mode : undefined;

  return (
    <div className="rounded-2xl border border-black/[0.06] px-4 py-3.5">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="text-[14px] font-semibold tracking-[-0.01em]">
            {engine.displayName}
          </div>
          <div className="mt-0.5 text-[12px] text-ink-2">{engine.summary}</div>
          <div className="mt-1 text-[12px] text-ink-3">{v.blurb}</div>
          {mode && (
            <div className="mt-1 font-mono text-[11px] text-ink-3">
              mode: {mode}
              {typeof engine.meta?.sha256 === "string"
                ? ` · sha256 ${String(engine.meta.sha256).slice(0, 12)}…`
                : ""}
            </div>
          )}
          {permalink && (
            <a
              href={permalink}
              target="_blank"
              rel="noreferrer"
              className="mt-1 inline-block text-[12px] font-medium text-blue hover:underline"
            >
              Открыть отчёт движка →
            </a>
          )}
        </div>
        <div className="shrink-0 text-right">
          <div className={`text-[12px] font-semibold ${v.className}`}>
            {v.label}
          </div>
          <div className="mt-0.5 text-[12px] tabular-nums text-ink-3">
            score {engine.score}
          </div>
          <div className="mt-0.5 text-[11px] text-ink-3">
            {(engine.durationMs / 1000).toFixed(1)}s
          </div>
        </div>
      </div>
    </div>
  );
}

function FindingCard({
  finding,
}: {
  finding: ThreatFinding & { engine: string };
}) {
  return (
    <li className="rounded-2xl border border-black/[0.06] px-4 py-4">
      <div className="flex flex-wrap items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.06em]">
        <span
          className={
            finding.severity === "critical" || finding.severity === "high"
              ? "text-red-ink"
              : finding.severity === "medium"
                ? "text-amber-ink"
                : "text-ink-3"
          }
        >
          {severityRu[finding.severity] ?? finding.severity}
        </span>
        <span className="text-ink-3">{finding.engine}</span>
        <span className="text-ink-3">
          · {categoryRu[finding.category] ?? finding.category}
        </span>
      </div>
      <p className="mt-2 text-[15px] font-semibold tracking-[-0.01em]">
        {finding.title}
      </p>
      <p className="mt-1 text-[13px] leading-relaxed text-ink-2">
        {finding.detail}
      </p>
      {finding.meaning && (
        <div className="mt-3 rounded-xl bg-bg px-3 py-2.5">
          <p className="text-[11px] font-semibold uppercase tracking-[0.08em] text-ink-3">
            Что это значит
          </p>
          <p className="mt-1 text-[13px] leading-relaxed text-ink">{finding.meaning}</p>
        </div>
      )}
      {finding.action && (
        <div className="mt-2 rounded-xl bg-blue-soft px-3 py-2.5">
          <p className="text-[11px] font-semibold uppercase tracking-[0.08em] text-blue">
            Что делать
          </p>
          <p className="mt-1 text-[13px] leading-relaxed text-ink">{finding.action}</p>
        </div>
      )}
    </li>
  );
}

function RescanButton({
  appId,
  engine,
  label,
}: {
  appId: string;
  engine: "virustotal" | "all";
  label?: string;
}) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function run() {
    setBusy(true);
    setErr(null);
    try {
      const q = engine === "all" ? "all" : "virustotal";
      const res = await fetch(`/api/apps/${appId}/rescan?engine=${q}`, {
        method: "POST",
      });
      const json = (await res.json()) as { error?: string };
      if (!res.ok) {
        setErr(json.error ?? "Не удалось перепроверить");
        setBusy(false);
        return;
      }
      router.refresh();
    } catch {
      setErr("Сеть недоступна");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="shrink-0">
      <button
        type="button"
        onClick={run}
        disabled={busy}
        className="btn-get !h-9"
      >
        {busy
          ? "Проверяем…"
          : label ??
            (engine === "virustotal"
              ? "Перепроверить VirusTotal"
              : "Скан заново")}
      </button>
      {err && <p className="mt-1 text-[11px] text-red-ink">{err}</p>}
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
