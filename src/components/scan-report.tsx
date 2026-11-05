"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import type {
  AuditPillars,
  EngineResult,
  ScanReport,
  ScannerVerdict,
  ThreatFinding,
} from "@/lib/types";
import { PILLAR_META } from "@/lib/types";
import { buildAgentPrompt } from "@/lib/scanners/agent-prompt";
import { useT } from "@/lib/i18n/client";
import { ScoreRing } from "./safety-badge";

const verdictCopy: Record<
  ScannerVerdict,
  { label: string; className: string; blurb: string }
> = {
  clean: {
    label: "Clean",
    className: "text-green-ink",
    blurb: "No threats found.",
  },
  suspicious: {
    label: "Suspicious",
    className: "text-amber-ink",
    blurb: "Signs of risk.",
  },
  malicious: {
    label: "Threat",
    className: "text-red-ink",
    blurb: "The engine considers the file malicious.",
  },
  error: {
    label: "Incomplete",
    className: "text-amber-ink",
    blurb: "Failure / timeout — this is not malware.",
  },
  skipped: {
    label: "Skipped",
    className: "text-ink-3",
    blurb: "Not applicable to this file type.",
  },
};

const severityLabel: Record<string, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

function pillarTone(score: number): string {
  if (score >= 75) return "text-green-ink";
  if (score >= 45) return "text-amber-ink";
  return "text-red-ink";
}

function pillarBar(score: number): string {
  if (score >= 75) return "bg-[var(--green)]";
  if (score >= 45) return "bg-[var(--amber)]";
  return "bg-[var(--red)]";
}

export function ScanReportView({
  report,
  appId,
  appName,
  appKind,
  appVersion,
  appTagline,
  fileName,
  compact = false,
}: {
  report: ScanReport;
  appId?: string;
  appName?: string;
  appKind?: string;
  appVersion?: string;
  appTagline?: string;
  fileName?: string;
  compact?: boolean;
}) {
  const t = useT();
  const findings = report.engines.flatMap((e) =>
    e.findings.map((f) => ({ ...f, engine: e.displayName })),
  );
  const vt = report.engines.find((e) => e.scanner === "virustotal");
  const vtPending = vt?.meta?.mode === "pending-analysis";
  const vtPermalink =
    typeof vt?.meta?.permalink === "string" ? vt.meta.permalink : undefined;
  const trust = report.trustScore ?? report.securityScore;
  const pillars = report.pillars;
  const appCtx = {
    name: appName ?? "app",
    kind: (appKind as "desktop") ?? "other",
    fileName: fileName ?? "artifact",
    version: appVersion ?? "0.0.0",
    tagline: appTagline ?? "",
  };

  return (
    <div className={compact ? "space-y-5" : "space-y-6"}>
      <div className="flex items-center gap-4">
        <ScoreRing score={trust} size={compact ? 72 : 88} />
        <div className="min-w-0 flex-1">
          <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-ink-3">
            Vibe Audit
          </p>
          <h2 className="mt-0.5 text-[18px] font-bold tracking-[-0.03em] text-ink md:text-[20px]">
            {t(report.readinessLabel)}
          </h2>
          <p className="mt-1 text-[13px] leading-snug text-ink-2">
            {t(report.readinessHint)}
          </p>
        </div>
      </div>

      {pillars && <PillarStrip pillars={pillars} />}

      {vtPending && (
        <div className="rounded-xl border border-amber/30 bg-amber-soft px-3.5 py-3">
          <p className="text-[13px] font-semibold text-amber-ink">
            {t("VirusTotal is still analyzing the file")}
          </p>
          <p className="mt-1 text-[12px] leading-relaxed text-ink-2">
            {t("This is a timeout, not a malware detection. Wait and check again.")}
          </p>
          <div className="mt-2.5 flex flex-wrap gap-2">
            {appId && <RescanButton appId={appId} engine="virustotal" />}
            {vtPermalink && (
              <a
                href={vtPermalink}
                target="_blank"
                rel="noreferrer"
                className="btn-secondary !h-8 !px-3 !text-[12px]"
              >
                VirusTotal →
              </a>
            )}
          </div>
        </div>
      )}

      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[12px] text-ink-3">
        <span>
          {t("Findings")}{" "}
          <strong className="tabular-nums text-ink">{report.threatCount}</strong>
        </span>
        <span>
          Critical{" "}
          <strong className="tabular-nums text-red-ink">
            {report.criticalCount}
          </strong>
        </span>
        <span>
          High{" "}
          <strong className="tabular-nums text-amber-ink">
            {report.highCount}
          </strong>
        </span>
        {appId && (
          <RescanButton appId={appId} engine="all" label={t("Rescan")} />
        )}
      </div>

      <section>
        <h3 className="text-[14px] font-semibold tracking-[-0.02em]">
          {t("Findings and an AI prompt")}
        </h3>
        {findings.length === 0 ? (
          <p className="mt-2 rounded-xl bg-green-soft px-3.5 py-2.5 text-[13px] text-green-ink">
            {t("No critical findings.")}
          </p>
        ) : (
          <ul className="mt-2 space-y-2">
            {findings.map((f) => (
              <FindingCard key={f.id} finding={f} appCtx={appCtx} />
            ))}
          </ul>
        )}
      </section>

      <details className="group rounded-xl border border-[var(--line)]">
        <summary className="cursor-pointer list-none px-3.5 py-3 text-[13px] font-semibold tracking-[-0.01em] marker:content-none [&::-webkit-details-marker]:hidden">
          <span className="flex items-center justify-between gap-2">
            {t("Engines")} ({report.engines.length})
            <span className="text-[12px] font-medium text-ink-3 group-open:hidden">
              {t("expand")}
            </span>
            <span className="hidden text-[12px] font-medium text-ink-3 group-open:inline">
              {t("collapse")}
            </span>
          </span>
        </summary>
        <div className="space-y-1.5 border-t border-[var(--line)] px-2 py-2">
          {report.engines.map((e) => (
            <EngineRow key={e.scanner} engine={e} />
          ))}
        </div>
      </details>
    </div>
  );
}

function PillarStrip({ pillars }: { pillars: AuditPillars }) {
  const t = useT();
  return (
    <div className="grid grid-cols-5 gap-1.5">
      {PILLAR_META.map((meta) => {
        const score = pillars[meta.key];
        return (
          <div
            key={meta.key}
            className="rounded-xl bg-bg px-1.5 py-2 text-center"
            title={t(meta.subtitle)}
          >
            <p className="text-[10px] font-semibold uppercase tracking-[0.04em] text-ink-3">
              {t(meta.title)}
            </p>
            <p
              className={`mt-0.5 text-[15px] font-bold tabular-nums tracking-[-0.03em] ${pillarTone(score)}`}
            >
              {score}
            </p>
            <div className="mx-auto mt-1.5 h-1 w-full max-w-[48px] overflow-hidden rounded-full bg-black/[0.06]">
              <div
                className={`h-full rounded-full ${pillarBar(score)}`}
                style={{ width: `${Math.max(4, Math.min(100, score))}%` }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}

function EngineRow({ engine }: { engine: EngineResult }) {
  const t = useT();
  const v = verdictCopy[engine.verdict];
  return (
    <div className="flex items-start justify-between gap-3 rounded-lg px-2 py-2 hover:bg-bg">
      <div className="min-w-0">
        <div className="text-[13px] font-medium">{t(engine.displayName)}</div>
        <div className="truncate text-[11px] text-ink-3">{t(engine.summary)}</div>
      </div>
      <div className={`shrink-0 text-[11px] font-semibold ${v.className}`}>
        {t(v.label)} · {engine.score}
      </div>
    </div>
  );
}

function FindingCard({
  finding,
  appCtx,
}: {
  finding: ThreatFinding & { engine: string };
  appCtx: {
    name: string;
    kind: string;
    fileName: string;
    version: string;
    tagline: string;
  };
}) {
  const [open, setOpen] = useState(
    finding.severity === "critical" || finding.severity === "high",
  );
  const [copied, setCopied] = useState(false);
  const t = useT();
  const prompt =
    finding.agentPrompt ??
    buildAgentPrompt(finding, appCtx);

  async function copyPrompt() {
    try {
      await navigator.clipboard.writeText(prompt);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      setCopied(false);
    }
  }

  return (
    <li className="rounded-xl border border-[var(--line)]">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-start justify-between gap-3 px-3.5 py-3 text-left"
      >
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2 text-[10px] font-semibold uppercase tracking-[0.06em]">
            <span
              className={
                finding.severity === "critical" || finding.severity === "high"
                  ? "text-red-ink"
                  : finding.severity === "medium"
                    ? "text-amber-ink"
                    : "text-ink-3"
              }
            >
              {t(severityLabel[finding.severity] ?? finding.severity)}
            </span>
            <span className="normal-case tracking-normal text-ink-3">
              {t(finding.engine)}
            </span>
          </div>
          <p className="mt-1 text-[14px] font-semibold tracking-[-0.01em]">
            {t(finding.title)}
          </p>
        </div>
        <span className="mt-1 shrink-0 text-[11px] text-ink-3">
          {open ? "−" : "+"}
        </span>
      </button>
      {open && (
        <div className="space-y-3 border-t border-[var(--line)] px-3.5 py-3">
          <p className="text-[13px] leading-relaxed text-ink-2">
            {t(finding.detail)}
          </p>
          {finding.action && (
            <p className="text-[13px] leading-relaxed text-ink">
              <span className="font-semibold text-blue">{t("What to do:")} </span>
              {t(finding.action)}
            </p>
          )}
          <div className="rounded-xl bg-bg px-3 py-2.5">
            <div className="flex items-center justify-between gap-2">
              <p className="text-[11px] font-semibold uppercase tracking-[0.08em] text-ink-3">
                {t("Prompt for an AI agent")}
              </p>
              <button
                type="button"
                onClick={copyPrompt}
                className="btn-get !h-7 !min-w-0 !px-3 !text-[11px]"
              >
                {copied ? t("Copied") : t("Copy")}
              </button>
            </div>
            <pre className="mt-2 max-h-40 overflow-auto whitespace-pre-wrap font-mono text-[11px] leading-relaxed text-ink-2">
              {prompt}
            </pre>
          </div>
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
  const t = useT();
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
        setErr(json.error ?? t("Recheck failed"));
        setBusy(false);
        return;
      }
      router.refresh();
    } catch {
      setErr(t("Network unavailable"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <span className="inline-flex flex-col items-end">
      <button
        type="button"
        onClick={run}
        disabled={busy}
        className="btn-get !h-8 !min-w-0 !px-3 !text-[12px]"
      >
        {busy
          ? "…"
          : label ??
            (engine === "virustotal" ? t("Recheck VT") : t("Rescan"))}
      </button>
      {err && <span className="mt-0.5 text-[10px] text-red-ink">{t(err)}</span>}
    </span>
  );
}
