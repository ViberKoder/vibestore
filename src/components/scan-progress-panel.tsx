"use client";

import { useEffect, useRef, useState } from "react";
import { useT } from "@/lib/i18n/client";
import type { ScanProgress, ScannerVerdict, StoreApp } from "@/lib/types";

const verdictColor: Record<ScannerVerdict, string> = {
  clean: "text-green-ink",
  suspicious: "text-amber-ink",
  malicious: "text-red-ink",
  error: "text-red-ink",
  skipped: "text-ink-3",
};

const verdictLabel: Record<ScannerVerdict, string> = {
  clean: "Clean",
  suspicious: "Suspicious",
  malicious: "Threat",
  error: "Error",
  skipped: "Skipped",
};

export function ScanProgressPanel({
  appId,
  initial,
  autoStart = true,
  onFinished,
}: {
  appId: string;
  initial?: ScanProgress;
  autoStart?: boolean;
  onFinished?: (app: StoreApp) => void;
}) {
  const [progress, setProgress] = useState<ScanProgress | undefined>(initial);
  const [error, setError] = useState<string | null>(null);
  const started = useRef(false);
  const t = useT();

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;

    async function poll() {
      try {
        const res = await fetch(`/api/apps/${appId}`, { cache: "no-store" });
        if (!res.ok) return;
        const json = (await res.json()) as { app: StoreApp };
        if (cancelled) return;
        if (json.app.scanProgress) setProgress(json.app.scanProgress);
        if (json.app.scan && json.app.scanProgress?.phase === "done") {
          onFinished?.(json.app);
          return;
        }
        if (json.app.scanProgress?.phase === "error") {
          setError(json.app.scanProgress.error ?? json.app.scanProgress.label);
          return;
        }
      } catch {
        /* keep polling */
      }
      if (!cancelled) timer = setTimeout(poll, 900);
    }

    async function start() {
      if (!autoStart || started.current) {
        poll();
        return;
      }
      started.current = true;
      setProgress((p) =>
        p ?? {
          phase: "running",
          label: "Starting the scan…",
          percent: 1,
          engines: [],
          updatedAt: new Date().toISOString(),
        },
      );

      // Poll in parallel — POST blocks until all engines finish
      poll();

      try {
        const res = await fetch(`/api/apps/${appId}/scan`, { method: "POST" });
        const json = (await res.json()) as {
          app?: StoreApp;
          error?: string;
          alreadyRunning?: boolean;
        };
        if (cancelled) return;
        if (!res.ok && !json.alreadyRunning) {
          setError(json.error ?? "Could not start the scan");
          return;
        }
        if (json.app?.scanProgress) setProgress(json.app.scanProgress);
        if (json.app?.scan) onFinished?.(json.app);
      } catch {
        if (!cancelled) setError("Network unavailable while starting the scan");
      }
    }

    start();
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [appId, autoStart, onFinished]);

  const percent = progress?.percent ?? 0;
  const done = progress?.phase === "done";
  const failed = progress?.phase === "error" || Boolean(error);

  return (
    <div className="surface-card overflow-hidden p-6 md:p-8">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <p className="text-[12px] font-semibold uppercase tracking-[0.14em] text-ink-3">
            {t("Security scan")}
          </p>
          <h2 className="mt-1 text-[22px] font-bold tracking-[-0.03em] text-ink">
            {failed
              ? t("Scan interrupted")
              : done
                ? t("Scan complete")
                : t("Checking the build")}
          </h2>
          <p className="mt-1 text-[14px] text-ink-2">
            {t(error ?? progress?.label ?? "Preparing…")}
          </p>
        </div>
        <div className="text-right">
          <div className="text-[28px] font-bold tabular-nums tracking-[-0.04em] text-ink">
            {percent}%
          </div>
          <div className="text-[11px] font-semibold uppercase tracking-[0.12em] text-ink-3">
            {t("progress")}
          </div>
        </div>
      </div>

      <div className="mt-5 h-2 overflow-hidden rounded-full bg-black/[0.06]">
        <div
          className={`h-full rounded-full transition-all duration-500 ${
            failed ? "bg-red" : done ? "bg-green" : "bg-blue"
          }`}
          style={{ width: `${Math.min(100, Math.max(2, percent))}%` }}
        />
      </div>

      <ul className="mt-6 space-y-2">
        {(progress?.engines ?? []).map((engine) => (
          <li
            key={engine.scanner}
            className={`flex items-center gap-3 rounded-2xl border px-4 py-3 ${
              engine.phase === "running"
                ? "border-blue/25 bg-blue-soft"
                : "border-black/[0.06] bg-white"
            }`}
          >
            <EngineGlyph phase={engine.phase} />
            <div className="min-w-0 flex-1">
              <div className="text-[14px] font-semibold tracking-[-0.01em]">
                {t(engine.displayName)}
              </div>
              {engine.summary && (
                <div className="mt-0.5 truncate text-[12px] text-ink-2">
                  {t(engine.summary)}
                </div>
              )}
            </div>
            <div className="shrink-0 text-right text-[12px] font-semibold">
              {engine.phase === "pending" && (
                <span className="text-ink-3">{t("Waiting")}</span>
              )}
              {engine.phase === "running" && (
                <span className="text-blue">{t("Scanning…")}</span>
              )}
              {engine.phase === "done" && engine.verdict && (
                <span className={verdictColor[engine.verdict]}>
                  {t(verdictLabel[engine.verdict])}
                </span>
              )}
            </div>
          </li>
        ))}
      </ul>

      {!done && !failed && (
        <p className="mt-5 text-[12px] text-ink-3">
          {t("VirusTotal · ClamAV · ClamWin · VibeGuard and other engines run one after another. Keep this tab open — progress updates in real time.")}
        </p>
      )}
    </div>
  );
}

function EngineGlyph({ phase }: { phase: "pending" | "running" | "done" }) {
  if (phase === "running") {
    return (
      <span
        className="grid h-8 w-8 shrink-0 place-items-center rounded-full bg-blue text-white"
        aria-hidden
      >
        <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-white/30 border-t-white" />
      </span>
    );
  }
  if (phase === "done") {
    return (
      <span
        className="grid h-8 w-8 shrink-0 place-items-center rounded-full bg-green-soft text-[14px] font-bold text-green-ink"
        aria-hidden
      >
        ✓
      </span>
    );
  }
  return (
    <span
      className="grid h-8 w-8 shrink-0 place-items-center rounded-full bg-black/[0.04] text-[12px] font-semibold text-ink-3"
      aria-hidden
    >
      ·
    </span>
  );
}
