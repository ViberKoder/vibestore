import type {
  EngineResult,
  ReleaseReadiness,
  ScanEngineProgress,
  ScanProgress,
  ScanReport,
  ScannerId,
  ThreatFinding,
} from "../types";
import { SCAN_ENGINE_ORDER } from "../types";
import { runClamAv, runClamWin } from "./clamav";
import { runVirusTotal } from "./virustotal";
import {
  runEntropyScanner,
  runNetworkSink,
  runPeInspector,
  runVibeGuard,
  runWebStatic,
} from "./custom";

function readinessFrom(
  score: number,
  findings: ThreatFinding[],
): Pick<
  ScanReport,
  "readiness" | "readinessLabel" | "readinessHint" | "consensus"
> {
  const critical = findings.filter((f) => f.severity === "critical").length;
  const high = findings.filter((f) => f.severity === "high").length;

  let readiness: ReleaseReadiness;
  if (critical > 0 || score < 45) readiness = "blocked";
  else if (high > 0 || score < 75) readiness = "needs_fixes";
  else readiness = "ready";

  const map = {
    ready: {
      readinessLabel: "Готово к массовому релизу",
      readinessHint:
        "Движки согласны: сборка выглядит безопасно. Следите за обновлениями.",
      consensus: "Чистый консенсус антивирусов и собственных движков.",
    },
    needs_fixes: {
      readinessLabel: "Нужны правки перед релизом",
      readinessHint:
        "Исправьте high/medium-находки и просканируйте снова перед публикацией.",
      consensus: "Смешанные сигналы — пока как пре-релиз, не в прод.",
    },
    blocked: {
      readinessLabel: "Заблокировано — не распространять",
      readinessHint:
        "Критичные признаки malware/stealer/trojan. Скачивание закрыто.",
      consensus:
        "Сильный malicious-консенсус — раздача пользователям запрещена.",
    },
  } as const;

  return { readiness, ...map[readiness] };
}

function aggregateScore(engines: EngineResult[]): number {
  const active = engines.filter((e) => e.verdict !== "skipped");
  if (!active.length) return 100;
  const weights: Record<string, number> = {
    virustotal: 1.4,
    clamav: 1.2,
    clamwin: 1.0,
    vibeguard: 1.5,
    entropy: 0.7,
    "pe-inspector": 1.0,
    "network-sink": 1.1,
    "web-static": 1.0,
  };
  let sum = 0;
  let w = 0;
  for (const e of active) {
    const weight = weights[e.scanner] ?? 1;
    sum += e.score * weight;
    w += weight;
  }
  return Math.round(sum / w);
}

export function initialScanProgress(): ScanProgress {
  return {
    phase: "queued",
    label: "Ожидание запуска сканирования…",
    percent: 0,
    engines: SCAN_ENGINE_ORDER.map((e) => ({
      scanner: e.scanner,
      displayName: e.displayName,
      phase: "pending",
    })),
    updatedAt: new Date().toISOString(),
  };
}

function buildProgress(
  engines: ScanEngineProgress[],
  current?: ScannerId,
  label?: string,
): ScanProgress {
  const done = engines.filter((e) => e.phase === "done").length;
  const total = engines.length;
  const running = engines.find((e) => e.phase === "running");
  const percent = Math.round((done / total) * 100);
  return {
    phase: done === total ? "done" : "running",
    label:
      label ??
      (running
        ? `Сканирует: ${running.displayName}…`
        : done === total
          ? "Сканирование завершено"
          : "Сканирование…"),
    percent: done === total ? 100 : Math.max(percent, running ? 5 : 0),
    currentEngine: current ?? running?.scanner,
    engines,
    updatedAt: new Date().toISOString(),
  };
}

export async function runScanPipeline(opts: {
  filePath: string;
  buffer: Buffer;
  fileName: string;
  onProgress?: (progress: ScanProgress) => void | Promise<void>;
}): Promise<ScanReport> {
  const startedAt = new Date().toISOString();
  const track: ScanEngineProgress[] = SCAN_ENGINE_ORDER.map((e) => ({
    scanner: e.scanner,
    displayName: e.displayName,
    phase: "pending",
  }));

  const notify = async (current?: ScannerId, label?: string) => {
    if (!opts.onProgress) return;
    await opts.onProgress(buildProgress(track, current, label));
  };

  await notify(undefined, "Запуск конвейера антивирусов…");

  const runners: Array<() => Promise<EngineResult>> = [
    () => runClamAv(opts.filePath, opts.buffer, opts.fileName),
    () => runClamWin(opts.filePath, opts.buffer, opts.fileName),
    () => runVirusTotal(opts.buffer, opts.fileName),
    () => runVibeGuard(opts.buffer, opts.fileName),
    () => runEntropyScanner(opts.buffer),
    () => runPeInspector(opts.buffer, opts.fileName),
    () => runNetworkSink(opts.buffer),
    () => runWebStatic(opts.buffer, opts.fileName),
  ];

  const results: EngineResult[] = [];

  for (let i = 0; i < runners.length; i++) {
    const meta = SCAN_ENGINE_ORDER[i];
    track[i] = {
      ...track[i],
      phase: "running",
      startedAt: new Date().toISOString(),
    };
    await notify(meta.scanner, `Сканирует: ${meta.displayName}…`);

    const result = await runners[i]();
    results.push(result);

    track[i] = {
      ...track[i],
      phase: "done",
      verdict: result.verdict,
      summary: result.summary,
      finishedAt: new Date().toISOString(),
    };
    await notify(
      undefined,
      `${meta.displayName}: ${result.verdict.toUpperCase()}`,
    );
  }

  const findings = results.flatMap((e) => e.findings);
  const avHardFail = results.filter(
    (e) =>
      ["clamav", "clamwin", "virustotal"].includes(e.scanner) &&
      e.verdict === "error" &&
      e.meta?.mode !== "pending-analysis",
  );
  const vtPending = results.some(
    (e) =>
      e.scanner === "virustotal" && e.meta?.mode === "pending-analysis",
  );
  for (const e of avHardFail) {
    findings.push(
      ...e.findings.filter((f) => !findings.some((x) => x.id === f.id)),
    );
  }

  let securityScore = aggregateScore(results);
  if (avHardFail.length) securityScore = Math.min(securityScore, 55);
  else if (vtPending) securityScore = Math.min(securityScore, 68);

  const ready = readinessFrom(securityScore, findings);
  const finishedAt = new Date().toISOString();

  await opts.onProgress?.({
    ...buildProgress(track),
    phase: "done",
    label: ready.readinessLabel,
    percent: 100,
  });

  return {
    id: `scan_${Date.now().toString(36)}`,
    startedAt,
    finishedAt,
    engines: results,
    securityScore,
    ...ready,
    threatCount: findings.length,
    criticalCount: findings.filter((f) => f.severity === "critical").length,
    highCount: findings.filter((f) => f.severity === "high").length,
  };
}

export function statusFromReport(
  report: ScanReport,
): "published" | "quarantined" | "rejected" {
  if (report.readiness === "blocked") return "rejected";
  if (report.readiness === "needs_fixes") return "quarantined";
  return "published";
}
