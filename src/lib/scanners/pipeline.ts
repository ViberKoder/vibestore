import type { EngineResult, ReleaseReadiness, ScanReport, ThreatFinding } from "../types";
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
      consensus: "Сильный malicious-консенсус — раздача пользователям запрещена.",
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

export async function runScanPipeline(opts: {
  filePath: string;
  buffer: Buffer;
  fileName: string;
}): Promise<ScanReport> {
  const startedAt = new Date().toISOString();

  const engines = await Promise.all([
    runClamAv(opts.filePath, opts.buffer, opts.fileName),
    runClamWin(opts.filePath, opts.buffer, opts.fileName),
    runVirusTotal(opts.buffer, opts.fileName),
    runVibeGuard(opts.buffer, opts.fileName),
    runEntropyScanner(opts.buffer),
    runPeInspector(opts.buffer, opts.fileName),
    runNetworkSink(opts.buffer),
    runWebStatic(opts.buffer, opts.fileName),
  ]);

  const findings = engines.flatMap((e) => e.findings);
  // Antivirus engines must not be skipped/bypassed: unavailable AV lowers readiness
  const avDown = engines.filter(
    (e) =>
      ["clamav", "clamwin", "virustotal"].includes(e.scanner) &&
      e.verdict === "error",
  );
  for (const e of avDown) {
    findings.push(
      ...e.findings.filter((f) => !findings.some((x) => x.id === f.id)),
    );
  }

  let securityScore = aggregateScore(engines);
  if (avDown.length) {
    securityScore = Math.min(securityScore, 55);
  }
  const ready = readinessFrom(securityScore, findings);
  const finishedAt = new Date().toISOString();

  return {
    id: `scan_${Date.now().toString(36)}`,
    startedAt,
    finishedAt,
    engines,
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
