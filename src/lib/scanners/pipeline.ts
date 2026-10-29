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
import {
  runDeviceFootprint,
  runElectronHardening,
  runIntegrityAuditor,
  runPrivacyAuditor,
  runSecretsAuditor,
} from "./audit";
import { runClamAv, runClamWin } from "./clamav";
import {
  runEntropyScanner,
  runNetworkSink,
  runPeInspector,
  runVibeGuard,
  runWebStatic,
} from "./custom";
import { enrichFindingsWithPrompts } from "./agent-prompt";
import { computeAuditPillars, trustFromPillars } from "./pillars";
import { runVirusTotal } from "./virustotal";

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
        "Независимый аудит не нашёл блокирующих рисков. Следите за обновлениями runtime и зависимостей.",
      consensus:
        "AV-консенсус + hardening/privacy/device — без критичных красных флагов.",
    },
    needs_fixes: {
      readinessLabel: "Нужны правки перед релизом",
      readinessHint:
        "Исправьте high/medium-находки аудита и пересканируйте перед массовой раздачей.",
      consensus: "Есть замечания аудитора — пока как пре-релиз, не в прод.",
    },
    blocked: {
      readinessLabel: "Заблокировано — не распространять",
      readinessHint:
        "Критичные malware/секреты/дыры. Скачивание для пользователей закрыто.",
      consensus: "Критичный риск для пользователей — релиз заблокирован.",
    },
  } as const;

  return { readiness, ...map[readiness] };
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
  appName?: string;
  appKind?: string;
  appVersion?: string;
  appTagline?: string;
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

  await notify(undefined, "Запуск Vibe Audit + антивирусов…");

  // Order MUST match SCAN_ENGINE_ORDER
  const runners: Array<() => Promise<EngineResult>> = [
    () => runClamAv(opts.filePath, opts.buffer, opts.fileName),
    () => runClamWin(opts.filePath, opts.buffer, opts.fileName),
    () => runVirusTotal(opts.buffer, opts.fileName),
    () => runVibeGuard(opts.buffer, opts.fileName),
    () => runEntropyScanner(opts.buffer),
    () => runPeInspector(opts.buffer, opts.fileName),
    () => runNetworkSink(opts.buffer),
    () => runWebStatic(opts.buffer, opts.fileName),
    () => runSecretsAuditor(opts.buffer, opts.fileName),
    () => runElectronHardening(opts.buffer, opts.fileName),
    () => runPrivacyAuditor(opts.buffer),
    () => runIntegrityAuditor(opts.buffer, opts.fileName),
    () => runDeviceFootprint(opts.buffer, opts.fileName),
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

  return finalizeReport(
    results,
    startedAt,
    {
      name: opts.appName ?? opts.fileName,
      kind: (opts.appKind as "desktop") ?? "other",
      fileName: opts.fileName,
      version: opts.appVersion ?? "0.0.0",
      tagline: opts.appTagline ?? "",
    },
    async (label) => {
      await opts.onProgress?.({
        ...buildProgress(track),
        phase: "done",
        label,
        percent: 100,
      });
    },
  );
}

export async function finalizeReport(
  results: EngineResult[],
  startedAt: string,
  appCtx?: {
    name: string;
    kind: string;
    fileName: string;
    version: string;
    tagline: string;
  },
  onDone?: (label: string) => void | Promise<void>,
): Promise<ScanReport> {
  const ctx = appCtx ?? {
    name: "app",
    kind: "other",
    fileName: "artifact",
    version: "0.0.0",
    tagline: "",
  };

  // Attach AI-agent fix prompts onto each finding (and mirror into engine lists)
  const resultsWithPrompts: EngineResult[] = results.map((engine) => ({
    ...engine,
    findings: enrichFindingsWithPrompts(engine.findings, {
      name: ctx.name,
      kind: ctx.kind as "desktop",
      fileName: ctx.fileName,
      version: ctx.version,
      tagline: ctx.tagline,
    }),
  }));

  let findings = resultsWithPrompts.flatMap((e) => e.findings);
  const avHardFail = resultsWithPrompts.filter(
    (e) =>
      ["clamav", "clamwin", "virustotal"].includes(e.scanner) &&
      e.verdict === "error" &&
      e.meta?.mode !== "pending-analysis",
  );
  const vtPending = resultsWithPrompts.some(
    (e) => e.scanner === "virustotal" && e.meta?.mode === "pending-analysis",
  );
  for (const e of avHardFail) {
    findings.push(
      ...e.findings.filter((f) => !findings.some((x) => x.id === f.id)),
    );
  }
  findings = enrichFindingsWithPrompts(findings, {
    name: ctx.name,
    kind: ctx.kind as "desktop",
    fileName: ctx.fileName,
    version: ctx.version,
    tagline: ctx.tagline,
  });

  const pillars = computeAuditPillars(resultsWithPrompts);
  let trustScore = trustFromPillars(pillars, findings);
  if (avHardFail.length) trustScore = Math.min(trustScore, 55);
  else if (vtPending) trustScore = Math.min(trustScore, 68);

  const ready = readinessFrom(trustScore, findings);
  if (vtPending && ready.readiness === "needs_fixes") {
    ready.readinessLabel = "Ждём VirusTotal — повторите проверку";
    ready.readinessHint =
      "VirusTotal ещё анализирует файл. Остальной аудит уже посчитан — нажмите «Перепроверить VirusTotal».";
    ready.consensus =
      "Локальные AV/аудит готовы; отчёт VirusTotal ещё догоняет.";
  }

  const finishedAt = new Date().toISOString();
  await onDone?.(ready.readinessLabel);

  return {
    id: `scan_${Date.now().toString(36)}`,
    startedAt,
    finishedAt,
    engines: resultsWithPrompts,
    securityScore: trustScore,
    trustScore,
    pillars,
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
