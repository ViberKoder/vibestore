import type {
  EngineResult,
  ScanCoverage,
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
import { runClamSuite } from "./clamav";
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
import { runArchiveEngine, runBlocklistEngine } from "./security-engines";
import { runStaticAuditor } from "./static-audit";
import { runDependencyEngine } from "./dependencies";
import { sha256Buffer } from "../hash";

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
      readinessLabel: "Ready for mass release",
      readinessHint:
        "The independent audit found no blocking risks. Keep the runtime and dependencies up to date.",
      consensus:
        "AV consensus + hardening/privacy/device — no critical red flags.",
    },
    needs_fixes: {
      readinessLabel: "Fixes needed before release",
      readinessHint:
        "Fix the high/medium audit findings and rescan before a mass release.",
      consensus: "The auditor has findings — pre-release only, not for production.",
    },
    blocked: {
      readinessLabel: "Blocked — do not distribute",
      readinessHint:
        "Critical malware/secrets/holes. Downloads for users are closed.",
      consensus: "Critical risk for users — release blocked.",
    },
  } as const;

  return { readiness, ...map[readiness] };
}

export function initialScanProgress(): ScanProgress {
  return {
    phase: "queued",
    label: "Waiting to start the scan…",
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
        ? `Running: ${running.displayName}…`
        : done === total
          ? "Scan complete"
          : "Scanning…"),
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
  const indexOf = new Map(SCAN_ENGINE_ORDER.map((e, i) => [e.scanner, i]));

  const notify = async (current?: ScannerId, label?: string) => {
    if (!opts.onProgress) return;
    await opts.onProgress(buildProgress(track, current, label));
  };

  await notify(undefined, "Starting Vibe Audit + antivirus engines…");

  // Independent engines run concurrently. I/O-bound work (clamd, VirusTotal
  // polling) overlaps with the CPU-bound heuristics instead of queueing behind
  // them. Each task reports one or more engine results.
  const tasks: Array<{
    scanners: ScannerId[];
    run: () => Promise<EngineResult[]>;
  }> = [
    {
      scanners: ["clamav", "clamwin"],
      run: () => runClamSuite(opts.filePath, opts.fileName),
    },
    { scanners: ["virustotal"], run: async () => [await runVirusTotal(opts.buffer, opts.fileName)] },
    { scanners: ["vibeguard"], run: async () => [await runVibeGuard(opts.buffer, opts.fileName)] },
    { scanners: ["entropy"], run: async () => [await runEntropyScanner(opts.buffer)] },
    { scanners: ["pe-inspector"], run: async () => [await runPeInspector(opts.buffer, opts.fileName)] },
    { scanners: ["network-sink"], run: async () => [await runNetworkSink(opts.buffer)] },
    { scanners: ["web-static"], run: async () => [await runWebStatic(opts.buffer, opts.fileName)] },
    { scanners: ["secrets"], run: async () => [await runSecretsAuditor(opts.buffer, opts.fileName)] },
    { scanners: ["electron-hardening"], run: async () => [await runElectronHardening(opts.buffer, opts.fileName)] },
    { scanners: ["privacy"], run: async () => [await runPrivacyAuditor(opts.buffer)] },
    { scanners: ["integrity"], run: async () => [await runIntegrityAuditor(opts.buffer, opts.fileName)] },
    { scanners: ["device-footprint"], run: async () => [await runDeviceFootprint(opts.buffer, opts.fileName)] },
    { scanners: ["archive"], run: async () => [await runArchiveEngine(opts.buffer, opts.fileName)] },
    { scanners: ["blocklist"], run: async () => [await runBlocklistEngine(sha256Buffer(opts.buffer))] },
    { scanners: ["static-audit"], run: async () => [await runStaticAuditor(opts.buffer, opts.fileName)] },
    { scanners: ["dependencies"], run: async () => [await runDependencyEngine(opts.buffer, opts.fileName)] },
  ];

  const byScanner = new Map<ScannerId, EngineResult>();
  for (const id of tasks.flatMap((t) => t.scanners)) {
    const i = indexOf.get(id);
    if (i !== undefined) {
      track[i] = { ...track[i], phase: "running", startedAt: new Date().toISOString() };
    }
  }
  await notify(undefined, "Scanning: engines started in parallel…");

  await Promise.all(
    tasks.map(async (task) => {
      const outputs = await task.run();
      for (const result of outputs) {
        byScanner.set(result.scanner, result);
        const i = indexOf.get(result.scanner);
        if (i === undefined) continue;
        track[i] = {
          ...track[i],
          phase: "done",
          verdict: result.verdict,
          summary: result.summary,
          finishedAt: new Date().toISOString(),
        };
      }
      const last = outputs[outputs.length - 1];
      await notify(
        undefined,
        `${last.displayName}: ${last.verdict.toUpperCase()}`,
      );
    }),
  );

  // Keep results in canonical engine order (report UI and pillars rely on it).
  const results: EngineResult[] = SCAN_ENGINE_ORDER.map((e) => {
    const r = byScanner.get(e.scanner);
    if (!r) throw new Error(`Engine ${e.scanner} produced no result`);
    return r;
  });

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
    ready.readinessLabel = "Waiting for VirusTotal — run the check again";
    ready.readinessHint =
      "VirusTotal is still analyzing the file. The rest of the audit is already done — press «Recheck VirusTotal».";
    ready.consensus =
      "Local AV/audit is ready; the VirusTotal report is still catching up.";
  }

  const finishedAt = new Date().toISOString();
  await onDone?.(ready.readinessLabel);

  const coverage = buildCoverage(resultsWithPrompts, ctx.kind);

  return {
    id: `scan_${Date.now().toString(36)}`,
    startedAt,
    finishedAt,
    engines: resultsWithPrompts,
    securityScore: trustScore,
    trustScore,
    pillars,
    ...ready,
    coverage,
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

/** Honest scope of a report: what ran, what was skipped or unavailable, and what is never verified. */
export function buildCoverage(engines: EngineResult[], kind: string): ScanCoverage {
  const count = (v: EngineResult["verdict"]) => engines.filter((e) => e.verdict === v).length;
  const unavailable = engines.filter((e) => e.verdict === "error").length;
  const dependenciesChecked = engines.some(
    (e) => e.scanner === "dependencies" && (e.verdict === "clean" || e.verdict === "suspicious" || e.verdict === "malicious"),
  );
  const notVerified = [
    "Runtime behaviour: nothing is executed, so keyloggers, injection and persistence are not observed",
    "Device impact under load: CPU/RAM are not measured",
    "Obfuscated or minified code: intent is not decided, only patterns are matched",
  ];
  if (!dependenciesChecked) {
    notVerified.unshift("Dependency vulnerabilities (CVE/OSV): no advisory lookup was completed for this build");
  }
  if (kind === "desktop") notVerified.push("Installer contents (NSIS/MSI) are not unpacked, only the outer file is checked");
  return {
    total: engines.length,
    passed: count("clean"),
    flagged: count("suspicious") + count("malicious"),
    skipped: count("skipped"),
    unavailable,
    notVerified,
  };
}
