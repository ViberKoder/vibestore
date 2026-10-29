import { promises as fs } from "fs";
import { NextResponse } from "next/server";
import {
  initialScanProgress,
  runScanPipeline,
  statusFromReport,
} from "@/lib/scanners/pipeline";
import { runVirusTotal } from "@/lib/scanners/virustotal";
import {
  getAppById,
  getAppBySlug,
  patchApp,
  updateScanProgress,
} from "@/lib/store";
import type { EngineResult, StoreApp } from "@/lib/types";

export const runtime = "nodejs";
export const maxDuration = 600;

function recomputeFromEngines(app: StoreApp, engines: EngineResult[]) {
  const findings = engines.flatMap((e) => e.findings);
  const avHardFail = engines.filter(
    (e) =>
      ["clamav", "clamwin", "virustotal"].includes(e.scanner) &&
      e.verdict === "error" &&
      e.meta?.mode !== "pending-analysis",
  );
  const vtPending = engines.some(
    (e) => e.scanner === "virustotal" && e.meta?.mode === "pending-analysis",
  );

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
  const active = engines.filter((e) => e.verdict !== "skipped");
  let sum = 0;
  let w = 0;
  for (const e of active) {
    const weight = weights[e.scanner] ?? 1;
    sum += e.score * weight;
    w += weight;
  }
  let securityScore = w ? Math.round(sum / w) : 100;
  if (avHardFail.length) securityScore = Math.min(securityScore, 55);
  else if (vtPending) securityScore = Math.min(securityScore, 68);

  const critical = findings.filter((f) => f.severity === "critical").length;
  const high = findings.filter((f) => f.severity === "high").length;
  let readiness: "ready" | "needs_fixes" | "blocked" = "ready";
  if (critical > 0 || securityScore < 45) readiness = "blocked";
  else if (high > 0 || securityScore < 75 || vtPending) readiness = "needs_fixes";

  const labels = {
    ready: {
      readinessLabel: "Готово к массовому релизу",
      readinessHint:
        "Движки согласны: сборка выглядит безопасно. Следите за обновлениями.",
      consensus: "Чистый консенсус антивирусов и собственных движков.",
    },
    needs_fixes: {
      readinessLabel: vtPending
        ? "Ждём VirusTotal — повторите проверку"
        : "Нужны правки перед релизом",
      readinessHint: vtPending
        ? "VirusTotal ещё анализирует файл. Это не malware-детект — нажмите «Перепроверить VirusTotal»."
        : "Исправьте high/medium-находки и просканируйте снова перед публикацией.",
      consensus: vtPending
        ? "Локальные AV чистые; отчёт VirusTotal ещё не готов."
        : "Смешанные сигналы — пока как пре-релиз, не в прод.",
    },
    blocked: {
      readinessLabel: "Заблокировано — не распространять",
      readinessHint:
        "Критичные признаки malware/stealer/trojan. Скачивание закрыто.",
      consensus:
        "Сильный malicious-консенсус — раздача пользователям запрещена.",
    },
  } as const;

  const now = new Date().toISOString();
  return {
    scan: {
      id: app.scan?.id ?? `scan_${Date.now().toString(36)}`,
      startedAt: app.scan?.startedAt ?? now,
      finishedAt: now,
      engines,
      securityScore,
      readiness,
      ...labels[readiness],
      threatCount: findings.length,
      criticalCount: critical,
      highCount: high,
    },
    status: statusFromReport({
      id: "tmp",
      startedAt: now,
      finishedAt: now,
      engines,
      securityScore,
      readiness,
      ...labels[readiness],
      threatCount: findings.length,
      criticalCount: critical,
      highCount: high,
    }),
  };
}

export async function POST(
  req: Request,
  ctx: { params: Promise<{ id: string }> },
) {
  const { id } = await ctx.params;
  const app = (await getAppById(id)) ?? (await getAppBySlug(id));
  if (!app) {
    return NextResponse.json({ error: "App not found" }, { status: 404 });
  }
  if (!app.filePath) {
    return NextResponse.json({ error: "No file on disk" }, { status: 400 });
  }

  const url = new URL(req.url);
  const engine = url.searchParams.get("engine") ?? "all";

  let buffer: Buffer;
  try {
    buffer = await fs.readFile(app.filePath);
  } catch {
    return NextResponse.json({ error: "File missing" }, { status: 404 });
  }

  if (engine === "virustotal" && app.scan) {
    await updateScanProgress(app.id, {
      ...initialScanProgress(),
      phase: "running",
      label: "Перепроверяем VirusTotal…",
      percent: 40,
      currentEngine: "virustotal",
      engines: (app.scanProgress?.engines ?? initialScanProgress().engines).map(
        (e) =>
          e.scanner === "virustotal"
            ? { ...e, phase: "running", summary: "Запрос к VirusTotal…" }
            : e,
      ),
    });

    const vt = await runVirusTotal(buffer, app.fileName);
    const engines = app.scan.engines.map((e) =>
      e.scanner === "virustotal" ? vt : e,
    );
    const next = recomputeFromEngines(app, engines);
    const updated = await patchApp(app.id, {
      scan: next.scan,
      status: next.status,
      scanProgress: {
        phase: "done",
        label: next.scan.readinessLabel,
        percent: 100,
        engines: next.scan.engines.map((e) => ({
          scanner: e.scanner,
          displayName: e.displayName,
          phase: "done" as const,
          verdict: e.verdict,
          summary: e.summary,
        })),
        updatedAt: new Date().toISOString(),
      },
    });
    return NextResponse.json({ app: updated, rescanned: "virustotal" });
  }

  // Full rescan
  await updateScanProgress(app.id, {
    ...initialScanProgress(),
    phase: "running",
    label: "Полный повторный скан…",
    percent: 1,
  });

  const scan = await runScanPipeline({
    filePath: app.filePath,
    buffer,
    fileName: app.fileName,
    onProgress: async (progress) => {
      await updateScanProgress(app.id, progress);
    },
  });

  const updated = await patchApp(app.id, {
    scan,
    status: statusFromReport(scan),
    scanProgress: {
      phase: "done",
      label: scan.readinessLabel,
      percent: 100,
      engines: scan.engines.map((e) => ({
        scanner: e.scanner,
        displayName: e.displayName,
        phase: "done" as const,
        verdict: e.verdict,
        summary: e.summary,
      })),
      updatedAt: new Date().toISOString(),
    },
  });

  return NextResponse.json({ app: updated, rescanned: "all" });
}
